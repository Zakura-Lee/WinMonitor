#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ETW 可行性验证（P2 spike）

目的: 用纯 ctypes 打通「创建会话 -> 启用内核提供者 -> 实时消费 -> 统计」的链路，
      输出事件速率、丢失事件数与解码失败数，作为 G1 决策门的依据。

用法（需管理员权限）:
    python src/collect/etw/spike.py
    python src/collect/etw/spike.py --seconds 10 --max-events 500
    python src/collect/etw/spike.py --provider Microsoft-Windows-Kernel-File

说明:
    内核提供者要求以管理员身份建立 ETW 会话，普通权限会返回 ERROR_ACCESS_DENIED。
    本脚本在启动前会先检查权限并给出明确提示，不会静默失败。
"""

import argparse
import collections
import ctypes
import datetime
import os
import re
import subprocess
import sys
import threading
import time

from ctypes import wintypes

if __package__ in (None, ""):  # 允许直接以脚本方式运行
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
    from collect.etw import api, etwtypes as types
else:
    from . import api, etwtypes as types

DEFAULT_PROVIDER = "Microsoft-Windows-Kernel-Process"
FALLBACK_GUIDS = {
    "Microsoft-Windows-Kernel-Process": "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716",
    "Microsoft-Windows-Kernel-File": "EDD08927-9CC4-4E65-B970-C2560FB5C289",
    "Microsoft-Windows-Kernel-Network": "7DD42A49-5329-4832-8DFD-43D979153A88",
    "Microsoft-Windows-Kernel-Registry": "70EB4F03-C1DE-4F73-A051-33D13D5413BD",
}

FILETIME_EPOCH_DELTA = 116444736000000000  # 1601-01-01 到 1970-01-01 的 100ns 数


# ---------------------------------------------------------------------------
# 解码
# ---------------------------------------------------------------------------

def filetime_to_text(timestamp):
    """把 100ns 单位的 FILETIME 转成本地时间字符串。"""
    try:
        unix_ns = (timestamp - FILETIME_EPOCH_DELTA) * 100
        return datetime.datetime.fromtimestamp(unix_ns / 1e9).strftime("%H:%M:%S.%f")[:-3]
    except (ValueError, OSError, OverflowError):
        return "-"


def extract_wide_strings(data, min_chars=4, limit=8):
    """从事件载荷里扫描 UTF-16LE 字符串。

    spike 阶段用它代替完整的 TDH 属性解码：进程路径、命令行这类字段
    在载荷里是 NUL 结尾的宽字符串，扫描足以证明链路是通的。
    """
    found = []
    length = len(data) - (len(data) % 2)
    index = 0
    while index < length and len(found) < limit:
        chars = []
        cursor = index
        while cursor + 1 < length:
            code = data[cursor] | (data[cursor + 1] << 8)
            if code == 0:
                break
            printable = 0x20 <= code <= 0x7E or 0x4E00 <= code <= 0x9FFF
            if not printable:
                chars = []
                break
            chars.append(chr(code))
            cursor += 2
        if len(chars) >= min_chars:
            found.append("".join(chars))
            index = cursor + 2
        else:
            index += 2
    return found


def decode_event_info(record):
    """用 TDH 取提供者名、事件名与属性数量。

    只读 TRACE_EVENT_INFO 的定长头部字段，不解析属性数组，
    以免受不同 SDK 版本数组起始偏移差异的影响。
    """
    info = {}
    size = wintypes.ULONG(0)
    rc = api.TdhGetEventInformation(ctypes.byref(record), 0, None, None, ctypes.byref(size))
    if rc != types.ERROR_INSUFFICIENT_BUFFER or not 0 < size.value < (1 << 20):
        return info

    buffer = ctypes.create_string_buffer(size.value)
    rc = api.TdhGetEventInformation(ctypes.byref(record), 0, None, buffer, ctypes.byref(size))
    if rc != types.ERROR_SUCCESS:
        return info

    raw = buffer.raw[: size.value]

    def read_ulong(offset):
        if offset + 4 > len(raw):
            return 0
        return int.from_bytes(raw[offset: offset + 4], "little")

    def read_wide(relative):
        if not 0 < relative < len(raw):
            return ""
        end = relative
        while end + 1 < len(raw) and (raw[end] or raw[end + 1]):
            end += 2
        return raw[relative:end].decode("utf-16-le", "ignore")

    provider_name = read_wide(read_ulong(52))
    event_name = read_wide(read_ulong(92))
    property_count = read_ulong(100)

    if provider_name:
        info["provider_name"] = provider_name
    if event_name:
        info["event_name"] = event_name
    if 0 <= property_count <= 128:
        info["property_count"] = property_count
    return info


def describe(record, want_raw):
    """把一条 EVENT_RECORD 描述成可打印的字典。"""
    header = record.EventHeader
    payload = b""
    if record.UserData and record.UserDataLength:
        payload = ctypes.string_at(record.UserData, record.UserDataLength)

    item = {
        "time": filetime_to_text(header.TimeStamp),
        "event_id": header.EventDescriptor.Id,
        "pid": header.ProcessId,
        "tid": header.ThreadId,
        "keyword": hex(header.EventDescriptor.Keyword),
        "payload_bytes": len(payload),
        "strings": extract_wide_strings(payload),
    }
    try:
        info = decode_event_info(record)
        if info:
            item.update(info)
    except Exception:  # noqa: BLE001 - 解码失败不应中断采集
        item["tdh_error"] = True

    if want_raw:
        item["raw"] = payload[:120].hex(" ")
    return item


# ---------------------------------------------------------------------------
# 运行状态
# ---------------------------------------------------------------------------

class SpikeState:
    def __init__(self, max_events=0, sample_limit=10, want_raw=False):
        self.count = 0
        self.sample_limit = sample_limit
        self.want_raw = want_raw
        self.max_events = max_events
        self.samples = []
        self.event_ids = collections.Counter()
        self.decode_errors = 0
        self.pid_count = 0


_STATE = SpikeState()


def _on_event(record_pointer):
    """ETW 事件回调。异常必须吞掉，否则会污染 TraceRuntime。"""
    state = _STATE
    try:
        record = record_pointer.contents
        state.count += 1
        state.event_ids[record.EventHeader.EventDescriptor.Id] += 1
        if len(state.samples) < state.sample_limit:
            state.samples.append(describe(record, state.want_raw))
    except Exception:  # noqa: BLE001
        state.decode_errors += 1
    return None


CALLBACK = types.EVENT_RECORD_CALLBACK(_on_event)

_BUFFER_COUNTER = {"count": 0}


def _on_buffer(logfile_pointer):
    """缓冲区回调：每交付一个缓冲调用一次。返回非 0 表示继续。"""
    try:
        _BUFFER_COUNTER["count"] += 1
    except Exception:  # noqa: BLE001
        pass
    return 1


BUFFER_CALLBACK = types.EVENT_TRACE_BUFFER_CALLBACKW(_on_buffer)


# 传统 EVENT_TRACE 回调（非 EVENT_RECORD 模式的兜底路径）
_LEGACY_STATE = {"count": 0, "samples": []}


def _on_legacy(trace_pointer):
    try:
        trace = trace_pointer.contents
        _LEGACY_STATE["count"] += 1
        if len(_LEGACY_STATE["samples"]) < 5:
            header = trace.Header
            payload = b""
            if trace.MofData and trace.MofLength:
                payload = ctypes.string_at(trace.MofData, trace.MofLength)
            _LEGACY_STATE["samples"].append(
                {
                    "time": filetime_to_text(header.TimeStamp),
                    "pid": header.ProcessId,
                    "type": header.Version & 0xFF,
                    "bytes": len(payload),
                    "strings": extract_wide_strings(payload),
                }
            )
    except Exception:  # noqa: BLE001
        pass


LEGACY_CALLBACK = ctypes.WINFUNCTYPE(None, ctypes.POINTER(types.EVENT_TRACE))(_on_legacy)


# ---------------------------------------------------------------------------
# 提供者解析
# ---------------------------------------------------------------------------

def resolve_provider(provider_name):
    """通过 logman 查提供者 GUID，失败时退回内置常量。"""
    guid = ""
    keywords = []
    try:
        completed = subprocess.run(
            ["logman", "query", "providers", provider_name],
            capture_output=True,
            text=True,
            errors="ignore",
            timeout=20,
            shell=False,
        )
        output = completed.stdout or ""
        match = re.search(r"\{([0-9a-fA-F-]{36})\}", output)
        if match:
            guid = match.group(1)
        keywords = re.findall(r"0x([0-9a-fA-F]{4,16})\s+(\S+)", output)
    except (OSError, subprocess.SubprocessError):
        pass

    source = "logman"
    if not guid:
        guid = FALLBACK_GUIDS.get(provider_name, "")
        source = "内置常量"
    return guid, source, keywords


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def _spawn_workload(count):
    """在独立线程里拉起若干短命进程，保证统计窗口内确实有进程事件。"""
    if count <= 0:
        return

    def _worker():
        for _ in range(count):
            try:
                subprocess.Popen(
                    ["cmd", "/c", "exit"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except OSError:
                return

    threading.Thread(target=_worker, daemon=True).start()


def run(provider_name, seconds, max_events, keywords, want_raw, session_name, level=5, etl_path=None, workload=20, legacy=False, bogus=False):
    state = SpikeState(max_events=max_events, want_raw=want_raw)
    global _STATE
    _STATE = state
    _BUFFER_COUNTER["count"] = 0

    if not api.IsUserAnAdmin():
        print("[FAIL] 当前进程不是管理员权限。")
        print("       内核 ETW 提供者要求以管理员身份建立会话，否则返回 ERROR_ACCESS_DENIED。")
        print("       请用管理员身份的 PowerShell 重新运行本脚本，例如：")
        print(f"       Start-Process -Verb RunAs -File \"{sys.executable}\" -ArgumentList \"{os.path.abspath(__file__)}\"")
        return 2

    guid, guid_source, provider_keywords = resolve_provider(provider_name)
    if not guid:
        print(f"[FAIL] 无法解析提供者 GUID: {provider_name}")
        return 3

    print(f"[INFO] 提供者      : {provider_name}")
    print(f"[INFO] GUID        : {{{guid}}}  (来源: {guid_source})")
    print(f"[INFO] 关键字      : 0x{keywords:X}")
    if provider_keywords:
        preview = ", ".join(f"0x{value}:{name}" for value, name in provider_keywords[:6])
        print(f"[INFO] 可用关键字  : {preview}")
    print(f"[INFO] 会话名      : {session_name}")
    print(f"[INFO] Level       : {level}")
    print(f"[INFO] 回调模式    : {'传统 EVENT_TRACE' if legacy else 'EVENT_RECORD'}")
    if bogus:
        print("[INFO] 反证模式    : 使用不存在的会话名去 OpenTrace（预期应当失败）")
    print(f"[INFO] 采集时长    : {seconds}s" + (f"，上限 {max_events} 条" if max_events else ""))
    print()

    if etl_path:
        return _run_to_file(provider_name, guid, keywords, level, etl_path, session_name, seconds, workload)

    buffer, properties = api.build_properties(session_name)
    session = types.TRACEHANDLE()

    rc = api.StartTraceW(ctypes.byref(session), session_name, properties)
    if rc == types.ERROR_ALREADY_EXISTS:
        print("[WARN] 同名会话已存在，先停止再重建。")
        api.ControlTraceW(types.TRACEHANDLE(0), session_name, properties, types.EVENT_TRACE_CONTROL_STOP)
        rc = api.StartTraceW(ctypes.byref(session), session_name, properties)
    if rc != types.ERROR_SUCCESS:
        print(f"[FAIL] StartTraceW 失败，错误码 {rc} ({ctypes.FormatError(rc).strip()})")
        return 4

    consumer = types.TRACEHANDLE()
    started = time.perf_counter()
    try:
        provider_guid = types.guid_from_string(guid)
        rc = api.EnableTraceEx2(
            session,
            ctypes.byref(provider_guid),
            types.EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            level,
            keywords,
            0,
            0,
            None,
        )
        if rc != types.ERROR_SUCCESS:
            print(f"[FAIL] EnableTraceEx2 失败，错误码 {rc} ({ctypes.FormatError(rc).strip()})")
            return 5

        # 查询会话真实属性：确认 REAL_TIME 标志真的生效了
        probe_buffer, probe_props = api.build_properties(session_name)
        probe_rc = api.ControlTraceW(
            types.TRACEHANDLE(0), session_name, probe_props, types.EVENT_TRACE_CONTROL_QUERY
        )
        if probe_rc == types.ERROR_SUCCESS:
            mode = probe_props.contents.LogFileMode
            expected = types.EVENT_TRACE_REAL_TIME_MODE
            flag = "OK" if (mode & expected) else "未生效"
            print(f"诊断: 会话 LogFileMode = 0x{mode:08X} (期望含 0x{expected:08X}) -> {flag}")
            print(f"      会话 BufferSize  = {probe_props.contents.BufferSize} KB")
        else:
            print(f"诊断: 会话查询失败，错误码 {probe_rc}")
        del probe_buffer

        logfile = types.EVENT_TRACE_LOGFILEW()
        logfile.LoggerName = "WinMonitorSpikeNotExist" if bogus else session_name
        if legacy:
            logfile.ProcessTraceMode = types.PROCESS_TRACE_MODE_REAL_TIME
            logfile.EventRecordCallback = types.EVENT_RECORD_CALLBACK(
                ctypes.cast(LEGACY_CALLBACK, ctypes.c_void_p).value
            )
        else:
            logfile.ProcessTraceMode = (
                types.PROCESS_TRACE_MODE_REAL_TIME | types.PROCESS_TRACE_MODE_EVENT_RECORD
            )
            logfile.EventRecordCallback = CALLBACK
        logfile.BufferCallback = BUFFER_CALLBACK
        logfile.Context = None

        consumer = types.TRACEHANDLE(api.OpenTraceW(ctypes.pointer(logfile)))
        if consumer == types.INVALID_PROCESSTRACE_HANDLE:
            error = api.last_error()
            print(f"[FAIL] OpenTraceW 失败，错误码 {error} ({ctypes.FormatError(error).strip()})")
            return 6

        # OpenTraceW 会回写结构体，读回来可以验证它确实认了我们的配置
        print("诊断: OpenTrace 之后的回写值")
        print(f"  LoggerName 回读                  : {logfile.LoggerName!r}")
        print(f"  ProcessTraceMode 回读            : 0x{logfile.ProcessTraceMode:08X}")
        print(f"  LogfileHeader.NumberOfProcessors : {logfile.LogfileHeader.NumberOfProcessors}"
              f" (本机 {os.cpu_count()})")
        print(f"  消费者句柄                       : 0x{consumer:016X}")
        print()

        trace_handle = types.TRACEHANDLE(consumer)
        trace_result = {"rc": None, "start": 0.0, "end": 0.0}

        def _consume():
            trace_result["start"] = time.perf_counter()
            trace_result["rc"] = api.ProcessTrace(ctypes.byref(trace_handle), 1, None, None)
            trace_result["end"] = time.perf_counter()

        worker = threading.Thread(target=_consume, daemon=True)
        worker.start()

        _spawn_workload(workload)

        last_report = started
        while True:
            time.sleep(0.05)
            elapsed = time.perf_counter() - started
            if elapsed >= seconds:
                break
            if max_events and state.count >= max_events:
                break
            if elapsed - last_report >= 2.0:
                last_report = elapsed
                print(f"        ... 已采集 {state.count} 条 / {elapsed:.1f}s")

        # 停止前先查一次会话统计，能区分「没产生事件」和「产生了但没送到消费者」
        query_buffer, query_props = api.build_properties(session_name)
        query_rc = api.ControlTraceW(
            types.TRACEHANDLE(0), session_name, query_props, types.EVENT_TRACE_CONTROL_QUERY
        )
        session_stats = {}
        if query_rc == types.ERROR_SUCCESS:
            session_stats = {
                "buffers_written": query_props.contents.BuffersWritten,
                "events_lost": query_props.contents.EventsLost,
                "number_of_buffers": query_props.contents.NumberOfBuffers,
                "free_buffers": query_props.contents.FreeBuffers,
                "rt_lost": query_props.contents.RealTimeBuffersLost,
                "log_lost": query_props.contents.LogBuffersLost,
            }
        del query_buffer

        api.CloseTrace(consumer)
        worker.join(timeout=10)
        elapsed = time.perf_counter() - started
    finally:
        api.ControlTraceW(types.TRACEHANDLE(0), session_name, properties, types.EVENT_TRACE_CONTROL_STOP)

    lost_session = properties.contents.EventsLost
    lost_logfile = logfile.EventsLost

    print()
    print("=" * 62)
    print("结果汇总")
    print("=" * 62)
    print(f"采集条数        : {state.count}")
    if legacy:
        print(f"传统回调条数    : {_LEGACY_STATE['count']}")
    print(f"实际耗时        : {elapsed:.2f}s")
    rate = state.count / elapsed if elapsed > 0 else 0.0
    print(f"事件速率        : {rate:.0f} 条/秒")
    print(f"会话侧丢事件    : {lost_session}")
    print(f"消费侧丢事件    : {lost_logfile}")
    print(f"解码异常        : {state.decode_errors}")

    print()
    print("诊断信息")
    print("-" * 62)
    trace_seconds = 0.0
    if trace_result["start"] and trace_result["end"]:
        trace_seconds = trace_result["end"] - trace_result["start"]

    print(f"ProcessTrace 返回 : {trace_result['rc']}  （阻塞 {trace_seconds:.3f}s）")
    if trace_result["rc"] == 0 and trace_seconds < 0.5:
        print("  ^ 说明 ProcessTrace 立刻返回了，消费者没有进入实时等待状态")
    print(f"缓冲区回调次数    : {_BUFFER_COUNTER['count']}")
    print(f"消费者已读缓冲    : {logfile.BuffersRead}   已填充: {logfile.Filled}")
    if session_stats:
        print(f"会话写盘缓冲      : {session_stats['buffers_written']}  "
              f"会话丢事件: {session_stats['events_lost']}")
        print(f"会话缓冲数        : {session_stats['number_of_buffers']}  "
              f"空闲: {session_stats['free_buffers']}")
        print(f"实时投递失败      : {session_stats['rt_lost']}  "
              f"写盘失败: {session_stats['log_lost']}")
        if session_stats["rt_lost"] > 0:
            print("  ^ 实时缓冲被丢弃，说明会话认为「没有消费者在收」")
    else:
        print(f"会话统计查询失败  : {query_rc}")

    if state.event_ids:
        print("事件 ID 分布    :")
        for event_id, count in state.event_ids.most_common(10):
            print(f"    ID {event_id:<4} {count} 条")

    if state.samples:
        print()
        print("-" * 62)
        print("样本事件")
        print("-" * 62)
        for index, sample in enumerate(state.samples, 1):
            label = sample.get("event_name") or f"EventID {sample['event_id']}"
            print(f"[{index}] {sample['time']}  {label}  pid={sample['pid']} tid={sample['tid']} "
                  f"载荷={sample['payload_bytes']}B 关键字={sample['keyword']}")
            if sample.get("provider_name"):
                print(f"     提供者: {sample['provider_name']}  属性数: {sample.get('property_count', '-')}")
            for text in sample["strings"][:4]:
                print(f"     字符串: {text}")
            if sample.get("tdh_error"):
                print("     (TDH 解码异常，已降级为原始扫描)")
            if sample.get("raw"):
                print(f"     原始: {sample['raw']}")
    else:
        print()
        print("[WARN] 没有采集到任何事件。可能原因：")
        print("       1. 提供者 GUID 与系统不匹配（用 logman query providers 核对）")
        print("       2. 关键字位不适用于该提供者")
        print("       3. 采集时长内确实没有该类事件（进程事件在静置机器上可能很少）")

    return 0 if state.count > 0 else 7


def _run_to_file(provider_name, guid, keywords, level, etl_path, session_name, seconds, workload=20):
    """写 ETL 文件模式：不挂消费者，用来单独验证会话与提供者配置。"""
    absolute = os.path.abspath(etl_path)
    parent = os.path.dirname(absolute)
    if parent:
        os.makedirs(parent, exist_ok=True)
    if os.path.exists(absolute):
        os.remove(absolute)

    print("[INFO] 模式        : 写 ETL 文件（不挂消费者）")
    print(f"[INFO] 目标文件    : {absolute}")
    print()

    buffer, properties = api.build_properties(session_name, log_file_path=absolute, real_time=False)
    session = types.TRACEHANDLE()

    rc = api.StartTraceW(ctypes.byref(session), session_name, properties)
    if rc == types.ERROR_ALREADY_EXISTS:
        api.ControlTraceW(types.TRACEHANDLE(0), session_name, properties, types.EVENT_TRACE_CONTROL_STOP)
        rc = api.StartTraceW(ctypes.byref(session), session_name, properties)
    if rc != types.ERROR_SUCCESS:
        print(f"[FAIL] StartTraceW 失败，错误码 {rc} ({ctypes.FormatError(rc).strip()})")
        return 4

    try:
        provider_guid = types.guid_from_string(guid)
        rc = api.EnableTraceEx2(
            session,
            ctypes.byref(provider_guid),
            types.EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            level,
            keywords,
            0,
            0,
            None,
        )
        if rc != types.ERROR_SUCCESS:
            print(f"[FAIL] EnableTraceEx2 失败，错误码 {rc} ({ctypes.FormatError(rc).strip()})")
            return 5
        print(f"       采集 {seconds}s ...")
        _spawn_workload(workload)
        time.sleep(seconds)
    finally:
        api.ControlTraceW(types.TRACEHANDLE(0), session_name, properties, types.EVENT_TRACE_CONTROL_STOP)

    size = os.path.getsize(absolute) if os.path.exists(absolute) else 0
    written = properties.contents.BuffersWritten
    lost = properties.contents.EventsLost

    print()
    print("=" * 62)
    print(f"ETL 大小        : {size} 字节")
    print(f"会话写盘缓冲    : {written}")
    print(f"会话丢事件      : {lost}")
    print()
    if size > 0:
        print("结论: 会话配置与提供者启用正常，事件能进会话。")
        print("      问题在消费者一侧（OpenTrace / ProcessTrace / 回调）。")
    else:
        print("结论: 会话侧没有产生任何事件，问题在会话配置或 Level/Keyword 过滤。")
    return 0 if size > 0 else 7


def main(argv=None):
    parser = argparse.ArgumentParser(description="ETW 可行性验证 spike")
    parser.add_argument("--provider", default=DEFAULT_PROVIDER, help="ETW 提供者名称")
    parser.add_argument("--seconds", type=float, default=8.0, help="采集时长（秒）")
    parser.add_argument("--max-events", type=int, default=0, help="达到该条数后提前结束，0 表示不限")
    parser.add_argument("--keywords", default="0x70", help="匹配任一关键字（十六进制，默认进程/线程/映像）")
    parser.add_argument("--raw", action="store_true", help="额外打印载荷前 120 字节")
    parser.add_argument("--session", default="WinMonitorSpike", help="ETW 会话名")
    parser.add_argument(
        "--level",
        type=int,
        default=5,
        help="事件级别门限，4=信息 5=详细（默认 5，与 logman 对照组保持一致）",
    )
    parser.add_argument(
        "--etl",
        default="",
        help="改为写 ETL 文件模式，不挂消费者，用于隔离验证会话配置",
    )
    parser.add_argument(
        "--workload",
        type=int,
        default=20,
        help="采集期间拉起的短命进程数量，保证窗口内有事件（默认 20）",
    )
    parser.add_argument(
        "--legacy",
        action="store_true",
        help="改用传统 EVENT_TRACE 回调，用于排查 EVENT_RECORD 路径问题",
    )
    parser.add_argument(
        "--bogus",
        action="store_true",
        help="反证实验：用一个不存在的会话名调用 OpenTraceW，验证它是否真的在校验会话",
    )
    args = parser.parse_args(argv)

    try:
        keyword_bits = int(args.keywords, 16)
    except ValueError:
        print(f"[FAIL] 无法解析关键字: {args.keywords}")
        return 3

    return run(
        provider_name=args.provider,
        seconds=args.seconds,
        max_events=args.max_events,
        keywords=keyword_bits,
        want_raw=args.raw,
        session_name=args.session,
        level=args.level,
        etl_path=args.etl or None,
        workload=args.workload,
        legacy=args.legacy,
        bogus=args.bogus,
    )


if __name__ == "__main__":
    sys.exit(main())
