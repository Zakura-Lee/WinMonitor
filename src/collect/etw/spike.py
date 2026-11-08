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
    return 0


CALLBACK = types.EVENT_RECORD_CALLBACK(_on_event)


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

def run(provider_name, seconds, max_events, keywords, want_raw, session_name):
    state = SpikeState(max_events=max_events, want_raw=want_raw)
    global _STATE
    _STATE = state

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
    print(f"[INFO] 采集时长    : {seconds}s" + (f"，上限 {max_events} 条" if max_events else ""))
    print()

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
            types.TRACE_LEVEL_INFORMATION,
            keywords,
            0,
            0,
            None,
        )
        if rc != types.ERROR_SUCCESS:
            print(f"[FAIL] EnableTraceEx2 失败，错误码 {rc} ({ctypes.FormatError(rc).strip()})")
            return 5

        logfile = types.EVENT_TRACE_LOGFILEW()
        logfile.LoggerName = session_name
        logfile.ProcessTraceMode = (
            types.PROCESS_TRACE_MODE_REAL_TIME | types.PROCESS_TRACE_MODE_EVENT_RECORD
        )
        logfile.EventRecordCallback = ctypes.cast(CALLBACK, ctypes.c_void_p)
        logfile.Context = None

        consumer = api.OpenTraceW(ctypes.pointer(logfile))
        if consumer == types.INVALID_PROCESSTRACE_HANDLE:
            error = api.last_error()
            print(f"[FAIL] OpenTraceW 失败，错误码 {error} ({ctypes.FormatError(error).strip()})")
            return 6

        handles = (types.TRACEHANDLE * 1)(consumer)
        worker = threading.Thread(
            target=api.ProcessTrace,
            args=(handles, 1, None, None),
            daemon=True,
        )
        worker.start()

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
    print(f"实际耗时        : {elapsed:.2f}s")
    rate = state.count / elapsed if elapsed > 0 else 0.0
    print(f"事件速率        : {rate:.0f} 条/秒")
    print(f"会话侧丢事件    : {lost_session}")
    print(f"消费侧丢事件    : {lost_logfile}")
    print(f"解码异常        : {state.decode_errors}")

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


def main(argv=None):
    parser = argparse.ArgumentParser(description="ETW 可行性验证 spike")
    parser.add_argument("--provider", default=DEFAULT_PROVIDER, help="ETW 提供者名称")
    parser.add_argument("--seconds", type=float, default=8.0, help="采集时长（秒）")
    parser.add_argument("--max-events", type=int, default=0, help="达到该条数后提前结束，0 表示不限")
    parser.add_argument("--keywords", default="0x70", help="匹配任一关键字（十六进制，默认进程/线程/映像）")
    parser.add_argument("--raw", action="store_true", help="额外打印载荷前 120 字节")
    parser.add_argument("--session", default="WinMonitorSpike", help="ETW 会话名")
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
    )


if __name__ == "__main__":
    sys.exit(main())
