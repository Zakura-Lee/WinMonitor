#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P3 采集层核心组件测试（不需要管理员权限）"""

import ctypes
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from collect import normalize
from collect.etw import providers
from collect.bus import EventBus
from collect.model import FILETIME_EPOCH_DELTA, Event, RawEvent


def _wstr(text):
    """构造一个 NUL 结尾的 UTF-16LE 字符串。"""
    return text.encode("utf-16-le") + b"\x00\x00"


def test_event_defaults():
    event = Event(ts_ns=1_000_000_000)
    assert event.source == "etw"
    assert event.pid == 0
    assert event.extra == {}
    payload = event.to_dict()
    assert payload["event_id"] == 0
    assert event.timestamp_seconds() == 1.0


def test_bus_basic():
    bus = EventBus(maxsize=4)
    assert bus.put("a") is True
    assert bus.put("b") is True
    assert bus.get(timeout=0.1) == "a"
    assert bus.get(timeout=0.1) == "b"
    assert bus.get(timeout=0.05) is None


def test_bus_overflow_counts_drops():
    bus = EventBus(maxsize=2)
    assert bus.put(1) is True
    assert bus.put(2) is True
    assert bus.put(3) is False
    stats = bus.stats()
    assert stats["put"] == 2
    assert stats["drop"] == 1
    assert stats["qsize"] == 2


def test_nt_path_passthrough():
    assert normalize.nt_path_to_dos("") == ""
    assert normalize.nt_path_to_dos(r"C:\Windows\System32") == r"C:\Windows\System32"


def test_nt_path_real_mapping():
    buffer = ctypes.create_unicode_buffer(1024)
    if not ctypes.WinDLL("kernel32").QueryDosDeviceW("C:", buffer, 1024):
        return  # 没有 C: 盘时跳过
    device = buffer.value
    converted = normalize.nt_path_to_dos(device + r"\Windows\System32\cmd.exe")
    assert converted.lower().startswith("c:\\"), converted


def test_extract_wide_strings():
    data = _wstr("hello world") + _wstr("second-string")
    found = normalize.extract_wide_strings(data)
    assert found[0] == "hello world"
    assert found[1] == "second-string"


def test_to_event_process_start():
    payload = _wstr(r"\Device\HarddiskVolume3\Windows\System32\cmd.exe") + _wstr(
        "cmd.exe /c exit"
    )
    raw = RawEvent(
        ts_ns=(134386229755751072 - FILETIME_EPOCH_DELTA) * 100,
        provider_id=providers.guid_bytes(providers.KERNEL_PROCESS.guid),
        event_id=providers.EVENT_PROCESS_START,
        level=4,
        keyword=0x10,
        pid=4242,
        tid=4243,
        payload=payload,
    )
    event = normalize.to_event(raw)
    assert event.provider == "Microsoft-Windows-Kernel-Process"
    assert event.event_id == providers.EVENT_PROCESS_START
    assert event.pid == 4242
    assert event.tid == 4243
    assert "cmd.exe" in event.image
    # 没有 TDH 布局时只能扫到路径，命令行需要结构化字段（见 test_to_event_prefers_structured_fields）
    assert event.cmdline == ""


def test_provider_guid_bytes():
    data = providers.guid_bytes(providers.KERNEL_PROCESS.guid)
    assert len(data) == 16
    assert providers.GUID_TO_NAME[data] == "Microsoft-Windows-Kernel-Process"


def test_decode_payload_integer_and_string():
    from collect.etw.tdh import Property, decode_payload

    props = (
        Property("ProcessId", 8, 0, 0, 0, 0),
        Property("ParentProcessId", 8, 0, 0, 0, 0),
        Property("ImageFileName", 1, 0, 0, 0, 0),
        Property("CommandLine", 1, 0, 0, 0, 0),
    )
    payload = (4242).to_bytes(4, "little") + (1).to_bytes(4, "little")
    payload += "cmd.exe".encode("utf-16-le") + b"\x00\x00"
    payload += "cmd.exe /c exit".encode("utf-16-le") + b"\x00\x00"

    fields = decode_payload(payload, props)
    assert fields["ProcessId"] == 4242
    assert fields["ParentProcessId"] == 1
    assert fields["ImageFileName"] == "cmd.exe"
    assert fields["CommandLine"] == "cmd.exe /c exit"


def test_to_event_sysmon_uses_payload_pid():
    """Sysmon 事件由 Sysmon64.exe 记录，pid 必须取自载荷。"""
    from collect.etw.tdh import Property

    props = (
        Property("ProcessId", 8, 0, 0, 0, 0),
        Property("ParentProcessId", 8, 0, 0, 0, 0),
        Property("Image", 1, 0, 0, 0, 0),
        Property("CommandLine", 1, 0, 0, 0, 0),
        Property("ProcessGuid", 1, 0, 0, 0, 0),
        Property("ParentProcessGuid", 1, 0, 0, 0, 0),
        Property("IntegrityLevel", 1, 0, 0, 0, 0),
    )
    guid = "{11111111-2222-3333-4444-555555555555}"
    parent_guid = "{66666666-7777-8888-9999-000000000000}"
    payload = (4242).to_bytes(4, "little") + (1).to_bytes(4, "little")
    payload += r"C:\Windows\System32\cmd.exe".encode("utf-16-le") + b"\x00\x00"
    payload += "cmd.exe /c exit".encode("utf-16-le") + b"\x00\x00"
    payload += guid.encode("utf-16-le") + b"\x00\x00"
    payload += parent_guid.encode("utf-16-le") + b"\x00\x00"
    payload += "High".encode("utf-16-le") + b"\x00\x00"

    raw = RawEvent(
        ts_ns=0,
        provider_id=providers.guid_bytes(providers.SYSMON.guid),
        event_id=1,
        level=4,
        keyword=0,
        pid=1234,  # Sysmon 自身的 pid
        tid=1,
        payload=payload,
        properties=props,
    )
    event = normalize.to_event(raw)
    assert event.provider == "Microsoft-Windows-Sysmon"
    assert event.pid == 4242
    assert event.ppid == 1
    assert event.cmdline == "cmd.exe /c exit"
    assert event.process_guid == guid
    assert event.parent_guid == parent_guid
    assert event.integrity == "High"
    assert event.image.endswith("cmd.exe")


def test_to_event_uses_header_pid():
    """对账结论：Kernel-Process 的事件头 pid 才是事件主体。

    见 scripts/etw_pid_check.py 的实测输出：事件头 8/8 命中真实 PID。
    该提供者不含 CommandLine 字段，命令行需由 Sysmon 提供。
    """
    from collect.etw.tdh import Property

    props = (
        Property("ProcessID", 8, 0, 0, 0, 0),
        Property("ParentProcessID", 8, 0, 0, 0, 0),
        Property("ImageName", 1, 0, 0, 0, 0),
        Property("ProcessSequenceNumber", 10, 0, 0, 0, 0),
    )
    image = r"C:\Windows\System32\cmd.exe"
    payload = (4242).to_bytes(4, "little") + (1).to_bytes(4, "little")
    payload += image.encode("utf-16-le") + b"\x00\x00"
    if len(payload) % 8:
        payload += b"\x00" * (8 - len(payload) % 8)
    payload += (6697650994420908032).to_bytes(8, "little")

    raw = RawEvent(
        ts_ns=0,
        provider_id=providers.guid_bytes(providers.KERNEL_PROCESS.guid),
        event_id=providers.EVENT_PROCESS_START,
        level=4,
        keyword=0x10,
        pid=9999,  # 事件头里的 pid，最终采用的就是它
        tid=1,
        payload=payload,
        properties=props,
    )
    event = normalize.to_event(raw)
    assert event.pid == 9999
    assert event.ppid == 1
    assert event.process_key == 6697650994420908032
    assert event.image.endswith("cmd.exe")
    assert event.cmdline == ""
    assert event.extra["fields"]["ProcessID"] == 4242


def test_session_config_keys_match_api():
    """EtwSession 的内部配置键必须与 build_properties 的形参一致。

    这条断言是为了避免形参名改动后，构造会话时才在运行期报 TypeError。
    """
    from collect.etw import api
    from collect.etw.session import EtwSession

    session = EtwSession("TestSession")
    buffer, properties = api.build_properties(session.name, **session._config)
    assert properties.contents.Wnode.BufferSize > 0
    assert properties.contents.LoggerNameOffset > 0
    del buffer


def test_decode_loop_drains_pending():
    """停止后解码线程必须把队列里剩余的事件处理完，不能丢尾巴。"""
    from collect.collector import EtwCollector

    seen = []
    collector = EtwCollector(session_name="DrainTest", on_event=seen.append)
    for _ in range(3):
        collector.bus.put(
            RawEvent(
                ts_ns=0,
                provider_id=providers.guid_bytes(providers.SYSMON.guid),
                event_id=3,
                level=4,
                keyword=0x20,
                pid=1,
                tid=2,
                payload=b"",
            )
        )
    # 未置位 _running，循环应在排空队列后自行返回
    collector._decode_loop()
    assert len(seen) == 3
    assert collector.bus.qsize() == 0


def test_decode_loop_skips_unknown_provider():
    """提供者为全零的会话元数据事件应被丢弃，不能污染统计。"""
    from collect.collector import EtwCollector

    seen = []
    collector = EtwCollector(session_name="SkipTest", on_event=seen.append)
    collector.bus.put(
        RawEvent(
            ts_ns=0,
            provider_id=b"\x00" * 16,
            event_id=0,
            level=0,
            keyword=0,
            pid=0,
            tid=0,
            payload=b"",
        )
    )
    collector._decode_loop()
    assert seen == []
    assert collector.skipped_unknown == 1
    assert collector.handled == 0


def test_classify_registry():
    from collect.detect import classify_registry

    run_key = Event(
        ts_ns=0,
        key=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Foo",
        value=r"C:\Program Files\App\app.exe",
    )
    kind, reason, severity = classify_registry(run_key)
    assert kind == "abnormal"
    assert severity == "warning"
    assert "自启动" in reason

    suspicious = Event(
        ts_ns=0,
        key=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\X",
        value=r"powershell -w hidden -enc AAAA",
    )
    assert classify_registry(suspicious)[0] == "danger"
    assert classify_registry(suspicious)[2] == "critical"

    run_once = Event(
        ts_ns=0,
        key=r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce\Y",
        value="ok",
    )
    assert classify_registry(run_once)[0] == "normal"

    assert classify_registry(Event(ts_ns=0, key=""))[0] == "normal"


def test_to_event_sysmon_registry():
    from collect.etw.tdh import Property

    props = (
        Property("ProcessId", 8, 0, 0, 0, 0),
        Property("Image", 1, 0, 0, 0, 0),
        Property("TargetObject", 1, 0, 0, 0, 0),
        Property("Details", 1, 0, 0, 0, 0),
        Property("EventType", 1, 0, 0, 0, 0),
    )
    key = r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\WinMonitorProbe"
    payload = (7777).to_bytes(4, "little")
    payload += r"C:\Windows\System32\reg.exe".encode("utf-16-le") + b"\x00\x00"
    payload += key.encode("utf-16-le") + b"\x00\x00"
    payload += r"C:\Windows\System32\cmd.exe".encode("utf-16-le") + b"\x00\x00"
    payload += "SetValue".encode("utf-16-le") + b"\x00\x00"

    raw = RawEvent(
        ts_ns=0,
        provider_id=providers.guid_bytes(providers.SYSMON.guid),
        event_id=13,
        level=4,
        keyword=0,
        pid=999,
        tid=1,
        payload=payload,
        properties=props,
    )
    event = normalize.to_event(raw)
    assert event.key == key
    assert event.value.endswith("cmd.exe")
    assert event.extra["registry_action"] == "SetValue"


def test_classify_file():
    from collect.detect import classify_file

    trusted = Event(ts_ns=0, path=r"C:\Windows\System32\drivers\ndis.sys")
    assert classify_file(trusted)[0] == "normal"

    dropped = Event(ts_ns=0, path=r"C:\Users\a\AppData\Local\Temp\evil.exe")
    kind, reason, severity = classify_file(dropped)
    assert kind == "danger"
    assert severity == "critical"
    assert "可执行扩展" in reason

    # 非可执行文件落在临时目录只记录、不告警，避免淹没有效信号
    note = Event(ts_ns=0, path=r"C:\Users\a\AppData\Local\Temp\notes.txt")
    assert classify_file(note)[0] == "normal"

    benign = Event(ts_ns=0, path=r"D:\work\notes.txt")
    assert classify_file(benign)[0] == "normal"

    empty = Event(ts_ns=0, path="")
    assert classify_file(empty)[0] == "normal"


def test_to_event_sysmon_file_create():
    from collect.etw.tdh import Property

    props = (
        Property("ProcessId", 8, 0, 0, 0, 0),
        Property("Image", 1, 0, 0, 0, 0),
        Property("TargetFilename", 1, 0, 0, 0, 0),
        Property("ProcessGuid", 1, 0, 0, 0, 0),
    )
    payload = (4321).to_bytes(4, "little")
    payload += r"C:\Windows\System32\powershell.exe".encode("utf-16-le") + b"\x00\x00"
    payload += r"C:\Users\a\AppData\Local\Temp\dropper.exe".encode("utf-16-le") + b"\x00\x00"
    payload += "{AAAA}".encode("utf-16-le") + b"\x00\x00"

    raw = RawEvent(
        ts_ns=0,
        provider_id=providers.guid_bytes(providers.SYSMON.guid),
        event_id=11,
        level=4,
        keyword=0,
        pid=999,
        tid=1,
        payload=payload,
        properties=props,
    )
    event = normalize.to_event(raw)
    assert event.path.endswith("dropper.exe")
    assert event.image.endswith("powershell.exe")
    assert event.pid == 4321


def test_format_endpoint():
    from collect.detect import format_endpoint

    assert format_endpoint("8.8.8.8", 53) == "8.8.8.8:53"
    assert format_endpoint("240e:460:8f0::22", 443) == "[240e:460:8f0::22]:443"
    assert format_endpoint("", 0) == ":0"


def test_is_public_address_variants():
    from collect.detect import is_public_address

    assert is_public_address("8.8.8.8")
    assert not is_public_address("192.168.1.1")
    assert not is_public_address("10.0.0.5")
    assert not is_public_address("127.0.0.1")
    assert not is_public_address("::1")
    assert not is_public_address("fe80::1234")
    assert not is_public_address("")


def test_classify_network():
    from collect.detect import classify_network

    attack = Event(ts_ns=0, daddr="8.8.8.8", dport=4444)
    assert classify_network(attack)[0] == "attack"
    assert classify_network(attack)[2] == "critical"

    internal = Event(ts_ns=0, daddr="192.168.1.10", dport=4444)
    assert classify_network(internal)[0] == "normal"

    safe = Event(ts_ns=0, daddr="1.1.1.1", dport=443)
    assert classify_network(safe)[0] == "normal"


def test_to_event_sysmon_network():
    from collect.etw.tdh import Property

    props = (
        Property("ProcessId", 8, 0, 0, 0, 0),
        Property("Image", 1, 0, 0, 0, 0),
        Property("Protocol", 1, 0, 0, 0, 0),
        Property("SourceIp", 1, 0, 0, 0, 0),
        Property("SourcePort", 6, 0, 0, 0, 0),
        Property("DestinationIp", 1, 0, 0, 0, 0),
        Property("DestinationPort", 6, 0, 0, 0, 0),
    )
    payload = (1234).to_bytes(4, "little")
    payload += r"C:\Windows\System32\curl.exe".encode("utf-16-le") + b"\x00\x00"
    payload += "tcp".encode("utf-16-le") + b"\x00\x00"
    payload += "10.0.0.5".encode("utf-16-le") + b"\x00\x00"
    payload += (50000).to_bytes(2, "little")
    payload += "8.8.8.8".encode("utf-16-le") + b"\x00\x00"
    payload += (4444).to_bytes(2, "little")

    raw = RawEvent(
        ts_ns=0,
        provider_id=providers.guid_bytes(providers.SYSMON.guid),
        event_id=3,
        level=4,
        keyword=0,
        pid=999,  # Sysmon 自身
        tid=1,
        payload=payload,
        properties=props,
    )
    event = normalize.to_event(raw)
    assert event.pid == 1234
    assert event.proto == "tcp"
    assert event.saddr == "10.0.0.5"
    assert event.sport == 50000
    assert event.daddr == "8.8.8.8"
    assert event.dport == 4444


def test_process_table_parent_chain():
    from collect.proctree import ProcessTable

    table = ProcessTable()
    parent = Event(ts_ns=1000, pid=100, ppid=4, image=r"C:\Windows\System32\cmd.exe",
                   process_guid="{A}")
    child = Event(ts_ns=2000, pid=200, ppid=100, image=r"C:\Windows\System32\ping.exe",
                  process_guid="{B}", parent_guid="{A}")

    table.add_start(parent)
    record = table.add_start(child)
    assert record.parent_key == "guid:{A}"

    names = table.ancestors_names(record.key)
    assert names[0].endswith("ping.exe")
    assert names[1].endswith("cmd.exe")
    assert table.stats()["started"] == 2


def test_process_table_marks_stop():
    from collect.proctree import ProcessTable

    table = ProcessTable()
    start = Event(ts_ns=1000, pid=500, ppid=4, image=r"C:\a.exe", process_guid="{C}")
    table.add_start(start)
    stop = Event(ts_ns=9000, pid=500, ppid=0, process_guid="{C}")

    record = table.mark_stop(stop)
    assert record is not None
    assert record.alive is False
    assert record.stopped_ns == 9000
    assert table.stats()["stopped"] == 1


def test_process_table_pid_reuse_keeps_distinct_records():
    from collect.proctree import ProcessTable

    table = ProcessTable()
    first = Event(ts_ns=1000, pid=700, ppid=4, image=r"C:\one.exe", process_guid="{D}")
    second = Event(ts_ns=3000, pid=700, ppid=4, image=r"C:\two.exe", process_guid="{E}")
    table.add_start(first)
    table.add_start(second)

    assert table.get("guid:{D}").image.endswith("one.exe")
    assert table.get("guid:{E}").image.endswith("two.exe")
    # 按 PID 查应返回最近一次出现的那个
    assert table.latest_by_pid(700).image.endswith("two.exe")


def test_process_table_records_unresolved_parent():
    from collect.proctree import ProcessTable

    table = ProcessTable()
    orphan = Event(ts_ns=1000, pid=800, ppid=999, image=r"C:\orphan.exe")
    record = table.add_start(orphan)
    assert record.parent_key == ""
    assert table.stats()["unresolved_parent"] == 1


def test_plan_collectors_etw_skips_legacy():
    """ETW 成功启动时，不应再装配已被覆盖的 legacy 采集器。"""
    from core.monitor import plan_collectors

    names = plan_collectors("etw", True)
    assert names == ["audit", "asset"]
    for legacy in ("process", "file", "network", "registry"):
        assert legacy not in names, f"{legacy} 不应在 ETW 模式下启动"


def test_plan_collectors_legacy_full():
    from core.monitor import plan_collectors

    names = plan_collectors("legacy", False)
    for expected in ("process", "file", "network", "registry", "audit", "asset"):
        assert expected in names

    # ETW 声明成功但实际没起来时，也要退回全套，避免漏采
    fallback = plan_collectors("etw", False)
    assert fallback == names


def test_monitor_status_exposes_backend():
    from core.monitor import monitor_service

    import config

    status = monitor_service.status()
    assert status["backend"] == config.MONITOR_BACKEND
    assert "etw_primary" in status
    assert "etw_fallback_reason" in status


def test_etw_backend_falls_back_without_admin():
    """非管理员时 ETW 后端应返回 False 并记录原因，由调用方回退到 legacy。"""
    import ctypes

    if ctypes.windll.shell32.IsUserAnAdmin():
        return  # 管理员环境下会真的建会话，跳过

    from core.monitor import MonitorService

    service = MonitorService()
    started = service._start_etw_backend(service.process_data, service.alert_queue)
    assert started is False
    assert service.etw_fallback_reason


def test_collector_importable():
    from collect.collector import EtwCollector

    collector = EtwCollector(session_name="TestOnly")
    assert collector.bus is not None
    assert [spec.name for spec in collector.provider_specs] == [
        "Microsoft-Windows-Kernel-Process",
        "Microsoft-Windows-Sysmon",
    ]
    assert collector.stats()["handled"] == 0
    assert collector.disabled_providers == []


if __name__ == "__main__":
    failures = 0
    for name in sorted(n for n in dir() if n.startswith("test_")):
        fn = globals()[name]
        try:
            fn()
            print(f"PASS  {name}")
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print(f"FAIL  {name}: {type(exc).__name__}: {exc}")
    print()
    print("全部通过" if failures == 0 else f"{failures} 个测试失败")
    sys.exit(1 if failures else 0)
