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
    assert event.cmdline == "cmd.exe /c exit"


def test_provider_guid_bytes():
    data = providers.guid_bytes(providers.KERNEL_PROCESS.guid)
    assert len(data) == 16
    assert providers.GUID_TO_NAME[data] == "Microsoft-Windows-Kernel-Process"


def test_collector_importable():
    from collect.collector import EtwCollector

    collector = EtwCollector(session_name="TestOnly")
    assert collector.bus is not None
    assert [spec.name for spec in collector.provider_specs] == [
        "Microsoft-Windows-Kernel-Process"
    ]
    assert collector.stats()["handled"] == 0


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
