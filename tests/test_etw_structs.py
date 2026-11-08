#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ETW 结构体布局测试

这些断言不验证运行时行为，只保证 ctypes 定义与 Windows SDK 的布局一致。
布局一旦写错，OpenTraceW 会读到错误字段导致采集静默失效，
所以把它固化成测试比靠肉眼核对更可靠。
"""

import ctypes
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from collect.etw import etwtypes as types


def test_basic_sizes():
    assert ctypes.sizeof(types.GUID) == 16
    assert ctypes.sizeof(types.WNODE_HEADER) == 48
    assert ctypes.sizeof(types.EVENT_TRACE_PROPERTIES) == 120


def test_event_trace_sizes():
    # EVENT_TRACE_HEADER 末尾是一个 8 字节联合体，总长 48。
    # 早期实现误拆成两个字段（56 字节），导致 EVENT_TRACE_LOGFILEW 里
    # EventRecordCallback 偏移错位 8 字节，ETW 永远读不到回调。
    assert ctypes.sizeof(types.EVENT_TRACE_HEADER) == 48
    assert ctypes.sizeof(types.EVENT_DESCRIPTOR) == 16
    assert ctypes.sizeof(types.EVENT_HEADER) == 80
    assert ctypes.sizeof(types.ETW_BUFFER_CONTEXT) == 4
    assert ctypes.sizeof(types.EVENT_RECORD) == 112


def test_logfile_header_sizes():
    assert ctypes.sizeof(types.SYSTEMTIME) == 16
    assert ctypes.sizeof(types.TIME_ZONE_INFORMATION) == 172
    assert ctypes.sizeof(types.TRACE_LOGFILE_HEADER) == 280
    assert ctypes.sizeof(types.EVENT_TRACE) == 88
    assert ctypes.sizeof(types.EVENT_TRACE_LOGFILEW) == 448


def test_event_record_offsets():
    assert types.EVENT_RECORD.EventHeader.offset == 0
    assert types.EVENT_RECORD.BufferContext.offset == 80
    assert types.EVENT_RECORD.UserDataLength.offset == 86
    assert types.EVENT_RECORD.UserData.offset == 96


def test_logfile_offsets():
    assert types.EVENT_TRACE_LOGFILEW.LoggerName.offset == 8
    assert types.EVENT_TRACE_LOGFILEW.ProcessTraceMode.offset == 28
    assert types.EVENT_TRACE_LOGFILEW.CurrentEvent.offset == 32
    assert types.EVENT_TRACE_LOGFILEW.LogfileHeader.offset == 120
    assert types.EVENT_TRACE_LOGFILEW.BufferCallback.offset == 400
    assert types.EVENT_TRACE_LOGFILEW.EventsLost.offset == 416
    assert types.EVENT_TRACE_LOGFILEW.EventRecordCallback.offset == 424
    assert types.EVENT_TRACE_LOGFILEW.Context.offset == 440


def test_guid_parse_and_format():
    parsed = types.guid_from_string("{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}")
    assert parsed.Data1 == 0x22FB2CD6
    assert parsed.Data2 == 0x0E7B
    assert parsed.Data3 == 0x422B
    assert str(parsed).upper() == "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"

    lenient = types.guid_from_string("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716")
    assert lenient.Data1 == parsed.Data1


def test_guid_rejects_bad_input():
    for bad in ("", "xyz", "22FB2CD6-0E7B-422B"):
        try:
            types.guid_from_string(bad)
        except ValueError:
            continue
        raise AssertionError(f"应当拒绝非法 GUID: {bad!r}")


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
