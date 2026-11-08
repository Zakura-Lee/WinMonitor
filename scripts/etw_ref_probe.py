#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
交叉验证探针：用 pywintrace 的底层类跑同样的场景。

绕开 pywintrace 的 ETW 包装层，因为它在 Python 3.15 上会把会话句柄
当成字符串传给 byref()；直接使用 EventProvider + EventConsumer，
这正是它的 ETW.start() 内部做的事。

用法（需管理员权限）:
    python scripts/etw_ref_probe.py
"""

import subprocess
import sys
import threading
import time
import uuid

PROVIDER_NAME = "Microsoft-Windows-Kernel-Process"
PROVIDER_GUID = "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"
# 每次用唯一会话名，避免上次异常退出残留的同名会话导致 ERROR_ALREADY_EXISTS
SESSION_NAME = "WinMonitorRef_" + uuid.uuid4().hex[:8]

STATE = {"count": 0, "samples": [], "callbacks": 0, "errors": 0}


def _event_callback(events):
    """pywintrace 每个缓冲回调一次，参数是该缓冲里的事件列表。"""
    try:
        STATE["callbacks"] += 1
        for item in events:
            STATE["count"] += 1
            if len(STATE["samples"]) < 5:
                STATE["samples"].append(item)
    except Exception as exc:  # noqa: BLE001
        STATE["errors"] += 1
        print("回调异常:", exc)


def _spawn_workload(count=20):
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


def main():
    try:
        from etw import ProviderInfo
        from etw.etw import EventConsumer, EventProvider, TraceProperties
    except ImportError as exc:
        print("[FAIL] 无法导入 pywintrace:", exc)
        return 2

    seconds = 6.0
    provider_info = ProviderInfo(PROVIDER_NAME, PROVIDER_GUID, level=5, any_keywords=0x70)
    properties = TraceProperties(ring_buf_size=64, min_buffers=4, max_buffers=32)

    print(f"[REF] 提供者: {PROVIDER_NAME}")
    print(f"[REF] GUID  : {PROVIDER_GUID}")
    print(f"[REF] 会话  : {SESSION_NAME}")
    print(f"[REF] 时长  : {seconds}s")
    print()

    provider = EventProvider(SESSION_NAME, properties, [provider_info])
    consumer = None

    try:
        provider.start()
    except Exception as exc:  # noqa: BLE001
        print("[FAIL] 启动会话失败:", type(exc).__name__, exc)
        return 3

    try:
        consumer = EventConsumer(SESSION_NAME, _event_callback)
        consumer.start()
        _spawn_workload()
        time.sleep(seconds)
    except Exception as exc:  # noqa: BLE001
        print("[FAIL] 启动消费者失败:", type(exc).__name__, exc)
    finally:
        try:
            if consumer is not None:
                consumer.stop()
        except Exception as exc:  # noqa: BLE001
            print("[WARN] 停止消费者出错:", exc)
        try:
            provider.stop()
        except Exception as exc:  # noqa: BLE001
            print("[WARN] 停止会话出错:", exc)

    print("=" * 50)
    print(f"回调次数   : {STATE['callbacks']}")
    print(f"事件条数   : {STATE['count']}")
    print(f"回调异常   : {STATE['errors']}")
    for index, sample in enumerate(STATE["samples"], 1):
        print(f"[{index}] {sample}")
    print()
    if STATE["count"] > 0:
        print("结论: 参照实现能收到事件 -> 我们的实现有 bug，可对照修复。")
    else:
        print("结论: 参照实现也收不到 -> 这台机器的实时消费路径有问题。")
    return 0 if STATE["count"] > 0 else 7


if __name__ == "__main__":
    sys.exit(main())
