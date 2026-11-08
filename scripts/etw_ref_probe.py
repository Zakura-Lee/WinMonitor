#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
交叉验证探针：用 pywintrace 这个成熟的 ctypes 绑定跑同样的场景。

目的只有一个：把「我们的实现有 bug」和「这台机器实时消费不可用」
两种情况区分开。不进入正式代码路径。

用法（需管理员权限）:
    python scripts/etw_ref_probe.py
"""

import os
import subprocess
import sys
import threading
import time

PROVIDER_NAME = "Microsoft-Windows-Kernel-Process"
PROVIDER_GUID = "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"

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
        from etw import ETW, ProviderInfo
    except ImportError as exc:
        print("[FAIL] 无法导入 pywintrace:", exc)
        return 2

    seconds = 6.0
    provider = ProviderInfo(
        PROVIDER_NAME, PROVIDER_GUID, level=5, any_keywords=0x70
    )

    print(f"[REF] 提供者: {PROVIDER_NAME}")
    print(f"[REF] GUID  : {PROVIDER_GUID}")
    print(f"[REF] 会话  : WinMonitorRef")
    print(f"[REF] 时长  : {seconds}s")
    print()

    session = ETW(
        session_name="WinMonitorRef",
        providers=[provider],
        event_callback=_event_callback,
        ring_buf_size=64,
        min_buffers=4,
        max_buffers=32,
        ignore_exists_error=True,
    )

    try:
        session.start()
    except Exception as exc:  # noqa: BLE001
        print("[FAIL] 启动失败:", type(exc).__name__, exc)
        return 3

    try:
        _spawn_workload()
        time.sleep(seconds)
    finally:
        try:
            session.stop()
        except Exception as exc:  # noqa: BLE001
            print("[WARN] 停止时出错:", exc)

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
