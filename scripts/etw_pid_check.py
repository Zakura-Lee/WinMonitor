#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PID 语义对账（需管理员权限）

目的:
    验证进程创建事件里的 pid 到底该取事件头还是载荷。
    做法是记下真实 Popen 出来的 PID，再去和两种取法比交集。

用法（管理员）:
    python scripts/etw_pid_check.py
"""

import collections
import os
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from collect.collector import EtwCollector
from collect.etw import api, providers


def main():
    if not api.IsUserAnAdmin():
        print("[FAIL] 需要管理员权限")
        return 2

    spawned = []
    events = []

    def spawn(count=8):
        for _ in range(count):
            try:
                proc = subprocess.Popen(
                    ["cmd", "/c", "ping -n 2 127.0.0.1 > nul"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                spawned.append(proc.pid)
            except OSError:
                pass

    def on_event(event):
        if event.event_id == providers.EVENT_PROCESS_START:
            events.append(event)

    collector = EtwCollector(session_name="WinMonitorPidCheck", on_event=on_event)
    print("[INFO] 开始采集，同时拉起 8 个存活约 1 秒的进程 ...")
    try:
        collector.start()
        threading.Thread(target=spawn, daemon=True).start()
        time.sleep(6)
    finally:
        collector.stop()

    real = set(spawned)
    from_header = [event.pid for event in events]
    # 目前 normalize 优先用载荷字段，这里再看一眼载荷里的原始值
    from_payload = [
        (event.extra.get("fields") or {}).get("ProcessId") for event in events
    ]

    print()
    print("=" * 58)
    print(f"本次真实创建的 PID   : {sorted(real)}")
    print(f"ProcessStart 事件数   : {len(events)}")
    print(f"事件里读取的 pid      : {from_header}")
    print(f"载荷里的 ProcessId    : {from_payload}")
    print()

    hit_header = len(real & set(from_header))
    hit_payload = len(real & set(p for p in from_payload if p))
    print(f"事件头 pid 命中真实 PID 数: {hit_header} / {len(real)}")
    print(f"载荷 pid 命中真实 PID 数  : {hit_payload} / {len(real)}")
    print()

    dup = [pid for pid, count in collections.Counter(from_header).items() if count > 1]
    print(f"事件头 pid 出现重复的值   : {dup}")

    if hit_payload >= hit_header and hit_payload > 0:
        print("结论: 载荷里的 ProcessId 才是事件主体。")
    elif hit_header > hit_payload:
        print("结论: 事件头 pid 更接近真实 PID。")
    else:
        print("结论: 两组都没命中，需要进一步检查解析正确性。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
