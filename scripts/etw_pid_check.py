#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
P4 字段核对（需管理员权限）

做三件事:
    1. 用真实创建的 PID 对账，确认事件头 pid 才是事件主体；
    2. 打印 ProcessStart 事件的真实属性名，供归一化层对接；
    3. 检查 ParentProcessID / CommandLine / ProcessKey 是否解出。

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


def _get(fields, *names):
    """不区分大小写地从字段字典取值。"""
    if not fields:
        return None
    lowered = {str(k).lower(): v for k, v in fields.items()}
    for name in names:
        value = lowered.get(name.lower())
        if value not in (None, ""):
            return value
    return None


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
    from_payload = [_get(event.extra.get("fields") or {}, "ProcessID", "ProcessId") for event in events]

    print()
    print("=" * 62)
    print(f"真实创建的 PID      : {sorted(real)}")
    print(f"ProcessStart 事件数 : {len(events)}")
    print()
    print(f"事件头 pid 命中      : {len(real & set(from_header))} / {len(real)}")
    print(f"载荷 ProcessID 命中  : {len(real & set(p for p in from_payload if p))} / {len(real)}")
    print()
    dup = [pid for pid, count in collections.Counter(from_header).items() if count > 1]
    print(f"事件头 pid 重复值    : {dup}")

    if events:
        first_fields = events[0].extra.get("fields") or {}
        print()
        print("ProcessStart 属性名:")
        print(f"    {sorted(first_fields.keys())}")
        print()
        print("前 3 条进程事件的关键字段:")
        for event in events[:3]:
            fields = event.extra.get("fields") or {}
            print(
                f"    pid={event.pid} "
                f"ppid={_get(fields, 'ParentProcessID', 'ParentProcessId')} "
                f"image={event.image}"
            )
            print(
                f"        cmdline={_get(fields, 'CommandLine')!r} "
                f"key={_get(fields, 'ProcessKey', 'UniqueProcessKey', 'Key')}"
            )

    print()
    if len(real & set(from_header)) >= len(real):
        print("结论: 事件头 pid 即事件主体，归一化层应直接采用它。")
    else:
        print("结论: 事件头 pid 未全部命中，需要进一步确认。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
