#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sysmon 接入验证（需管理员权限）

重点看三件事:
    1. ProcessCreate 能不能解出 CommandLine；
    2. ProcessGuid / ParentProcessGuid 能否用于进程树关联；
    3. User、IntegrityLevel 等安全字段是否可取。

用法（管理员）:
    python scripts/etw_sysmon_check.py
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

    by_provider = collections.Counter()
    creates = []

    def on_event(event):
        by_provider[event.provider or "unknown"] += 1
        if event.provider == providers.SYSMON.name and event.event_id == 1:
            creates.append(event)

    collector = EtwCollector(session_name="WinMonitorSysmon", on_event=on_event)

    print("[INFO] 采集 6 秒，同时拉起一条特征明显的命令行 ...")
    try:
        collector.start()
        threading.Thread(
            target=lambda: subprocess.Popen(
                ["cmd", "/c", "echo sysmon-probe-marker && ping -n 2 127.0.0.1 > nul"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ),
            daemon=True,
        ).start()
        time.sleep(6)
    finally:
        collector.stop()

    stats = collector.stats()
    print()
    print("=" * 62)
    print(f"已处理事件 : {stats['handled']}   解码异常: {stats['decode_errors']}")
    print(f"已跳过提供者: {collector.disabled_providers or '无'}")
    print(f"按提供者统计: {dict(by_provider)}")
    print(f"ProcessCreate 条数: {len(creates)}")

    if creates:
        print()
        print("前 3 条 ProcessCreate:")
        for event in creates[:3]:
            fields = event.extra.get("fields") or {}
            print(f"    pid={event.pid} ppid={event.ppid}")
            print(f"        image   = {event.image}")
            print(f"        cmdline = {event.cmdline!r}")
            print(f"        guid    = {event.process_guid}")
            print(f"        pguid   = {event.parent_guid}")
            print(f"        user    = {_get(fields, 'User')}")
            print(f"        integrity = {_get(fields, 'IntegrityLevel')}")
            print(f"        hashes  = {_get(fields, 'Hashes')}")

        marker = [e for e in creates if "sysmon-probe-marker" in (e.cmdline or "")]
        print()
        if marker:
            print("结论: 成功抓到命令行标记 sysmon-probe-marker")
        else:
            print("结论: 没抓到标记命令行，需检查 CommandLine 字段映射")

    print()
    return 0 if creates else 7


if __name__ == "__main__":
    sys.exit(main())
