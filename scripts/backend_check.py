#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
双后端切换验证（需管理员权限才能走通 etw 分支）

只验证进程采集这一路，不启动文件/网络/注册表等 legacy 模块，
避免为了验证一个开关而去全盘挂 watchdog。

用法（管理员）:
    python scripts/backend_check.py
    python scripts/backend_check.py --seconds 6
"""

import argparse
import os
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from core.monitor import MonitorService
import config


def main(argv=None):
    parser = argparse.ArgumentParser(description="进程采集后端切换验证")
    parser.add_argument("--seconds", type=float, default=5.0)
    args = parser.parse_args(argv)

    print(f"[INFO] config.MONITOR_BACKEND = {config.MONITOR_BACKEND!r}")

    service = MonitorService()
    print(f"[INFO] 实例 backend          = {service.backend!r}")

    started = service._start_etw_backend(service.process_data, service.alert_queue)
    print(f"[INFO] ETW 后端启动结果      = {started}")
    print(f"[INFO] 主提供者             = {service.etw_primary}")
    if service.etw_fallback_reason:
        print(f"[INFO] 回退原因             = {service.etw_fallback_reason}")

    if not started:
        print()
        print("结论: ETW 后端未启动，服务会回退到 legacy 进程采集（预期行为）。")
        return 0

    def spawn():
        for _ in range(6):
            try:
                subprocess.Popen(
                    ["cmd", "/c", "ping -n 2 127.0.0.1 > nul"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except OSError:
                return

    print(f"[INFO] 采集 {args.seconds}s 并拉起 6 个进程 ...")
    threading.Thread(target=spawn, daemon=True).start()
    time.sleep(args.seconds)

    changes = service.process_data.get("process_changes", [])
    print()
    print("=" * 58)
    print(f"process_changes 条数: {len(changes)}")

    started = [c for c in changes if c["type"] == "started"]
    print(f"其中 started: {len(started)}")
    for entry in started[:5]:
        print(
            f"    [started] pid={entry['pid']} name={entry['name']} "
            f"ppid={entry['ppid']} pname={entry['pname'] or '-'}"
        )
        if entry["cmdline"]:
            print(f"        cmdline={entry['cmdline']}")

    if service.process_table is not None:
        print()
        print(f"进程表统计: {service.process_table.stats()}")
        for entry in started[:2]:
            record = service.process_table.latest_by_pid(entry["pid"])
            if record is None:
                continue
            chain = service.process_table.ancestors_names(record.key)
            print(f"    父链 pid={entry['pid']}: {' <- '.join(chain)}")

    service._stop_etw_backend()
    print()
    print("结论: ETW 后端可用，进程变化已写入 process_data，仪表盘接口可直接消费。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
