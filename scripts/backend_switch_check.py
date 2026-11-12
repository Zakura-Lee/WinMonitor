#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
后端开关覆盖验证（需管理员权限）

真正启动一次 MonitorService，确认 etw 模式下不会同时跑 legacy 采集器。
重点看 active_collectors 与线程名：不应出现 file/network/registry。

用法（管理员）:
    python scripts/backend_switch_check.py
    python scripts/backend_switch_check.py --backend legacy
"""

import argparse
import os
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import config
from core.monitor import MonitorService, plan_collectors


def main(argv=None):
    parser = argparse.ArgumentParser(description="后端开关覆盖验证")
    parser.add_argument("--backend", default=None, help="覆盖 MONITOR_BACKEND")
    parser.add_argument("--seconds", type=float, default=4.0)
    args = parser.parse_args(argv)

    if args.backend:
        config.MONITOR_BACKEND = args.backend

    print(f"[INFO] 配置后端 = {config.MONITOR_BACKEND!r}")
    print(f"[INFO] 计划采集器（按配置推演）= {plan_collectors(config.MONITOR_BACKEND, True)}")
    print()

    service = MonitorService()
    try:
        service.start()
        time.sleep(args.seconds)

        status = service.status()
        print("=" * 60)
        print(f"实际后端       : {status['backend']}")
        print(f"进程采集来源   : {status.get('etw_primary') or 'legacy process_mon'}")
        print(f"活动采集器     : {status.get('active_collectors')}")
        print(f"活动线程数     : {status['active_threads']}")

        names = sorted(t.name for t in threading.enumerate() if t is not threading.main_thread())
        print(f"线程明细       : {names[:12]}")

        active = set(status.get("active_collectors") or [])
        if status["backend"] == "etw":
            leftovers = active & {"file", "network", "registry"}
            if leftovers:
                print(f"\n[WARN] ETW 模式下仍在运行 legacy 采集器: {sorted(leftovers)}")
            else:
                print("\n结论: ETW 模式下未启动 file/network/registry 的 legacy 采集器。")
        else:
            print(f"\n结论: legacy 模式下装配了 {len(active)} 个采集器。")
    finally:
        service.stop()
        print("已停止。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
