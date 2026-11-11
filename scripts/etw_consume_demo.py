#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
P3 采集层冒烟脚本（需管理员权限）

验证 EtwSession + EtwConsumer + EventBus + normalize 这条正式链路。
默认会拉起一批短命进程作为负载，否则静置机器上进程事件很少。

用法（管理员 PowerShell）:
    python scripts/etw_consume_demo.py --seconds 6
    python scripts/etw_consume_demo.py --seconds 10 --workload 30
"""

import argparse
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


def _spawn_workload(count):
    """拉起若干短命进程，确保统计窗口内出现进程创建事件。"""

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


def main(argv=None):
    parser = argparse.ArgumentParser(description="ETW 采集层冒烟")
    parser.add_argument("--seconds", type=float, default=6.0)
    parser.add_argument("--session", default="WinMonitorP3")
    parser.add_argument("--workload", type=int, default=20, help="采集期间拉起的短命进程数")
    args = parser.parse_args(argv)

    if not api.IsUserAnAdmin():
        print("[FAIL] 需要管理员权限才能启用内核 ETW 提供者。")
        return 2

    counter = collections.Counter()
    samples = []

    def on_event(event):
        counter[event.event_id] += 1
        if event.event_id == providers.EVENT_PROCESS_START and len(samples) < 5:
            samples.append(event)

    collector = EtwCollector(session_name=args.session, on_event=on_event)
    print(f"[INFO] 会话: {args.session}")
    print(f"[INFO] 提供者: {[s.name for s in collector.provider_specs]}")
    print(f"[INFO] 采集 {args.seconds}s，负载 {args.workload} 个进程 ...")
    print()

    try:
        collector.start()
        _spawn_workload(args.workload)
        time.sleep(args.seconds)
    finally:
        collector.stop()

    stats = collector.stats()
    consumer = stats.get("consumer") or {}

    print("=" * 58)
    print("结果")
    print("=" * 58)
    print(f"已处理事件 : {stats['handled']}")
    print(f"解码异常   : {stats['decode_errors']}")
    print(f"原始记录   : {consumer.get('records')}")
    print(f"缓冲回调   : {consumer.get('buffers')}")
    print(f"回调异常   : {consumer.get('errors')}")
    print(f"ProcessTrace 返回 : {consumer.get('process_rc')}")
    bus = stats["bus"]
    print(f"总线       : 入队 {bus['put']} / 出队 {bus['get']} / 丢弃 {bus['drop']} / 剩余 {bus['qsize']}")

    if counter:
        print()
        print("事件分布:")
        for event_id, count in counter.most_common(10):
            name = providers.EVENT_ID_NAMES.get(event_id, "")
            print(f"    ID {event_id:<3} {name:<14} {count}")

    if samples:
        print()
        print("进程创建样本:")
        for index, event in enumerate(samples, 1):
            print(f"[{index}] pid={event.pid} image={event.image}")
            if event.cmdline:
                print(f"      cmdline={event.cmdline}")

    if stats["handled"] == 0:
        print()
        print("[WARN] 没有处理到任何事件，请检查权限与提供者关键字。")
        return 7
    return 0


if __name__ == "__main__":
    sys.exit(main())
