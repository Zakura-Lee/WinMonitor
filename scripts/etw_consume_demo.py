#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
P3 采集层冒烟脚本（需管理员权限）

验证 EtwSession + EtwConsumer + EventBus + normalize 这条链路，
与 spike 的区别是：这里跑的是正式代码路径，不含任何诊断代码。

用法（管理员 PowerShell）:
    python scripts/etw_consume_demo.py --seconds 6
"""

import argparse
import collections
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from collect.collector import EtwCollector
from collect.etw import api, providers


def main(argv=None):
    parser = argparse.ArgumentParser(description="ETW 采集层冒烟")
    parser.add_argument("--seconds", type=float, default=6.0)
    parser.add_argument("--session", default="WinMonitorP3")
    args = parser.parse_args(argv)

    if not api.IsUserAnAdmin():
        print("[FAIL] 需要管理员权限才能启用内核 ETW 提供者。")
        return 2

    counter = collections.Counter()
    samples = []

    def on_event(event):
        counter[event.event_id] += 1
        if len(samples) < 5 and event.event_id == providers.EVENT_PROCESS_START:
            samples.append(event)
        elif len(samples) < 5 and not samples:
            samples.append(event)

    collector = EtwCollector(session_name=args.session, on_event=on_event)
    print(f"[INFO] 会话: {args.session}")
    print(f"[INFO] 提供者: {[s.name for s in collector.provider_specs]}")
    print(f"[INFO] 采集 {args.seconds}s ...")
    print()

    try:
        collector.start()
        time.sleep(args.seconds)
    finally:
        collector.stop()

    stats = collector.stats()
    print("=" * 58)
    print("结果")
    print("=" * 58)
    print(f"已处理事件 : {stats['handled']}")
    print(f"解码异常   : {stats['decode_errors']}")
    consumer = stats.get("consumer") or {}
    print(f"原始记录   : {consumer.get('records')}")
    print(f"缓冲回调   : {consumer.get('buffers')}")
    print(f"回调异常   : {consumer.get('errors')}")
    print(f"总线统计   : {stats['bus']}")

    if counter:
        print()
        print("事件分布:")
        for event_id, count in counter.most_common(10):
            name = providers.EVENT_ID_NAMES.get(event_id, "")
            print(f"    ID {event_id:<3} {name:<14} {count}")

    if samples:
        print()
        print("样本:")
        for index, event in enumerate(samples, 1):
            print(f"[{index}] id={event.event_id} pid={event.pid} image={event.image}")
            if event.cmdline:
                print(f"      cmdline={event.cmdline}")

    if stats["handled"] == 0:
        print()
        print("[WARN] 没有处理到任何事件，请检查权限与提供者关键字。")
        return 7
    return 0


if __name__ == "__main__":
    sys.exit(main())
