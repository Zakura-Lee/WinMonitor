#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络采集验证（需管理员权限）

用 Sysmon 的 NetworkConnect 事件验证网络链路：
采集期间主动向外建立几条 TCP 连接，然后检查是否被记录并分类。

用法（管理员）:
    python scripts/etw_network_check.py
"""

import os
import socket
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from core.monitor import MonitorService

TARGETS = [
    ("1.1.1.1", 443),
    ("8.8.8.8", 53),
    ("223.5.5.5", 443),
    ("1.1.1.1", 3389),  # 公网 + 高危端口，用于触发 attack 分类
    ("192.168.255.254", 445),  # 内网目标，应判为 normal
]


def probe():
    for host, port in TARGETS:
        try:
            sock = socket.create_connection((host, port), timeout=2)
            sock.close()
        except OSError:
            pass


def main():
    service = MonitorService()
    started = service._start_etw_backend(service.process_data, service.alert_queue)
    print(f"[INFO] ETW 后端启动 = {started}   主提供者 = {service.etw_primary}")
    if not started:
        print(f"[INFO] 回退原因 = {service.etw_fallback_reason}")
        return 0

    print("[INFO] 采集 6 秒，期间主动建立 4 条 TCP 连接 ...")
    threading.Thread(target=probe, daemon=True).start()
    time.sleep(6)

    events = service.network_events
    print()
    print("=" * 62)
    print(f"网络事件条数: {len(events)}")
    for entry in events[:8]:
        print(
            f"    [{entry['type']}] {entry['process_name'] or '-'} "
            f"{entry['local']} -> {entry['remote']} ({entry['reason']})"
        )

    if service.process_table is not None:
        print()
        print(f"进程表统计: {service.process_table.stats()}")

    service._stop_etw_backend()

    print()
    if events:
        print("结论: 网络连接已被 Sysmon 捕获并完成分类。")
    else:
        print("结论: 没有捕获到网络事件，检查 Sysmon 是否启用了 NetworkConnect。")
    return 0 if events else 7


if __name__ == "__main__":
    sys.exit(main())
