#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络采集验证（需管理员权限）

验证 Sysmon 的 NetworkConnect 事件是否被正确捕获与分类。
除了外网目标，还会在本地起一个监听端口并连接它，保证至少有一条必然成功的 TCP 连接。

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


def _connect(host, port):
    try:
        sock = socket.create_connection((host, port), timeout=2)
        sock.close()
    except OSError:
        pass


def _local_probe():
    """本机起监听再连接，保证一定有一条成功的 TCP 连接。"""
    server = socket.socket()
    try:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        client = socket.create_connection(("127.0.0.1", port), timeout=2)
        client.close()
    except OSError:
        pass
    finally:
        server.close()


def probe():
    _local_probe()
    for host, port in TARGETS:
        threading.Thread(target=_connect, args=(host, port), daemon=True).start()


def main():
    service = MonitorService()
    started = service._start_etw_backend(service.process_data, service.alert_queue)
    print(f"[INFO] ETW 后端启动 = {started}   主提供者 = {service.etw_primary}")
    if not started:
        print(f"[INFO] 回退原因 = {service.etw_fallback_reason}")
        return 0

    print("[INFO] 采集 8 秒，期间建立本机连接 + 5 个外网连接 ...")
    threading.Thread(target=probe, daemon=True).start()
    time.sleep(8)

    events = service.network_events
    print()
    print("=" * 62)
    print(f"网络事件条数: {len(events)}")
    for entry in events[:8]:
        print(
            f"    [{entry['type']}] {entry['process_name'] or '-'} "
            f"{entry['local']} -> {entry['remote']} ({entry['reason']})"
        )

    collector = service.etw_collector
    if collector is not None:
        stats = collector.stats()
        print()
        print(f"采集统计: handled={stats.get('handled')}  解码异常={stats.get('decode_errors')}")
        counts = stats.get("event_counts") or {}
        if counts:
            print("按「提供者#事件ID」统计:")
            for key, count in counts.items():
                print(f"    {key}: {count}")
        else:
            print("按「提供者#事件ID」统计: 无（这一轮没有收到任何事件）")

    if service.process_table is not None:
        print()
        print(f"进程表统计: {service.process_table.stats()}")

    service._stop_etw_backend()

    print()
    if events:
        print("结论: 网络连接已被 Sysmon 捕获并完成分类。")
    else:
        print("结论: 没有捕获到网络事件，需要确认 Sysmon 是否在记录 NetworkConnect。")
    return 0 if events else 7


if __name__ == "__main__":
    sys.exit(main())
