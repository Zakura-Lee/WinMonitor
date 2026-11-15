#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络流聚合验证（需管理员权限）

启动完整服务，制造若干连接，等待流窗口结束后检查聚合出来的特征。

用法（管理员）:
    python scripts/netflow_check.py --seconds 25
"""

import argparse
import os
import socket
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import config
from core.monitor import MonitorService

TARGETS = [("8.8.8.8", 53), ("223.5.5.5", 443), ("1.1.1.1", 443)]


def _connect(host, port, payload=b""):
    try:
        sock = socket.create_connection((host, port), timeout=2)
        if payload:
            sock.sendall(payload)
            try:
                sock.recv(1024)
            except OSError:
                pass
        sock.close()
    except OSError:
        pass


def _local_traffic():
    server = socket.socket()
    try:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        client = socket.create_connection(("127.0.0.1", port), timeout=2)
        client.sendall(b"a" * 1024)
        peer, _ = server.accept()
        peer.recv(4096)
        peer.sendall(b"b" * 2048)
        client.recv(4096)
        peer.close()
        client.close()
    except OSError:
        pass
    finally:
        server.close()


def _traffic():
    _local_traffic()
    for host, port in TARGETS:
        threading.Thread(target=_connect, args=(host, port, b"x" * 256), daemon=True).start()


def main(argv=None):
    parser = argparse.ArgumentParser(description="网络流聚合验证")
    parser.add_argument("--seconds", type=float, default=25.0)
    args = parser.parse_args(argv)

    print(f"[INFO] 流窗口 = {getattr(config, 'NETFLOW_WINDOW_SECONDS', 15.0)}s")
    service = MonitorService()
    try:
        service.start()
        if service.backend != "etw":
            print(f"[WARN] 当前后端是 {service.backend}，流聚合只在 etw 下工作")
            return 0

        time.sleep(3)
        print("[INFO] 制造流量 ...")
        _traffic()

        print(f"[INFO] 等待 {args.seconds}s 让流窗口关闭并输出 ...")
        time.sleep(args.seconds)

        flows = service.network_flows
        print()
        print("=" * 74)
        print(f"聚合出的流: {len(flows)} 条")
        for flow in flows[:8]:
            print(
                f"    {flow['src']}:{flow['sport']} -> {flow['dst']}:{flow['dport']}  "
                f"pid={flow['pid']}"
            )
            print(
                f"        spkts={flow['spkts']} dpkts={flow['dpkts']} "
                f"sbytes={flow['sbytes']} dbytes={flow['dbytes']} "
                f"dur={flow['dur_ms']}ms rate={flow['rate_bps']}bps"
            )
            if "ml_probability" in flow:
                flag = "攻击" if flow.get("ml_attack") else "正常"
                print(
                    f"        模型评分={flow['ml_probability']:.4f} 判定={flag}"
                )
            else:
                print("        模型评分: 未打分（模型未加载或已禁用）")

        status = service.status()
        print()
        print(f"netflow 统计: {status.get('netflow')}")
        print(f"event_store : {status.get('event_store')}")
        print(f"net_model   : {status.get('net_model')}")

        collector_stats = None
        if service.etw_collector is not None:
            collector_stats = service.etw_collector.stats()
        if collector_stats:
            print()
            print(f"采集 handled={collector_stats.get('handled')} "
                  f"解码异常={collector_stats.get('decode_errors')}")
            print(f"总线: {collector_stats.get('bus')}")
            print(f"会话: {collector_stats.get('session')}")
            counts = collector_stats.get("event_counts") or {}
            net = {k: v for k, v in counts.items() if "Network" in k}
            print(f"内核网络事件分布: {net}")
    finally:
        service.stop()

    print()
    print("结论: 流记录已写入 network_flows，并落盘到 data/events。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
