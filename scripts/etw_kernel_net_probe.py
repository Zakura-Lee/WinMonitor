#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kernel-Network 字段与方向探针（需管理员权限）

回答两个问题:
    1. 内核网络事件是否带字节数（决定网络 ML 用哪套特征）
    2. 哪个 EventID 承载「发出」、哪个承载「接收」

方向判定用「两阶段对照」：先用局域网 IP 建本机服务器，
阶段 A 客户端单向发 1MB，阶段 B 服务器单向发 1MB，
分别统计各事件 ID 的字节增量——暴涨的那个 ID 就是该方向的载体。

用局域网 IP 而不是 127.0.0.1，避免被回环过滤掉。

用法（管理员）:
    python scripts/etw_kernel_net_probe.py --seconds 6
"""

import argparse
import collections
import os
import socket
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from collect.etw import api, providers
from collect.etw.consumer import EtwConsumer
from collect.etw.session import EtwSession

CHUNK = 65536
PAYLOAD = 1024 * 1024  # 每阶段 1MB


def detect_local_ip():
    """用一个不会真正发包的 UDP 连接拿到默认出口地址。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 53))
        return sock.getsockname()[0]
    except OSError:
        return socket.gethostbyname(socket.gethostname())
    finally:
        sock.close()


def _send_all(sock, total):
    chunk = b"C" * CHUNK
    sent = 0
    try:
        sock.settimeout(5)
        while sent < total:
            sent += sock.send(chunk[: min(CHUNK, total - sent)])
    except OSError:
        pass
    return sent


def _read_all(sock, total):
    received = 0
    try:
        sock.settimeout(5)
        while received < total:
            data = sock.recv(CHUNK)
            if not data:
                break
            received += len(data)
    except OSError:
        pass
    return received


def directional_test(per_id_bytes, local_ip):
    """两阶段对照，返回 {阶段: {事件ID: 字节增量}}。"""
    results = {}

    for phase in ("upload", "download"):
        before = dict(per_id_bytes)
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind((local_ip, 0))
            server.listen(1)
            port = server.getsockname()[1]

            client = socket.create_connection((local_ip, port), timeout=5)
            peer, _ = server.accept()

            if phase == "upload":
                # 客户端发，服务器读
                reader = threading.Thread(target=_read_all, args=(peer, PAYLOAD))
                reader.start()
                sent = _send_all(client, PAYLOAD)
                reader.join(timeout=10)
                print(f"  阶段 A(上传): 客户端发送 {sent} 字节")
            else:
                # 服务器发，客户端读
                sender = threading.Thread(target=_send_all, args=(peer, PAYLOAD))
                sender.start()
                received = _read_all(client, PAYLOAD)
                sender.join(timeout=10)
                print(f"  阶段 B(下载): 客户端接收 {received} 字节")

            time.sleep(0.6)
            after = dict(per_id_bytes)
            results[phase] = {
                event_id: after.get(event_id, 0) - before.get(event_id, 0)
                for event_id in set(before) | set(after)
            }
            try:
                client.close()
            except OSError:
                pass
            try:
                peer.close()
            except OSError:
                pass
        finally:
            server.close()

    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description="Kernel-Network 字段与方向探针")
    parser.add_argument("--seconds", type=float, default=6.0, help="收尾观察时间")
    args = parser.parse_args(argv)

    if not api.IsUserAnAdmin():
        print("[FAIL] 需要管理员权限")
        return 2

    per_id = collections.Counter()
    per_id_bytes = collections.Counter()
    records = []

    def sink(raw):
        fields = raw.decoded or {}
        size = int(fields.get("size") or 0)
        per_id[raw.event_id] += 1
        per_id_bytes[raw.event_id] += size
        if len(records) < 400:
            records.append(raw)

    session = EtwSession("WinMonitorKernelNet", buffer_size_kb=256, max_buffers=64)
    session.start()
    session.enable(providers.KERNEL_NETWORK)

    consumer = EtwConsumer("WinMonitorKernelNet", sink, decode_all=True)
    consumer.start()

    local_ip = detect_local_ip()
    print(f"[INFO] 本机地址 = {local_ip}")
    print("[INFO] 开始两阶段方向对照（各 1MB）...")
    time.sleep(1.0)

    results = directional_test(per_id_bytes, local_ip)

    print(f"[INFO] 收尾观察 {args.seconds}s ...")
    time.sleep(args.seconds)

    consumer.stop()
    session.stop()

    print()
    print("=" * 66)
    print(f"事件总数 : {sum(per_id.values())}   分布: {dict(per_id)}")
    print(f"消费者   : records={consumer.record_count} buffers={consumer.buffer_count} "
          f"errors={consumer.error_count}")

    print()
    print("阶段字节增量（单位: 字节）:")
    header = "    ID   " + "".join(f"{phase:>12}" for phase in ("upload", "download"))
    print(header)
    all_ids = sorted(set(results["upload"]) | set(results["download"]) | set(per_id))
    for event_id in all_ids:
        up = results["upload"].get(event_id, 0)
        down = results["download"].get(event_id, 0)
        if up == 0 and down == 0:
            continue
        print(f"    ID {event_id:>3} {up:>12} {down:>12}")

    # 得出方向结论
    up_best = max(results["upload"].items(), key=lambda kv: kv[1], default=(None, 0))
    down_best = max(results["download"].items(), key=lambda kv: kv[1], default=(None, 0))
    print()
    print(f"上传阶段字节最多的事件 ID: {up_best[0]}（{up_best[1]} 字节）")
    print(f"下载阶段字节最多的事件 ID: {down_best[0]}（{down_best[1]} 字节）")
    if up_best[0] is not None and down_best[0] is not None and up_best[0] != down_best[0]:
        print(f"结论: 发送 = ID {up_best[0]}，接收 = ID {down_best[0]}")
    elif up_best[0] == down_best[0]:
        print("结论: 两阶段落在同一个 ID 上，说明该 ID 不区分方向，需另找依据。")
    else:
        print("结论: 数据不足，无法判定方向。")

    # 字段样例
    print()
    print("字段样例（每种事件 ID 一条）:")
    seen = set()
    for raw in records:
        if raw.event_id in seen:
            continue
        seen.add(raw.event_id)
        fields = raw.decoded or {}
        if not fields:
            continue
        print(f"    --- EventID {raw.event_id} ---")
        for name in sorted(fields):
            print(f"        {name:26s} = {fields[name]!r}")
        if len(seen) >= 4:
            break

    return 0


if __name__ == "__main__":
    sys.exit(main())
