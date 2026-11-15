#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kernel-Network 字段探针（需管理员权限）

路线 A 的前提是「内核网络事件能提供 CICIDS 那类流特征（字节数、包长）」。
本脚本订阅 Microsoft-Windows-Kernel-Network，对所有事件做逐字段解码，
把真实字段名和值打印出来，用来判断这个前提是否成立。

用法（管理员）:
    python scripts/etw_kernel_net_probe.py --seconds 8
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

TARGETS = [("8.8.8.8", 53), ("223.5.5.5", 443), ("1.1.1.1", 443)]


def _traffic():
    for host, port in TARGETS:
        threading.Thread(
            target=lambda h=host, p=port: _connect(h, p), daemon=True
        ).start()
    _bulk_public_transfer()


def _connect(host, port):
    try:
        sock = socket.create_connection((host, port), timeout=2)
        sock.sendall(b"x" * 64)
        sock.close()
    except OSError:
        pass


def _bulk_public_transfer():
    """向公网单向发送 4MB，用于判断哪个 EventID 承载「发出」字节。

    回环测试分不清方向（两端都在本机），必须走外网：
    发出的字节会集中落在「发送」那一个事件 ID 上。
    """
    data = b"B" * 65536
    for host, port in (("1.1.1.1", 443), ("223.5.5.5", 443)):
        try:
            sock = socket.create_connection((host, port), timeout=3)
        except OSError as exc:
            print(f"  {host}:{port} 连接失败: {exc}")
            continue
        sent = 0
        try:
            sock.settimeout(2)
            for _ in range(64):  # 最多 4MB
                sent += sock.send(data)
        except OSError:
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass
        print(f"  {host}:{port} 单向发送 {sent} 字节")
        if sent > 0:
            return


def main(argv=None):
    parser = argparse.ArgumentParser(description="Kernel-Network 字段探针")
    parser.add_argument("--seconds", type=float, default=8.0)
    args = parser.parse_args(argv)

    if not api.IsUserAnAdmin():
        print("[FAIL] 需要管理员权限")
        return 2

    records = []
    per_id = collections.Counter()

    def sink(raw):
        per_id[raw.event_id] += 1
        if len(records) < 200:
            records.append(raw)

    session = EtwSession("WinMonitorKernelNet", buffer_size_kb=256, max_buffers=64)
    session.start()
    session.enable(providers.KERNEL_NETWORK)

    consumer = EtwConsumer("WinMonitorKernelNet", sink, decode_all=True)
    consumer.start()

    print(f"[INFO] 订阅 {providers.KERNEL_NETWORK.name}，采集 {args.seconds}s 并制造流量 ...")
    threading.Thread(target=_traffic, daemon=True).start()
    time.sleep(args.seconds)

    consumer.stop()
    session.stop()

    print()
    print("=" * 62)
    print(f"事件总数 : {sum(per_id.values())}")
    print(f"事件分布 : {dict(per_id)}")
    print(f"消费者   : records={consumer.record_count} buffers={consumer.buffer_count} "
          f"errors={consumer.error_count}")

    # 按事件 ID 各取一条「非回环」事件，打印全部字段
    # 回环事件的地址两端都是 127.0.0.1，看不出方向与端口语义
    LOOPBACK = 16777343  # 0x0100007F
    seen = set()
    printed = 0
    for raw in records:
        fields = raw.decoded or {}
        saddr, daddr = fields.get("saddr"), fields.get("daddr")
        if saddr == LOOPBACK or daddr == LOOPBACK:
            continue
        if raw.event_id in seen:
            continue
        seen.add(raw.event_id)
        printed += 1
        print()
        print(f"--- EventID {raw.event_id}  载荷 {len(raw.payload)} 字节 ---")
        for name in sorted(fields):
            print(f"    {name:26s} = {fields[name]!r}")
        if printed >= 6:
            break

    if printed == 0:
        print()
        print("(窗口内没有捕获到非回环事件——请确保有外网连接)")

    print()
    if not records:
        print("结论: 没有收到任何 Kernel-Network 事件。")
        return 7

    all_fields = set()
    for raw in records:
        all_fields.update((raw.decoded or {}).keys())

    # 每个事件 ID 的字节总量：哪个 ID 拿到了 4MB，哪个就是「发出」方向
    print()
    print("按事件 ID 统计字节量:")

    # 出现次数最多的 saddr 基本就是本机地址，用它判断「本机在前」的比例
    saddr_counter = collections.Counter(
        (raw.decoded or {}).get("saddr") for raw in records
    )
    common_saddr = saddr_counter.most_common(1)[0][0] if saddr_counter else None

    for event_id in sorted(per_id):
        related = [raw for raw in records if raw.event_id == event_id]
        total_size = sum(int((raw.decoded or {}).get("size") or 0) for raw in related)
        local_first = sum(
            1 for raw in related if (raw.decoded or {}).get("saddr") == common_saddr
        )
        print(
            f"    ID {event_id:>3}  事件 {per_id[event_id]:>4}  "
            f"字节 {total_size:>10}  本机在前 {local_first}/{len(related)}"
        )

    hints = [n for n in all_fields if any(k in n.lower() for k in ("size", "byte", "length", "count"))]
    print(f"全部出现过的字段名: {sorted(all_fields)}")
    print()
    if hints:
        print(f"结论: 存在可能表示流量大小的字段 -> {sorted(hints)}")
        print("      路线 A 有希望，可基于这些字段构造流特征。")
    else:
        print("结论: 未发现字节数/包长类字段，路线 A 可能不成立。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
