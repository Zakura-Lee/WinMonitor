#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P9b 网络流聚合测试"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from collect.netflow import FlowAggregator, ipv4_from_int

_LOCAL = "10.0.0.5"
_REMOTE = "8.8.8.8"


def test_ipv4_from_int():
    # 127.0.0.1 的小端整数表示
    assert ipv4_from_int(16777343) == "127.0.0.1"
    assert ipv4_from_int(0x08080808) == "8.8.8.8"
    assert ipv4_from_int(0) == "0.0.0.0"
    assert ipv4_from_int(None) == ""


def test_flow_merges_both_directions():
    agg = FlowAggregator(window_seconds=10, local_ips=[_LOCAL])
    records = []
    agg.on_flow = records.append

    # 本机发起，发 3 个包，模拟事件时间递增
    for index in range(3):
        agg.add(
            ts_ns=(index + 1) * 1_000_000,
            src=_LOCAL, sport=51000, dst=_REMOTE, dport=443,
            size=100, pid=999,
        )
    # 对端回 2 个包（方向相反，应并入同一条流）
    for index in range(2):
        agg.add(
            ts_ns=(index + 1) * 2_000_000,
            src=_REMOTE, sport=443, dst=_LOCAL, dport=51000,
            size=200, pid=999,
        )

    agg.flush(now_ns=10 ** 12)  # 远超窗口，触发输出
    assert len(records) == 1, records
    flow = records[0]
    assert flow["spkts"] == 3
    assert flow["dpkts"] == 2
    assert flow["sbytes"] == 300
    assert flow["dbytes"] == 400
    assert {flow["src"], flow["dst"]} == {_LOCAL, _REMOTE}
    assert flow["kind"] == "flow"


def test_flow_close_emits_immediately():
    agg = FlowAggregator(window_seconds=60, local_ips=[_LOCAL])
    records = []
    agg.on_flow = records.append

    agg.add(ts_ns=1_000_000, src=_LOCAL, sport=50001, dst=_REMOTE, dport=80, size=50, pid=1)
    agg.add(
        ts_ns=2_000_000, src=_LOCAL, sport=50001, dst=_REMOTE, dport=80,
        size=0, pid=1, close=True,
    )
    assert len(records) == 1
    assert records[0]["closed_by"] == "closed"
    assert agg.stats()["active_flows"] == 0


def test_separate_flows_are_distinct():
    agg = FlowAggregator(window_seconds=60, local_ips=[_LOCAL])
    records = []
    agg.on_flow = records.append

    agg.add(ts_ns=1_000_000, src=_LOCAL, sport=50001, dst=_REMOTE, dport=80, size=10)
    agg.add(ts_ns=1_000_000, src=_LOCAL, sport=50002, dst=_REMOTE, dport=80, size=10)
    agg.flush(now_ns=10 ** 12)
    assert len(records) == 2


def test_eviction_caps_memory():
    agg = FlowAggregator(window_seconds=600, max_flows=3, local_ips=[_LOCAL])
    records = []
    agg.on_flow = records.append

    for index in range(6):
        agg.add(ts_ns=index * 1000, src=_LOCAL, sport=50000 + index, dst=_REMOTE, dport=80, size=1)
    stats = agg.stats()
    assert stats["active_flows"] <= 3
    assert stats["evicted"] >= 3
    assert len(records) >= 3


def test_idle_flow_not_emitted_early():
    agg = FlowAggregator(window_seconds=60, local_ips=[_LOCAL])
    records = []
    agg.on_flow = records.append

    agg.add(ts_ns=5_000_000_000, src=_LOCAL, sport=50001, dst=_REMOTE, dport=80, size=10)
    emitted = agg.flush(now_ns=5_100_000_000)  # 只过了 0.1 秒
    assert emitted == 0
    assert records == []


def test_missing_address_filtered():
    agg = FlowAggregator()
    agg.add(ts_ns=1, src="", sport=0, dst=_REMOTE, dport=80, size=1)
    assert agg.stats()["filtered"] == 1


if __name__ == "__main__":
    failures = 0
    for name in sorted(n for n in dir() if n.startswith("test_")):
        fn = globals()[name]
        try:
            fn()
            print(f"PASS  {name}")
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print(f"FAIL  {name}: {type(exc).__name__}: {exc}")
    print()
    print("全部通过" if failures == 0 else f"{failures} 个测试失败")
    sys.exit(1 if failures else 0)
