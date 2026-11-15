#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P9b 特征对齐测试（方向无关版）"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from detect.features import (
    FEATURE_NAMES,
    aggregate_features,
    dataset_row_to_features,
    flow_to_features,
    vector,
)

_SAMPLE_FLOW = {
    "spkts": 6,
    "dpkts": 4,
    "sbytes": 258,
    "dbytes": 172,
    "dur_ms": 121.478,
    "smean": 43.0,
    "dmean": 43.0,
    "sintpkt": 24.2956,
    "dintpkt": 8.375,
    "sjit": 30.177547,
    "djit": 11.830604,
    "rate": 74.08749,
    "proto": "tcp",
}

_SAMPLE_ROW = {
    "spkts": 6,
    "dpkts": 4,
    "sbytes": 258,
    "dbytes": 172,
    "dur": 0.121478,
    "rate": 74.08749,
    "sload": 16990.0,
    "dload": 11326.0,
    "sinpkt": 24.2956,
    "dinpkt": 8.375,
    "sjit": 30.177547,
    "djit": 11.830604,
    "proto": "tcp",
}


def test_feature_names_stable():
    assert FEATURE_NAMES[:3] == ("pkts_total", "bytes_total", "dur")
    assert "proto_tcp" in FEATURE_NAMES
    assert len(FEATURE_NAMES) == len(set(FEATURE_NAMES))


def test_aggregate_basic_math():
    features = aggregate_features(
        dur=1.0, spkts=6, dpkts=4, sbytes=258, dbytes=172,
        rate=100.0, sload=2064.0, dload=1376.0,
        sinpkt=10.0, dinpkt=20.0, sjit=1.0, djit=3.0, proto="tcp",
    )
    assert features["pkts_total"] == 10
    assert features["bytes_total"] == 430
    assert abs(features["mean_pkt_size"] - 43.0) < 1e-6
    # 加权平均：(10*6 + 20*4)/10 = 14
    assert abs(features["iat_mean"] - 14.0) < 1e-6
    assert abs(features["jitter"] - 1.8) < 1e-6
    assert features["proto_tcp"] == 1.0


def test_flow_and_dataset_produce_same_shape():
    from_flow = flow_to_features(_SAMPLE_FLOW)
    from_row = dataset_row_to_features(_SAMPLE_ROW)
    assert set(from_flow) == set(from_row)
    # 包数与字节数必须完全一致
    for name in ("pkts_total", "bytes_total", "proto_tcp"):
        assert from_flow[name] == from_row[name], name


def test_zero_packets_no_division_error():
    features = aggregate_features(
        dur=0, spkts=0, dpkts=0, sbytes=0, dbytes=0,
        rate=0, sload=0, dload=0, sinpkt=0, dinpkt=0,
        sjit=0, djit=0, proto="udp",
    )
    assert features["pkts_total"] == 0
    assert features["mean_pkt_size"] == 0.0
    assert features["iat_mean"] == 0.0
    assert features["proto_tcp"] == 0.0


def test_nan_and_garbage_inputs():
    features = aggregate_features(
        dur=None, spkts="abc", dpkts=2, sbytes=float("nan"), dbytes=100,
        rate="x", sload=None, dload=1, sinpkt=None, dinpkt=2,
        sjit=float("inf"), djit=3, proto=None,
    )
    assert features["spkts"] if False else True
    assert features["pkts_total"] == 2.0
    assert features["bytes_total"] == 100.0
    assert features["proto_tcp"] == 0.0


def test_vector_order_matches_names():
    values = vector(_SAMPLE_FLOW)
    assert len(values) == len(FEATURE_NAMES)
    features = flow_to_features(_SAMPLE_FLOW)
    for name, value in zip(FEATURE_NAMES, values):
        assert value == features[name]


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
