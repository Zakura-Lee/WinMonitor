#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P9b 特征对齐测试"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from detect.features import (
    DATASET_COLUMN_MAP,
    FEATURE_NAMES,
    flow_to_features,
    vector,
)

_SAMPLE = {
    "src": "10.0.0.5",
    "sport": 51000,
    "dst": "8.8.8.8",
    "dport": 53,
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


def test_feature_names_stable():
    # 顺序即模型输入顺序，改动必须同步版本号
    assert FEATURE_NAMES[:4] == ("spkts", "dpkts", "sbytes", "dbytes")
    assert "dur" in FEATURE_NAMES
    assert len(FEATURE_NAMES) == len(set(FEATURE_NAMES))


def test_flow_to_features_values():
    features = flow_to_features(_SAMPLE)
    assert features["sbytes"] == 258
    assert abs(features["dur"] - 0.121478) < 1e-9
    # sload = sbytes * 8 / dur_seconds
    assert abs(features["sload"] - 258 * 8 / 0.121478) < 1.0
    assert features["proto_tcp"] == 1.0


def test_zero_duration_no_division_error():
    flow = dict(_SAMPLE, dur_ms=0)
    features = flow_to_features(flow)
    assert features["sload"] == 0.0
    assert features["dload"] == 0.0


def test_nan_and_missing_fields():
    flow = {"spkts": "abc", "dur_ms": None, "sbytes": float("nan")}
    features = flow_to_features(flow)
    assert features["spkts"] == 0.0
    assert features["sbytes"] == 0.0
    assert features["dur"] == 0.0


def test_udp_detected():
    flow = dict(_SAMPLE, proto="udp")
    assert flow_to_features(flow)["proto_tcp"] == 0.0


def test_vector_order_matches_names():
    values = vector(_SAMPLE)
    assert len(values) == len(FEATURE_NAMES)
    features = flow_to_features(_SAMPLE)
    for name, value in zip(FEATURE_NAMES, values):
        assert value == features[name]


def test_dataset_map_covers_direct_features():
    for name in DATASET_COLUMN_MAP:
        assert name in FEATURE_NAMES, f"{name} 应属于我们的特征"
    # 数据集列名与我们的名字不一致的两项
    assert DATASET_COLUMN_MAP["sintpkt"] == "sinpkt"
    assert DATASET_COLUMN_MAP["dintpkt"] == "dinpkt"


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
