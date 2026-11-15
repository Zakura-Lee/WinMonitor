#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P9b 纯标准库推理测试"""

import gzip
import json
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from detect.netmodel import NetModel, load_model, score_flow

FEATURES = ["a", "b"]


def _tiny_payload():
    # 两棵树：树1 按 a<=10 划分，树2 按 b<=5 划分
    tree1 = [
        [0, 10.0, 1, 2, -1.0],   # 根: a <= 10 -> 左
        [-1, 0.0, -1, -1, 0.0],  # 叶: 概率 0
        [-1, 0.0, -1, -1, 1.0],  # 叶: 概率 1
    ]
    tree2 = [
        [1, 5.0, 1, 2, -1.0],
        [-1, 0.0, -1, -1, 1.0],
        [-1, 0.0, -1, -1, 0.0],
    ]
    return {"version": 2, "features": FEATURES, "n_trees": 2, "trees": [tree1, tree2]}


def test_prediction_averages_trees():
    model = NetModel(FEATURES, _tiny_payload()["trees"])
    # a=1(左,0) b=1(左,1) -> (0+1)/2 = 0.5
    assert abs(model.predict_proba([1.0, 1.0]) - 0.5) < 1e-9
    # a=20(右,1) b=1(左,1) -> 1.0
    assert abs(model.predict_proba([20.0, 1.0]) - 1.0) < 1e-9
    # a=1 b=20 -> (0+0)/2 = 0
    assert abs(model.predict_proba([1.0, 20.0]) - 0.0) < 1e-9


def test_threshold_boundary_goes_left():
    model = NetModel(FEATURES, _tiny_payload()["trees"])
    # a 正好等于阈值应走左分支（概率 0）
    assert abs(model.predict_proba([10.0, 20.0]) - 0.0) < 1e-9


def test_predict_uses_threshold():
    model = NetModel(FEATURES, _tiny_payload()["trees"])
    assert model.predict([1.0, 1.0], threshold=0.5) == 1
    assert model.predict([1.0, 1.0], threshold=0.6) == 0


def test_dimension_mismatch_raises():
    model = NetModel(FEATURES, _tiny_payload()["trees"])
    try:
        model.predict_proba([1.0])
    except ValueError:
        return
    raise AssertionError("维度不匹配应抛 ValueError")


def test_load_from_gzip_file():
    directory = tempfile.mkdtemp(prefix="wm_model_")
    try:
        path = os.path.join(directory, "m.json.gz")
        with gzip.open(path, "wt", encoding="utf-8") as handle:
            json.dump(_tiny_payload(), handle)
        model = load_model(path)
        assert model is not None
        assert model.n_trees == 2
        assert len(model.features) == 2
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def test_missing_model_returns_none():
    assert load_model(os.path.join(tempfile.gettempdir(), "definitely_absent.gz")) is None


def test_score_flow_without_model():
    """模型文件不存在时返回 None，调用方应视为「模型不可用」而不是报错。"""
    result = score_flow({"spkts": 1}, model=None)
    if result is None:
        return
    # 若本机已训练出模型，则结果必须包含可用的概率
    assert 0.0 <= result["probability"] <= 1.0


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
