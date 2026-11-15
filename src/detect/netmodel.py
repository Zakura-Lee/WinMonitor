#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络入侵模型的纯标准库推理

模型由 scripts/export_model.py 导出为 gzip JSON，节点格式：
    [feature_index, threshold, left, right, probability]
    feature_index = -1 表示叶节点

推理规则与 sklearn 的随机森林一致：逐树走到叶子取概率，再取平均。
不依赖 numpy / sklearn，因此可以跑在 Python 3.15 的应用环境里。
"""

import gzip
import json
import os
import struct
import threading


def _f32(value):
    """把数值压成 float32 再比较。

    sklearn 在预测时会把输入转成 float32，阈值也是 float32 精度，
    如果这里用 float64 直接比，边界样本会走错分支（实测偏差可达 0.04）。
    """
    return struct.unpack("f", struct.pack("f", float(value)))[0]

DEFAULT_MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data",
    "models",
    "net_model.json.gz",
)


class NetModel:
    def __init__(self, features, trees):
        self.features = list(features)
        self.trees = trees
        self.n_trees = len(trees) or 1

    @property
    def size(self):
        return self.n_trees

    def _tree_probability(self, nodes, vector):
        index = 0
        while True:
            node = nodes[index]
            feature = node[0]
            if feature < 0:
                return node[4]
            index = node[2] if vector[feature] <= node[1] else node[3]

    def predict_proba(self, vector):
        """返回攻击概率，0~1。"""
        if len(vector) != len(self.features):
            raise ValueError(
                f"特征维度不匹配: 期望 {len(self.features)}，收到 {len(vector)}"
            )
        # 与 sklearn 保持一致：先整体转 float32
        vector = [_f32(value) for value in vector]
        total = 0.0
        for nodes in self.trees:
            total += self._tree_probability(nodes, vector)
        return total / self.n_trees

    def predict(self, vector, threshold=0.5):
        return 1 if self.predict_proba(vector) >= threshold else 0


def load_model(path=DEFAULT_MODEL_PATH):
    """加载导出的模型；文件不存在返回 None（调用方应视为「模型不可用」）。"""
    if not os.path.exists(path):
        return None
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        payload = json.load(handle)
    return NetModel(payload["features"], payload["trees"])


_cache = {}
_cache_lock = threading.Lock()


def get_model(path=DEFAULT_MODEL_PATH):
    """带缓存的加载，避免每处理一条流都读文件。"""
    with _cache_lock:
        if path in _cache:
            return _cache[path]
    model = load_model(path)
    with _cache_lock:
        _cache[path] = model
    return model


def score_flow(flow, model=None, threshold=0.5):
    """对一条流打分。返回 dict；模型不可用时返回 None。"""
    from .features import flow_to_features, vector_from_dict

    if model is None:
        model = get_model()
    if model is None:
        return None

    features = flow_to_features(flow)
    vector = vector_from_dict(features)
    probability = model.predict_proba(vector)
    return {
        "probability": round(probability, 4),
        "is_attack": probability >= threshold,
        "threshold": threshold,
        "features": features,
    }
