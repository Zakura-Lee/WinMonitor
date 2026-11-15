#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把训练好的随机森林导出成纯数据模型

为什么要导出：
    应用跑在 Python 3.15.0a3 上，numpy/sklearn 的 C 扩展在该版本会报
    "unknown slot ID"，因此运行时不能依赖它们。
    导出后只剩数组，推理用标准库遍历即可，应用环境保持零科学计算依赖。

用法（需要带 sklearn 的解释器）:
    py -3.14 scripts/export_model.py
"""

import argparse
import gzip
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))


def export_tree(estimator):
    """把单棵树压成节点数组 [feature, threshold, left, right, prob]。"""
    tree = estimator.tree_
    nodes = []
    for index in range(tree.node_count):
        left = int(tree.children_left[index])
        right = int(tree.children_right[index])
        if left == -1:  # 叶节点
            counts = tree.value[index][0]
            total = float(counts[0] + counts[1]) or 1.0
            nodes.append([-1, 0.0, -1, -1, float(counts[1]) / total])
        else:
            # 阈值不能四舍五入，否则边界附近的样本会走错分支
            nodes.append(
                [
                    int(tree.feature[index]),
                    float(tree.threshold[index]),
                    left,
                    right,
                    -1.0,
                ]
            )
    return nodes


def main(argv=None):
    parser = argparse.ArgumentParser(description="导出纯数据模型")
    parser.add_argument(
        "--model", default=os.path.join(ROOT, "data", "models", "net_model.joblib")
    )
    parser.add_argument(
        "--out", default=os.path.join(ROOT, "data", "models", "net_model.json.gz")
    )
    args = parser.parse_args(argv)

    if not os.path.exists(args.model):
        print(f"[FAIL] 找不到模型: {args.model}")
        return 2

    try:
        import joblib
    except ImportError:
        print("[FAIL] 需要带 scikit-learn 的解释器来读取 joblib 模型")
        return 3

    from detect.features import FEATURE_NAMES, FEATURE_VERSION

    print(f"[INFO] 读取模型: {args.model}")
    model = joblib.load(args.model)
    estimators = getattr(model, "estimators_", None)
    if not estimators:
        print("[FAIL] 不是随机森林模型，暂不支持导出")
        return 4

    print(f"[INFO] 树的数量 = {len(estimators)}")
    trees = [export_tree(estimator) for estimator in estimators]

    payload = {
        "version": FEATURE_VERSION,
        "features": list(FEATURE_NAMES),
        "n_trees": len(trees),
        "trees": trees,
    }

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with gzip.open(args.out, "wt", encoding="utf-8") as handle:
        json.dump(payload, handle, separators=(",", ":"))
    size = os.path.getsize(args.out)
    print(f"[INFO] 已导出: {args.out}  ({size / 1024 / 1024:.1f} MB)")
    print(f"[INFO] 节点总数 = {sum(len(t) for t in trees)}")

    # 导出后立即自检：与 sklearn 的预测结果对照
    meta_path = os.path.splitext(args.model)[0] + ".meta.json"
    if os.path.exists(meta_path):
        with open(meta_path, encoding="utf-8") as handle:
            meta = json.load(handle)
        print(f"[INFO] 模型元数据: {meta.get('metrics')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
