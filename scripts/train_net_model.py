#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络入侵检测模型训练（UNSW-NB15）

特征口径与线上采集一致：都用 detect/features.py 里的 aggregate_features，
只取方向无关的聚合量。这样数据集上训练出来的模型才能直接用于本项目。

用法:
    python scripts/train_net_model.py
    python scripts/train_net_model.py --csv data/datasets/UNSW_NB15.csv --test-size 0.3
"""

import argparse
import collections
import csv
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from detect.features import (
    CATEGORY_COLUMN,
    FEATURE_NAMES,
    FEATURE_VERSION,
    LABEL_COLUMN,
    dataset_row_to_features,
    vector_from_dict,
)


def load_dataset(path):
    features = []
    labels = []
    categories = []
    with open(path, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = [c for c in ("spkts", "dpkts", "sbytes", "dbytes", LABEL_COLUMN) if c not in reader.fieldnames]
        if missing:
            raise SystemExit(f"数据集缺少必需列: {missing}")
        for row in reader:
            features.append(vector_from_dict(dataset_row_to_features(row)))
            labels.append(int(float(row[LABEL_COLUMN])))
            categories.append((row.get(CATEGORY_COLUMN) or "Normal").strip())
    return features, labels, categories


def main(argv=None):
    parser = argparse.ArgumentParser(description="UNSW-NB15 网络入侵模型训练")
    parser.add_argument(
        "--csv", default=os.path.join(ROOT, "data", "datasets", "UNSW_NB15.csv")
    )
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--trees", type=int, default=150)
    parser.add_argument(
        "--out", default=os.path.join(ROOT, "data", "models", "net_model.joblib")
    )
    args = parser.parse_args(argv)

    if not os.path.exists(args.csv):
        print(f"[FAIL] 找不到数据集: {args.csv}")
        return 2

    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import (
            accuracy_score,
            confusion_matrix,
            f1_score,
            precision_score,
            recall_score,
            roc_auc_score,
            roc_curve,
        )
        from sklearn.model_selection import train_test_split
    except ImportError:
        print("[FAIL] 缺少 scikit-learn，先运行: pip install scikit-learn")
        return 3

    started = time.time()
    print(f"[INFO] 读取数据集: {args.csv}")
    features, labels, categories = load_dataset(args.csv)
    print(f"[INFO] 样本数 = {len(features)}   特征数 = {len(FEATURE_NAMES)}")
    print(f"[INFO] 标签分布: 正常 {labels.count(0)}  攻击 {labels.count(1)}")
    print(f"[INFO] 读取耗时 {time.time() - started:.1f}s")

    train_x, test_x, train_y, test_y, train_cat, test_cat = train_test_split(
        features, labels, categories,
        test_size=args.test_size, random_state=42, stratify=labels,
    )

    print(f"[INFO] 训练集 {len(train_x)}  测试集 {len(test_x)}")
    print(f"[INFO] 开始训练 RandomForest(trees={args.trees}) ...")
    model = RandomForestClassifier(
        n_estimators=args.trees,
        n_jobs=-1,
        random_state=42,
        class_weight="balanced_subsample",
        min_samples_leaf=2,
    )
    train_started = time.time()
    model.fit(train_x, train_y)
    print(f"[INFO] 训练完成，耗时 {time.time() - train_started:.1f}s")

    probabilities = model.predict_proba(test_x)[:, 1]
    predictions = (probabilities >= 0.5).astype(int)

    accuracy = accuracy_score(test_y, predictions)
    precision = precision_score(test_y, predictions, zero_division=0)
    recall = recall_score(test_y, predictions, zero_division=0)
    f1 = f1_score(test_y, predictions, zero_division=0)
    auc = roc_auc_score(test_y, probabilities)

    tn, fp, fn, tp = confusion_matrix(test_y, predictions, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    tnr = 1 - fpr

    print()
    print("=" * 58)
    print(f"准确率 Accuracy       : {accuracy:.4f}")
    print(f"精确率 Precision      : {precision:.4f}")
    print(f"召回率 Recall         : {recall:.4f}")
    print(f"F1 分数               : {f1:.4f}")
    print(f"ROC AUC               : {auc:.4f}")
    print(f"误报率 FPR            : {fpr:.4f}")
    print(f"混淆矩阵  TN={tn}  FP={fp}  FN={fn}  TP={tp}")

    # 按攻击类型看召回
    per_category = collections.defaultdict(lambda: [0, 0])
    for truth, prediction, category in zip(test_y, predictions, test_cat):
        if truth != 1:
            continue
        per_category[category][1] += 1
        if prediction == 1:
            per_category[category][0] += 1

    print()
    print("按攻击类型的召回率:")
    for category, (hit, total) in sorted(per_category.items(), key=lambda kv: -kv[1][1]):
        ratio = hit / total if total else 0
        print(f"    {category:<16} {hit:>6}/{total:<6} {ratio * 100:5.1f}%")

    # 特征重要度
    importances = sorted(
        zip(FEATURE_NAMES, model.feature_importances_), key=lambda kv: -kv[1]
    )
    print()
    print("特征重要度:")
    for name, value in importances:
        bar = "#" * max(1, int(value * 60))
        print(f"    {name:<14} {value:6.3f}  {bar}")

    # 找一个低误报工作点
    fpr_curve, tpr_curve, thresholds = roc_curve(test_y, probabilities)
    target_fpr = 0.01
    index = None
    for position, value in enumerate(fpr_curve):
        if value >= target_fpr:
            index = position
            break
    if index is not None:
        threshold = thresholds[index]
        low_fp_predictions = (probabilities >= threshold).astype(int)
        low_fp_precision = precision_score(test_y, low_fp_predictions, zero_division=0)
        low_fp_recall = recall_score(test_y, low_fp_predictions, zero_division=0)
        print()
        print(f"低误报工作点 (FPR≈{fpr_curve[index]:.3f}):")
        print(f"    阈值     {threshold:.4f}")
        print(f"    Precision {low_fp_precision:.4f}")
        print(f"    Recall    {low_fp_recall:.4f}")

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    try:
        import joblib

        joblib.dump(model, args.out)
        print()
        print(f"[INFO] 模型已保存: {args.out}")
    except Exception as exc:  # noqa: BLE001
        print(f"[WARN] 保存模型失败: {exc}")

    meta_path = os.path.splitext(args.out)[0] + ".meta.json"
    metadata = {
        "feature_version": FEATURE_VERSION,
        "features": list(FEATURE_NAMES),
        "dataset": os.path.basename(args.csv),
        "samples": len(features),
        "trees": args.trees,
        "metrics": {
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "roc_auc": round(auc, 4),
            "fpr": round(fpr, 4),
        },
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    with open(meta_path, "w", encoding="utf-8") as handle:
        json.dump(metadata, handle, ensure_ascii=False, indent=2)
    print(f"[INFO] 元数据已保存: {meta_path}")

    total = time.time() - started
    print(f"[INFO] 总耗时 {total:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
