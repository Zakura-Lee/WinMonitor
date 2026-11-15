#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络流特征对齐（方向无关版）

背景：内核网络事件以「连接」为单位上报，本机地址始终出现在源端，
无法可靠区分收发方向。与其猜事件 ID 语义，不如把特征降维成
方向无关的聚合量，并在 UNSW-NB15 侧做同样的聚合。

保证对称的做法：两侧都调用同一个 aggregate_features()，
只是取数来源不同。任何一侧改了公式，另一侧自动跟随。

特征清单与对应关系（UNSW-NB15 列名）:
    pkts_total    = spkts + dpkts
    bytes_total   = sbytes + dbytes
    dur           = dur
    rate          = rate
    load_total    = sload + dload
    mean_pkt_size = bytes_total / pkts_total
    iat_mean      = (sinpkt*spkts + dinpkt*dpkts) / pkts_total
    jitter        = (sjit*spkts + djit*dpkts) / pkts_total
    proto_tcp     = proto == "tcp"
"""

# 特征顺序即模型输入顺序，改动必须同步版本号
FEATURE_VERSION = 2

FEATURE_NAMES = (
    "pkts_total",
    "bytes_total",
    "dur",
    "rate",
    "load_total",
    "mean_pkt_size",
    "iat_mean",
    "jitter",
    "proto_tcp",
)

# 训练时要用到的数据集原始列
DATASET_COLUMNS = (
    "dur",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "rate",
    "sload",
    "dload",
    "sinpkt",
    "dinpkt",
    "sjit",
    "djit",
    "proto",
)

LABEL_COLUMN = "label"
CATEGORY_COLUMN = "attack_cat"


def _f(value, default=0.0):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    if number != number:  # NaN
        return default
    if number in (float("inf"), float("-inf")):
        return default
    return number


def _weighted(a, wa, b, wb):
    total = wa + wb
    if total <= 0:
        return 0.0
    return (a * wa + b * wb) / total


def aggregate_features(
    dur,
    spkts,
    dpkts,
    sbytes,
    dbytes,
    rate,
    sload,
    dload,
    sinpkt,
    dinpkt,
    sjit,
    djit,
    proto,
):
    """两侧共用的特征公式。"""
    spkts = _f(spkts)
    dpkts = _f(dpkts)
    sbytes = _f(sbytes)
    dbytes = _f(dbytes)
    dur = _f(dur)

    pkts_total = spkts + dpkts
    bytes_total = sbytes + dbytes

    mean_pkt_size = bytes_total / pkts_total if pkts_total > 0 else 0.0
    iat_mean = _weighted(_f(sinpkt), spkts, _f(dinpkt), dpkts)
    jitter = _weighted(_f(sjit), spkts, _f(djit), dpkts)

    proto_text = str(proto or "").lower()
    proto_tcp = 1.0 if proto_text.startswith("tcp") else 0.0

    return {
        "pkts_total": pkts_total,
        "bytes_total": bytes_total,
        "dur": dur,
        "rate": _f(rate),
        "load_total": _f(sload) + _f(dload),
        "mean_pkt_size": round(mean_pkt_size, 4),
        "iat_mean": round(iat_mean, 4),
        "jitter": round(jitter, 4),
        "proto_tcp": proto_tcp,
    }


def flow_to_features(flow):
    """把一条采集到的流记录转成特征字典。"""
    duration_seconds = _f(flow.get("dur_ms")) / 1000.0
    sbytes = _f(flow.get("sbytes"))
    dbytes = _f(flow.get("dbytes"))

    if duration_seconds > 0:
        sload = sbytes * 8 / duration_seconds
        dload = dbytes * 8 / duration_seconds
    else:
        sload = 0.0
        dload = 0.0

    return aggregate_features(
        dur=duration_seconds,
        spkts=flow.get("spkts"),
        dpkts=flow.get("dpkts"),
        sbytes=sbytes,
        dbytes=dbytes,
        rate=flow.get("rate"),
        sload=sload,
        dload=dload,
        sinpkt=flow.get("sintpkt"),
        dinpkt=flow.get("dintpkt"),
        sjit=flow.get("sjit"),
        djit=flow.get("djit"),
        proto=flow.get("proto", "tcp"),
    )


def dataset_row_to_features(row):
    """把 UNSW-NB15 的一行转成同样的特征字典。"""
    return aggregate_features(
        dur=row.get("dur"),
        spkts=row.get("spkts"),
        dpkts=row.get("dpkts"),
        sbytes=row.get("sbytes"),
        dbytes=row.get("dbytes"),
        rate=row.get("rate"),
        sload=row.get("sload"),
        dload=row.get("dload"),
        sinpkt=row.get("sinpkt"),
        dinpkt=row.get("dinpkt"),
        sjit=row.get("sjit"),
        djit=row.get("djit"),
        proto=row.get("proto"),
    )


def vector_from_dict(features):
    """按 FEATURE_NAMES 顺序输出列表。"""
    return [features[name] for name in FEATURE_NAMES]


def vector(flow):
    """流记录直接转成模型输入向量。"""
    return vector_from_dict(flow_to_features(flow))
