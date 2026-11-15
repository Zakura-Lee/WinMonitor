#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络流特征对齐

用途：把本项目采集到的流记录，映射成与 UNSW-NB15 同名的特征向量，
这样公开数据集上训练出来的模型才能直接用到线上数据。

对齐原则：只使用两边都有的特征。
数据集里有、我们采不到的（TCP 状态机、TTL、重传计数等）一律不进向量，
宁可少几个特征，也不能在推理时编造数值。
"""

# 特征顺序即模型输入顺序，改动会影响已训练模型，必须同步版本号
FEATURE_VERSION = 1

# 直接对应 UNSW-NB15 列名的特征
DIRECT_FEATURES = (
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "smean",
    "dmean",
    "sintpkt",
    "dintpkt",
    "sjit",
    "djit",
    "rate",
)

# 由基础字段推导出来的特征
DERIVED_FEATURES = (
    "dur",    # 秒
    "sload",  # 源方向比特率 bps
    "dload",  # 目的方向比特率 bps
)

# 协议：我们的采集只能稳定区分 TCP / 非 TCP
PROTO_FEATURES = ("proto_tcp",)

FEATURE_NAMES = DIRECT_FEATURES + DERIVED_FEATURES + PROTO_FEATURES

# 我们用不到但数据集里存在的列，训练时必须丢弃
DATASET_EXTRA_COLUMNS = (
    "state",
    "service",
    "sttl",
    "dttl",
    "sloss",
    "dloss",
    "swin",
    "stcpb",
    "dtcpb",
    "dwin",
    "tcprtt",
    "synack",
    "ackdat",
    "trans_depth",
    "response_body_len",
    "ct_srv_src",
    "ct_state_ttl",
    "ct_dst_ltm",
    "ct_src_dport_ltm",
    "ct_dst_sport_ltm",
    "ct_dst_src_ltm",
    "is_ftp_login",
    "ct_ftp_cmd",
    "ct_flw_http_mthd",
    "ct_src_ltm",
    "ct_srv_dst",
    "is_sm_ips_ports",
)

# 数据集里我们直接沿用的列名（dur 在数据集里是秒）
DATASET_COLUMN_MAP = {
    "spkts": "spkts",
    "dpkts": "dpkts",
    "sbytes": "sbytes",
    "dbytes": "dbytes",
    "smean": "smean",
    "dmean": "dmean",
    "sintpkt": "sinpkt",
    "dintpkt": "dinpkt",
    "sjit": "sjit",
    "djit": "djit",
    "rate": "rate",
    "dur": "dur",
}


def _safe_float(value, default=0.0):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    if number != number or number in (float("inf"), float("-inf")):  # NaN / inf
        return default
    return number


def flow_to_features(flow):
    """把一条流记录转成特征字典（键为 FEATURE_NAMES）。"""
    duration_seconds = _safe_float(flow.get("dur_ms")) / 1000.0
    sbytes = _safe_float(flow.get("sbytes"))
    dbytes = _safe_float(flow.get("dbytes"))

    if duration_seconds > 0:
        sload = sbytes * 8 / duration_seconds
        dload = dbytes * 8 / duration_seconds
    else:
        sload = 0.0
        dload = 0.0

    proto = str(flow.get("proto", "tcp")).lower()

    return {
        "spkts": _safe_float(flow.get("spkts")),
        "dpkts": _safe_float(flow.get("dpkts")),
        "sbytes": sbytes,
        "dbytes": dbytes,
        "smean": _safe_float(flow.get("smean")),
        "dmean": _safe_float(flow.get("dmean")),
        "sintpkt": _safe_float(flow.get("sintpkt")),
        "dintpkt": _safe_float(flow.get("dintpkt")),
        "sjit": _safe_float(flow.get("sjit")),
        "djit": _safe_float(flow.get("djit")),
        "rate": _safe_float(flow.get("rate")),
        "dur": duration_seconds,
        "sload": round(sload, 3),
        "dload": round(dload, 3),
        "proto_tcp": 1.0 if proto.startswith("tcp") else 0.0,
    }


def vector(flow):
    """按 FEATURE_NAMES 顺序输出列表，可直接喂给模型。"""
    features = flow_to_features(flow)
    return [features[name] for name in FEATURE_NAMES]
