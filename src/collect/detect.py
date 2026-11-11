#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
事件判定规则

本阶段只有网络连接的分类，进程与文件规则在后续阶段补入。
判定结果统一返回 (event_type, reason, severity)：
    event_type : normal / abnormal / attack
    severity   : None / warning / critical
"""

import config

HIGH_RISK_PORTS = config.HIGH_RISK_REMOTE_PORTS
SQL_PORTS = config.SQL_REMOTE_PORTS
SAFE_PUBLIC_PORTS = config.SAFE_PUBLIC_PORTS
PRIVATE_PREFIXES = config.PRIVATE_PREFIXES


def is_public_address(address):
    """判断是否为公网地址。内网与回环不算外部连接。"""
    if not address:
        return False
    return not str(address).startswith(PRIVATE_PREFIXES)


def classify_network(event):
    """对一次网络连接给出分类结果。"""
    port = event.dport or 0
    external = is_public_address(event.daddr)

    if port in HIGH_RISK_PORTS and external:
        return "attack", f"高危端口连接 {port}", "critical"
    if port in SQL_PORTS and external:
        return "attack", f"SQL 目标端口 {port}", "warning"
    if port in SAFE_PUBLIC_PORTS:
        return "normal", f"常见服务端口 {port}", None
    if not external:
        return "normal", "内网连接", None
    return "normal", "外部连接", None
