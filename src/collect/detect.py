#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
事件判定规则

当前覆盖网络连接与文件写入两类，进程规则在后续阶段补入。
判定结果统一返回 (event_type, reason, severity)：
    event_type : normal / abnormal / attack / danger
    severity   : None / warning / critical
"""

import os

import config
from utils.paths import matches_prefix

HIGH_RISK_PORTS = config.HIGH_RISK_REMOTE_PORTS
SQL_PORTS = config.SQL_REMOTE_PORTS
SAFE_PUBLIC_PORTS = config.SAFE_PUBLIC_PORTS
PRIVATE_PREFIXES = config.PRIVATE_PREFIXES

DANGEROUS_EXTENSIONS = config.DANGEROUS_FILE_EXTENSIONS
TRUSTED_PATHS = config.FILE_MONITOR_TRUSTED_PATHS
SENSITIVE_PATHS = config.FILE_MONITOR_SENSITIVE_PATHS
TEMP_PATTERNS = config.TEMP_PATH_PATTERNS
FILE_SCORE_THRESHOLD = config.FILE_MONITOR_EVENT_SCORE_THRESHOLD


def is_public_address(address):
    """判断是否为公网地址。内网、回环与 IPv6 本地地址都不算外部连接。"""
    if not address:
        return False
    text = str(address).strip().lower()
    if text == "::1" or text.startswith("fe80:") or text.startswith("fc") or text.startswith("fd"):
        return False
    return not text.startswith(PRIVATE_PREFIXES)


def format_endpoint(address, port):
    """拼成 host:port；IPv6 需要加方括号，否则冒号会混淆。"""
    host = str(address or "")
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{host}:{port}"


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


def classify_file(event, action="created"):
    """对一次文件写入/删除给出分类结果。

    评分思路沿用旧文件监控：可执行扩展、敏感路径、临时目录三项加权，
    落在信任目录下的操作直接放行。
    """
    path = event.path
    if not path:
        return "normal", "无路径信息", None

    if matches_prefix(path, TRUSTED_PATHS):
        return "normal", "信任路径", None

    normalized = str(path).lower().replace("/", "\\")
    score = 0
    reasons = []

    extension = os.path.splitext(normalized)[1]
    if extension in DANGEROUS_EXTENSIONS:
        score += 2
        reasons.append(f"可执行扩展 {extension}")

    if matches_prefix(path, SENSITIVE_PATHS):
        score += 1
        reasons.append("敏感路径")

    if any(pattern in normalized for pattern in TEMP_PATTERNS):
        score += 1
        reasons.append("临时目录")

    if score < FILE_SCORE_THRESHOLD:
        return "normal", "；".join(reasons) or "常规文件操作", None

    severity = "critical" if score >= 3 else "warning"
    return "danger", f"{action}：" + "；".join(reasons), severity
