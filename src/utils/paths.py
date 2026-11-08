#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块名: paths.py
功能: 路径归一化与前缀匹配，供白名单、黑名单与信任目录判定统一使用

说明:
    Windows 路径在比较时存在大小写、分隔符方向、重复分隔符与尾部分隔符等差异，
    直接调用 startswith 容易漏判。本模块把两侧统一规范到同一形式后再比较，
    并按路径边界判断前缀，避免 c:\\windows 误匹配 c:\\windowsold 这类情况。
"""


def normalize(path):
    """把路径转换为用于比较的规范形式。

    规则: 小写化、反斜杠转正斜杠、折叠重复分隔符、去掉尾部分隔符。
    """
    if not path:
        return ""
    text = str(path).strip().replace("\\", "/").lower()
    while "//" in text:
        text = text.replace("//", "/")
    if len(text) > 1:
        text = text.rstrip("/")
    return text


def matches_prefix(path, prefixes):
    """判断 path 是否等于某个前缀目录，或位于该前缀目录之下。"""
    target = normalize(path)
    if not target:
        return False
    for prefix in prefixes or ():
        base = normalize(prefix)
        if not base:
            continue
        if target == base or target.startswith(base + "/"):
            return True
    return False


def contains_any(path, patterns):
    """判断 path 是否包含任一子串模式（用于缓存目录等模糊匹配）。"""
    target = normalize(path)
    if not target:
        return False
    return any(normalize(pattern) in target for pattern in (patterns or ()) if pattern)
