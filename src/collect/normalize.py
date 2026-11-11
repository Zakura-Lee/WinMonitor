#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
事件归一化：把 RawEvent 转成统一的 Event。

当前阶段只做基于载荷字符串的启发式解析，
完整的 TDH 属性解码（CommandLine、ParentProcessId 等）在 P4 随进程采集器一起补齐。
"""

import ctypes

from .etw import providers, tdh
from .model import Event

_DEVICE_CACHE = None
_KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)

# 允许出现在文件名里的字符（用于字符串扫描的合法性判断）
_SAFE_PUNCT = set(" ._-:\\/()[]{}#$%&'+,;=@~!^")


def _device_map():
    """建立 NT 设备路径到盘符的映射，结果缓存。

    例如 '\\device\\harddiskvolume3' -> 'C:'
    """
    global _DEVICE_CACHE
    if _DEVICE_CACHE is not None:
        return _DEVICE_CACHE

    mapping = {}
    buffer = ctypes.create_unicode_buffer(1024)
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        drive = f"{letter}:"
        if _KERNEL32.QueryDosDeviceW(drive, buffer, 1024):
            mapping[buffer.value.lower()] = drive
    _DEVICE_CACHE = mapping
    return mapping


def nt_path_to_dos(path):
    """把 '\\Device\\HarddiskVolume3\\Windows\\...' 转成 'C:\\Windows\\...'。

    无法映射时原样返回，调用方应把这种情况当作「未知路径」处理。
    """
    if not path or not path.startswith("\\Device\\"):
        return path

    lowered = path.lower()
    for device, drive in _device_map().items():
        if lowered.startswith(device + "\\"):
            return drive + path[len(device):]
    return path


def extract_wide_strings(data, min_chars=3, limit=8):
    """从载荷里扫描 NUL 结尾的 UTF-16LE 字符串。"""
    found = []
    length = len(data) - (len(data) % 2)
    index = 0
    while index < length and len(found) < limit:
        chars = []
        cursor = index
        while cursor + 1 < length:
            code = data[cursor] | (data[cursor + 1] << 8)
            if code == 0:
                break
            printable = 0x20 <= code <= 0x7E or 0x4E00 <= code <= 0x9FFF
            if not printable:
                chars = []
                break
            chars.append(chr(code))
            cursor += 2
        if len(chars) >= min_chars:
            found.append("".join(chars))
            index = cursor + 2
        else:
            index += 2
    return found


def _looks_like_path(text):
    if not text:
        return False
    if text.startswith("\\Device\\") or text.startswith("\\\\?\\"):
        return True
    return len(text) > 3 and text[1] == ":" and text[2] in "\\/"


def _field(fields, *names, default=None):
    """按不区分大小写的字段名取值，取不到时返回默认值。"""
    if not fields:
        return default
    lowered = {}
    for key, value in fields.items():
        if key:
            lowered.setdefault(key.lower(), value)
    for name in names:
        value = lowered.get(name.lower())
        if value not in (None, ""):
            return value
    return default


def to_event(raw, provider_names=None):
    """把 RawEvent 转成 Event。

    优先使用 TDH 解析出的结构化字段；布局缺失时退回载荷字符串扫描。
    """
    names = provider_names if provider_names is not None else providers.GUID_TO_NAME
    provider_name = names.get(raw.provider_id, "")

    fields = {}
    if raw.properties:
        try:
            fields = tdh.decode_payload(raw.payload, raw.properties)
        except Exception:  # noqa: BLE001 - 解析失败退回字符串扫描
            fields = {}

    strings = [] if fields else extract_wide_strings(raw.payload)

    image = _field(fields, "ImageFileName", "ImageName", default="")
    if not image:
        for text in strings:
            if _looks_like_path(text):
                image = text
                break

    event = Event(
        ts_ns=raw.ts_ns,
        source="etw",
        provider=provider_name,
        event_id=raw.event_id,
        level=raw.level,
        keyword=raw.keyword,
        # 实测对账结论：事件头里的 pid 就是事件主体（8/8 命中真实 PID），
        # 载荷中的 ProcessID 只作参考保留在 extra 里，不覆盖此字段
        pid=raw.pid,
        tid=raw.tid,
        ppid=_field(fields, "ParentProcessID", "ParentProcessId", default=0),
        session_id=_field(fields, "SessionID", "SessionId", default=0),
        # Kernel-Process 没有 UniqueProcessKey，用序号作 PID 复用的判别键
        process_key=_field(fields, "ProcessSequenceNumber", "ProcessKey", default=0),
        image=nt_path_to_dos(image),
        path=nt_path_to_dos(image),
        cmdline=_field(fields, "CommandLine", default=""),
    )

    event.extra = {"fields": fields, "strings": strings}
    return event
