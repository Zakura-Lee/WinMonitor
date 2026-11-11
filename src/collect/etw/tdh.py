#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TDH 事件解码

用途:
    从 EVENT_RECORD 里取出事件的属性布局（属性名、类型、长度），
    再按布局把 UserData 载荷解析成字典。

设计:
    TdhGetEventInformation 的开销不低，而同一事件的布局是固定的，
    所以按 (提供者, 事件ID, 版本) 缓存布局，回调线程只解析一次。

结构偏移来自 Windows SDK 的 tdh.h（10.0.22621.0）:
    EVENT_PROPERTY_INFO 24 字节
    TRACE_EVENT_INFO 的 EventPropertyInfoArray 起始于 112
"""

import ctypes
from ctypes import wintypes

from . import api

PROPERTY_ARRAY_OFFSET = 112
PROPERTY_INFO_SIZE = 24

# TRACE_EVENT_INFO 头部字段偏移
OFFSET_PROVIDER_NAME = 52
OFFSET_EVENT_NAME = 92
OFFSET_PROPERTY_COUNT = 100

# TDH_INTYPE_* 取值
INTYPE_UNICODESTRING = 1
INTYPE_ANSISTRING = 2
INTYPE_INT8 = 3
INTYPE_UINT8 = 4
INTYPE_INT16 = 5
INTYPE_UINT16 = 6
INTYPE_INT32 = 7
INTYPE_UINT32 = 8
INTYPE_INT64 = 9
INTYPE_UINT64 = 10
INTYPE_FLOAT = 11
INTYPE_DOUBLE = 12
INTYPE_BOOLEAN = 13
INTYPE_BINARY = 14
INTYPE_GUID = 15
INTYPE_POINTER = 16
INTYPE_FILETIME = 17
INTYPE_SYSTEMTIME = 18
INTYPE_SID = 19
INTYPE_HEXINT32 = 20
INTYPE_HEXINT64 = 21

_INT_TYPES = {
    INTYPE_INT8: (1, True),
    INTYPE_UINT8: (1, False),
    INTYPE_INT16: (2, True),
    INTYPE_UINT16: (2, False),
    INTYPE_INT32: (4, True),
    INTYPE_UINT32: (4, False),
    INTYPE_INT64: (8, True),
    INTYPE_UINT64: (8, False),
    INTYPE_HEXINT32: (4, False),
    INTYPE_HEXINT64: (8, False),
    INTYPE_POINTER: (8, False),
    INTYPE_BOOLEAN: (4, False),
}

_FIXED_SIZES = {
    INTYPE_FLOAT: 4,
    INTYPE_DOUBLE: 8,
    INTYPE_FILETIME: 8,
    INTYPE_GUID: 16,
    INTYPE_SYSTEMTIME: 16,
}


class Property:
    """事件属性的布局描述。"""

    __slots__ = ("name", "in_type", "out_type", "count", "length", "flags")

    def __init__(self, name, in_type, out_type, count, length, flags):
        self.name = name
        self.in_type = in_type
        self.out_type = out_type
        self.count = count
        self.length = length
        self.flags = flags

    def __repr__(self):
        return f"Property({self.name!r}, in_type={self.in_type}, count={self.count})"


def _read_ulong(buffer, offset):
    if offset + 4 > len(buffer):
        return 0
    return int.from_bytes(buffer[offset: offset + 4], "little")


def _read_ushort(buffer, offset):
    if offset + 2 > len(buffer):
        return 0
    return int.from_bytes(buffer[offset: offset + 2], "little")


def _read_wide(buffer, offset):
    if not 0 < offset < len(buffer):
        return ""
    end = offset
    while end + 1 < len(buffer) and (buffer[end] or buffer[end + 1]):
        end += 2
    return buffer[offset:end].decode("utf-16-le", "ignore")


def parse_event_information(buffer):
    """解析 TRACE_EVENT_INFO 缓冲区，返回 (事件名, 属性列表)。"""
    event_name = _read_wide(buffer, _read_ulong(buffer, OFFSET_EVENT_NAME))
    count = _read_ulong(buffer, OFFSET_PROPERTY_COUNT)
    if count > 256:  # 明显的异常值，拒绝继续解析
        return event_name, []

    properties = []
    for index in range(count):
        base = PROPERTY_ARRAY_OFFSET + index * PROPERTY_INFO_SIZE
        if base + PROPERTY_INFO_SIZE > len(buffer):
            break
        flags = _read_ulong(buffer, base)
        name_offset = _read_ulong(buffer, base + 4)
        in_type = _read_ushort(buffer, base + 8)
        out_type = _read_ushort(buffer, base + 10)
        prop_count = _read_ushort(buffer, base + 16)
        length = _read_ushort(buffer, base + 18)
        properties.append(
            Property(_read_wide(buffer, name_offset), in_type, out_type, prop_count, length, flags)
        )
    return event_name, properties


class LayoutCache:
    """按 (提供者, 事件ID, 版本) 缓存事件布局。"""

    def __init__(self):
        self._cache = {}

    def get(self, record, provider_id, event_id, version):
        key = (provider_id, event_id, version)
        cached = self._cache.get(key)
        if cached is not None:
            return cached

        buffer = self._fetch(record)
        if not buffer:
            layout = ("", ())
        else:
            layout = parse_event_information(buffer)
        self._cache[key] = layout
        return layout

    @staticmethod
    def _fetch(record):
        size = wintypes.ULONG(0)
        rc = api.TdhGetEventInformation(
            ctypes.byref(record), 0, None, None, ctypes.byref(size)
        )
        if rc != 122 or not 0 < size.value < (1 << 20):  # 122 = ERROR_INSUFFICIENT_BUFFER
            return b""

        buffer = ctypes.create_string_buffer(size.value)
        rc = api.TdhGetEventInformation(
            ctypes.byref(record), 0, None, buffer, ctypes.byref(size)
        )
        if rc != 0:
            return b""
        return buffer.raw[: size.value]

    def __len__(self):
        return len(self._cache)


def _align(offset, alignment):
    if alignment <= 1:
        return offset
    return (offset + alignment - 1) // alignment * alignment


def _decode_one(payload, offset, prop):
    """解析单个属性值，返回 (值, 新偏移)。"""
    in_type = prop.in_type

    if in_type == INTYPE_UNICODESTRING:
        offset = _align(offset, 2)
        end = offset
        while end + 1 < len(payload) and (payload[end] or payload[end + 1]):
            end += 2
        text = payload[offset:end].decode("utf-16-le", "ignore")
        return text, min(end + 2, len(payload))

    if in_type == INTYPE_ANSISTRING:
        end = payload.find(b"\x00", offset)
        if end < 0:
            end = len(payload)
        return payload[offset:end].decode("utf-8", "ignore"), min(end + 1, len(payload))

    if in_type in _INT_TYPES:
        size, signed = _INT_TYPES[in_type]
        offset = _align(offset, size)
        if offset + size > len(payload):
            return None, len(payload)
        value = int.from_bytes(payload[offset: offset + size], "little", signed=signed)
        return value, offset + size

    if in_type in _FIXED_SIZES:
        size = _FIXED_SIZES[in_type]
        offset = _align(offset, size)
        if offset + size > len(payload):
            return None, len(payload)
        raw = payload[offset: offset + size]
        if in_type == INTYPE_GUID:
            from .etwtypes import GUID

            guid = GUID.from_buffer_copy(raw)
            return str(guid), offset + size
        if in_type == INTYPE_FILETIME:
            return int.from_bytes(raw, "little"), offset + size
        if in_type == INTYPE_SYSTEMTIME:
            return raw.hex(), offset + size
        return int.from_bytes(raw, "little"), offset + size

    if in_type == INTYPE_SID:
        offset = _align(offset, 4)
        if offset + 8 > len(payload):
            return None, len(payload)
        revision = payload[offset]
        sub_count = payload[offset + 1]
        size = 8 + 4 * sub_count
        raw = payload[offset: offset + size]
        return raw.hex(), min(offset + size, len(payload))

    # 未知类型：无法安全推算长度，停止解析
    return None, len(payload)


def decode_payload(payload, properties):
    """按属性布局把载荷解析成字典。"""
    result = {}
    offset = 0
    for prop in properties:
        if not prop.name:
            continue
        try:
            value, offset = _decode_one(payload, offset, prop)
        except Exception:  # noqa: BLE001
            break
        result[prop.name] = value
    return result
