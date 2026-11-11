#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ETW 提供者注册表：集中管理提供者 GUID、关键字与事件 ID。"""

from dataclasses import dataclass

# Kernel-Process 关键字位（来自 logman query providers 实测）
WINEVENT_KEYWORD_PROCESS = 0x10
WINEVENT_KEYWORD_THREAD = 0x20
WINEVENT_KEYWORD_IMAGE = 0x40

# Kernel-Process 事件 ID
EVENT_PROCESS_START = 1
EVENT_PROCESS_STOP = 2
EVENT_THREAD_START = 3
EVENT_THREAD_STOP = 4
EVENT_IMAGE_LOAD = 5
EVENT_IMAGE_UNLOAD = 6

EVENT_ID_NAMES = {
    EVENT_PROCESS_START: "ProcessStart",
    EVENT_PROCESS_STOP: "ProcessStop",
    EVENT_THREAD_START: "ThreadStart",
    EVENT_THREAD_STOP: "ThreadStop",
    EVENT_IMAGE_LOAD: "ImageLoad",
    EVENT_IMAGE_UNLOAD: "ImageUnload",
}


@dataclass(frozen=True)
class ProviderSpec:
    """一个 ETW 提供者的启用参数。

    keywords 为 0 表示不按关键字过滤（启用该提供者的全部事件）。
    """

    name: str
    guid: str
    keywords: int = 0
    level: int = 5


KERNEL_PROCESS = ProviderSpec(
    name="Microsoft-Windows-Kernel-Process",
    guid="{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}",
    keywords=WINEVENT_KEYWORD_PROCESS | WINEVENT_KEYWORD_THREAD | WINEVENT_KEYWORD_IMAGE,
    level=5,
)

KERNEL_FILE = ProviderSpec(
    name="Microsoft-Windows-Kernel-File",
    guid="{EDD08927-9CC4-4E65-B970-C2560FB5C289}",
    keywords=0,
    level=5,
)

KERNEL_NETWORK = ProviderSpec(
    name="Microsoft-Windows-Kernel-Network",
    guid="{7DD42A49-5329-4832-8DFD-43D979153A88}",
    keywords=0,
    level=5,
)

KERNEL_REGISTRY = ProviderSpec(
    name="Microsoft-Windows-Kernel-Registry",
    guid="{70EB4F03-C1DE-4F73-A051-33D13D5413BD}",
    keywords=0,
    level=5,
)

# 本阶段只启用进程提供者；文件、网络、注册表在 P6/P7 接入
DEFAULT_PROVIDERS = (KERNEL_PROCESS,)

ALL_PROVIDERS = (KERNEL_PROCESS, KERNEL_FILE, KERNEL_NETWORK, KERNEL_REGISTRY)


def guid_bytes(guid_text):
    """把 GUID 文本转成与内存布局一致的 16 字节。"""
    from .etwtypes import guid_from_string

    return bytes(guid_from_string(guid_text))


GUID_TO_NAME = {guid_bytes(spec.guid): spec.name for spec in ALL_PROVIDERS}
