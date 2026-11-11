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

# 进程采集以 Kernel-Process 为骨干，Sysmon 补充命令行与进程 GUID。
# 未安装 Sysmon 的环境会自动跳过该提供者（见 EtwCollector.start 的容错）。
DEFAULT_PROVIDERS = (KERNEL_PROCESS, SYSMON)

# --- Sysmon ---------------------------------------------------------------
# Sysmon 的事件由 Sysmon64.exe 记录，因此 EventHeader.ProcessId 是 Sysmon 自身，
# 进程的真实 PID 必须取自载荷里的 ProcessId 字段。

SYSMON = ProviderSpec(
    name="Microsoft-Windows-Sysmon",
    guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}",
    keywords=0,
    level=5,
)

SYSMON_EVENT_NAMES = {
    1: "ProcessCreate",
    2: "FileCreateTime",
    3: "NetworkConnect",
    4: "SysmonServiceState",
    5: "ProcessTerminate",
    6: "DriverLoad",
    7: "ImageLoad",
    8: "CreateRemoteThread",
    9: "RawAccessRead",
    10: "ProcessAccess",
    11: "FileCreate",
    12: "RegistryCreateDelete",
    13: "RegistryValueSet",
    14: "RegistryRename",
    15: "FileCreateStreamHash",
    17: "PipeCreated",
    18: "PipeConnected",
    22: "DnsQuery",
    23: "FileDelete",
    25: "ProcessTampering",
    26: "FileDeleteDetected",
}

# 本课题关心的事件：进程创建是核心，其余按 P6/P7 需要再放开
SYSMON_CORE_EVENTS = (1, 5)

ALL_PROVIDERS = (KERNEL_PROCESS, KERNEL_FILE, KERNEL_NETWORK, KERNEL_REGISTRY, SYSMON)


def guid_bytes(guid_text):
    """把 GUID 文本转成与内存布局一致的 16 字节。"""
    from .etwtypes import guid_from_string

    return bytes(guid_from_string(guid_text))


GUID_TO_NAME = {guid_bytes(spec.guid): spec.name for spec in ALL_PROVIDERS}
