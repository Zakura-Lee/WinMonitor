#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
资产清点（不依赖 WMI）

原实现通过 Win32_ComputerSystem / Win32_OperatingSystem / Win32_LogicalDisk /
Win32_NetworkAdapterConfiguration 四个 WMI 类取信息，这里全部改为
原生 API 与注册表读取：
    系统型号   -> HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS
    内存       -> GlobalMemoryStatusEx
    磁盘       -> GetLogicalDrives + GetDiskFreeSpaceExW
    网卡       -> GetAdaptersAddresses
"""

import ctypes
import os
import platform
import socket
import winreg
from ctypes import wintypes

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)

AF_INET = 2
AF_INET6 = 23
MAX_ADAPTER_ADDRESS_LENGTH = 8
ERROR_BUFFER_OVERFLOW = 111
GAA_FLAG_SKIP_ANYCAST = 0x0002
GAA_FLAG_SKIP_MULTICAST = 0x0004
GAA_FLAG_SKIP_DNS_SERVER = 0x0008


class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", wintypes.DWORD),
        ("dwMemoryLoad", wintypes.DWORD),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


class SOCKET_ADDRESS(ctypes.Structure):
    _fields_ = [("lpSockaddr", ctypes.c_void_p), ("iSockaddrLength", ctypes.c_int)]


class IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
    pass


IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
    ("Length", wintypes.ULONG),
    ("Flags", wintypes.DWORD),
    ("Next", ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
    ("Address", SOCKET_ADDRESS),
    ("PrefixOrigin", ctypes.c_int),
    ("SuffixOrigin", ctypes.c_int),
    ("DadState", ctypes.c_int),
    ("ValidLifetime", wintypes.ULONG),
    ("PreferredLifetime", wintypes.ULONG),
    ("LeaseLifetime", wintypes.ULONG),
    ("OnLinkPrefixLength", ctypes.c_ubyte),
]


class IP_ADAPTER_ADDRESSES(ctypes.Structure):
    """只声明到 FriendlyName 与物理地址，后续字段不读取。"""

    pass


IP_ADAPTER_ADDRESSES._fields_ = [
    ("Length", wintypes.ULONG),
    ("IfIndex", wintypes.DWORD),
    ("Next", ctypes.POINTER(IP_ADAPTER_ADDRESSES)),
    ("AdapterName", ctypes.c_char_p),
    ("FirstUnicastAddress", ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
    ("FirstAnycastAddress", ctypes.c_void_p),
    ("FirstMulticastAddress", ctypes.c_void_p),
    ("FirstDnsServerAddress", ctypes.c_void_p),
    ("DnsSuffix", ctypes.c_wchar_p),
    ("Description", ctypes.c_wchar_p),
    ("FriendlyName", ctypes.c_wchar_p),
    ("PhysicalAddress", ctypes.c_ubyte * MAX_ADAPTER_ADDRESS_LENGTH),
    ("PhysicalAddressLength", wintypes.ULONG),
]


def _format_sockaddr(sockaddr_ptr, length):
    """把 SOCKADDR 指针转成 IP 字符串。"""
    if not sockaddr_ptr or length < 2:
        return ""
    family = int.from_bytes(ctypes.string_at(sockaddr_ptr, 2), "little")
    try:
        if family == AF_INET and length >= 8:
            raw = ctypes.string_at(sockaddr_ptr + 4, 4)
            return socket.inet_ntop(AF_INET, raw)
        if family == AF_INET6 and length >= 24:
            raw = ctypes.string_at(sockaddr_ptr + 8, 16)
            return socket.inet_ntop(AF_INET6, raw)
    except (OSError, ValueError):
        return ""
    return ""


def collect_system_model():
    """从注册表读取厂商与型号。"""
    info = {"manufacturer": "", "model": ""}
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS"
        ) as key:
            for field, name in (("manufacturer", "SystemManufacturer"), ("model", "SystemProductName")):
                try:
                    info[field] = str(winreg.QueryValueEx(key, name)[0]).strip()
                except OSError:
                    info[field] = ""
    except OSError:
        pass
    return info


def collect_memory_gb():
    status = MEMORYSTATUSEX()
    status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    if _kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        return round(status.ullTotalPhys / 1024 ** 3, 2)
    return "unknown"


def collect_disks():
    drives = []
    try:
        bitmask = _kernel32.GetLogicalDrives()
    except Exception:  # noqa: BLE001
        return drives

    for index in range(26):
        if not bitmask & (1 << index):
            continue
        root = f"{chr(ord('A') + index)}:\\"
        free = ctypes.c_ulonglong(0)
        total = ctypes.c_ulonglong(0)
        if _kernel32.GetDiskFreeSpaceExW(
            ctypes.c_wchar_p(root), ctypes.byref(free), ctypes.byref(total), None
        ):
            if total.value == 0:
                continue  # 光驱等无容量设备
            drives.append(
                {
                    "device_id": root.rstrip("\\"),
                    "size_gb": round(total.value / 1024 ** 3, 2),
                    "free_space_gb": round(free.value / 1024 ** 3, 2),
                }
            )
    return drives


def collect_adapters():
    """枚举网卡：友好名、MAC、IP 地址。"""
    flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER
    size = wintypes.ULONG(15000)
    buffer = ctypes.create_string_buffer(size.value)

    rc = _iphlpapi.GetAdaptersAddresses(
        wintypes.ULONG(AF_INET | AF_INET6), flags, None, buffer, ctypes.byref(size)
    )
    if rc == ERROR_BUFFER_OVERFLOW:
        buffer = ctypes.create_string_buffer(size.value)
        rc = _iphlpapi.GetAdaptersAddresses(
            wintypes.ULONG(AF_INET | AF_INET6), flags, None, buffer, ctypes.byref(size)
        )
    if rc != 0:
        return []

    adapters = []
    current = ctypes.cast(buffer, ctypes.POINTER(IP_ADAPTER_ADDRESSES))
    while current:
        entry = current.contents
        addresses = []
        unicast = entry.FirstUnicastAddress
        while unicast:
            address = unicast.contents.Address
            text = _format_sockaddr(address.lpSockaddr, address.iSockaddrLength)
            if text:
                addresses.append(text)
            unicast = unicast.contents.Next

        mac = ""
        length = min(int(entry.PhysicalAddressLength), MAX_ADAPTER_ADDRESS_LENGTH)
        if length:
            mac = ":".join(f"{entry.PhysicalAddress[i]:02X}" for i in range(length))

        adapters.append(
            {
                "description": entry.Description or "",
                "friendly_name": entry.FriendlyName or "",
                "mac_address": mac,
                "ip_addresses": addresses,
            }
        )
        current = entry.Next

    return adapters


def collect_asset_inventory():
    """汇总资产信息，字段与 WMI 版本保持一致。"""
    model = collect_system_model()
    inventory = {
        "computer_name": platform.node(),
        "os_version": platform.platform(),
        "architecture": platform.machine(),
        "cpu_count": os.cpu_count() or 0,
        "physical_memory_gb": collect_memory_gb(),
        "manufacturer": model["manufacturer"],
        "model": model["model"],
        "system_drive": os.environ.get("SystemDrive", ""),
        "logical_drives": collect_disks(),
        "network_adapters": collect_adapters(),
    }
    return inventory
