#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块名: asset_mon.py
功能: Windows 系统资产清点与基本设备信息采集
"""

import ctypes
import logging
import os
import platform
import re
import time

import pythoncom
from win32com.client import Dispatch

import config


def _parse_numeric_value(value):
    if isinstance(value, (int, float)):
        return float(value)
    if value is None:
        return 0.0
    try:
        text = str(value).strip().replace(",", "")
        suffix = text.lower().split()[-1] if " " in text else ""
        multiplier = 1.0
        if suffix == "bytes":
            text = text[: -len(suffix)].strip()
        elif suffix == "kb":
            multiplier = 1024.0
            text = text[: -len(suffix)].strip()
        elif suffix == "mb":
            multiplier = 1024.0 ** 2
            text = text[: -len(suffix)].strip()
        elif suffix == "gb":
            multiplier = 1024.0 ** 3
            text = text[: -len(suffix)].strip()
        elif suffix == "tb":
            multiplier = 1024.0 ** 4
            text = text[: -len(suffix)].strip()
        match = re.search(r"[-+]?[0-9]*\.?[0-9]+", text)
        if match:
            return float(match.group(0)) * multiplier
    except Exception:
        pass
    return 0.0


def collect_asset_inventory():
    inventory = {
        "computer_name": platform.node(),
        "os_version": platform.platform(),
        "architecture": platform.machine(),
        "cpu_count": os.cpu_count() or 0,
        "physical_memory_gb": "unknown",
        "logical_drives": [],
        "network_adapters": [],
    }

    try:
        pythoncom.CoInitialize()
        try:
            wmi = Dispatch("WbemScripting.SWbemLocator").ConnectServer(".", "root\\cimv2")
            system = wmi.ExecQuery("SELECT * FROM Win32_ComputerSystem")
            os_info = wmi.ExecQuery("SELECT * FROM Win32_OperatingSystem")
            disks = wmi.ExecQuery("SELECT * FROM Win32_LogicalDisk WHERE DriveType=3")
            adapters = wmi.ExecQuery("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=True")

            for item in system:
                inventory["manufacturer"] = getattr(item, "Manufacturer", "")
                inventory["model"] = getattr(item, "Model", "")
                inventory["cpu_count"] = getattr(item, "NumberOfLogicalProcessors", inventory["cpu_count"])
                total_physical = _parse_numeric_value(getattr(item, "TotalPhysicalMemory", 0))
                if total_physical:
                    inventory["physical_memory_gb"] = round(total_physical / 1024 ** 3, 2)

            for item in os_info:
                inventory["os_version"] = f"{getattr(item, 'Caption', inventory['os_version'])} {getattr(item, 'Version', '')}".strip()
                inventory["system_drive"] = getattr(item, "SystemDrive", "")

            for disk in disks:
                size_bytes = _parse_numeric_value(getattr(disk, "Size", 0))
                free_bytes = _parse_numeric_value(getattr(disk, "FreeSpace", 0))
                inventory["logical_drives"].append({
                    "device_id": getattr(disk, "DeviceID", ""),
                    "size_gb": round(size_bytes / 1024 ** 3, 2) if size_bytes else 0,
                    "free_space_gb": round(free_bytes / 1024 ** 3, 2) if free_bytes else 0,
                })

            for adapter in adapters:
                inventory["network_adapters"].append({
                    "description": getattr(adapter, "Description", ""),
                    "mac_address": getattr(adapter, "MACAddress", ""),
                    "ip_addresses": getattr(adapter, "IPAddress", []),
                })
        finally:
            try:
                pythoncom.CoUninitialize()
            except Exception:
                pass
    except Exception as exc:
        logging.warning("资产清点失败，使用基础平台信息: %s", exc)

    if inventory["physical_memory_gb"] == "unknown":
        inventory["physical_memory_gb"] = _query_physical_memory_fallback()

    return inventory


def _query_physical_memory_fallback():
    try:
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        memory_status = MEMORYSTATUSEX()
        memory_status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory_status)):
            return round(memory_status.ullTotalPhys / 1024 ** 3, 2)
    except Exception as exc:
        logging.debug("内存清点回退方式失败: %s", exc)
    return "unknown"


def asset_mon(stop_event, results, alert_queue=None, refresh_interval=config.ASSET_MON_INTERVAL):
    logging.info("资产清点已启动")
    try:
        while not stop_event.is_set():
            inventory = collect_asset_inventory()
            results["asset_inventory"] = inventory
            logging.info("资产清点完成: %s", inventory.get("computer_name", "unknown"))
            for _ in range(refresh_interval):
                if stop_event.is_set():
                    break
                time.sleep(1)
    finally:
        logging.info("资产清点已停止")
