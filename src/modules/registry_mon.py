#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块名: registry_mon.py
功能: Windows 注册表变更监控
"""

import logging
import time
import win32api
import win32con

import config

MONITORED_REGISTRY = config.MONITORED_REGISTRY
SUSPICIOUS_REGISTRY_PATTERNS = config.SUSPICIOUS_REGISTRY_PATTERNS
REGISTRY_SAFE_PATTERNS = config.REGISTRY_SAFE_PATTERNS


def normalize_key(text):
    return str(text).strip().lower() if text else ""


def read_registry_values(hive, subkey):
    """读取指定注册表项的值和数据，返回字典。"""
    values = {}
    try:
        key = win32api.RegOpenKeyEx(hive, subkey, 0, win32con.KEY_READ)
    except Exception as exc:
        logging.debug("无法打开注册表项 %s\\%s: %s", hive, subkey, exc)
        return values

    try:
        try:
            value_count, _, _ = win32api.RegQueryInfoKey(key)
        except Exception:
            value_count = 0

        for index in range(value_count):
            try:
                name, data, _type = win32api.RegEnumValue(key, index)
                values[normalize_key(name)] = str(data)
            except OSError:
                break
            except Exception as exc:
                logging.debug("注册表值枚举失败 %s\\%s index=%s: %s", hive, subkey, index, exc)
                break
    finally:
        win32api.RegCloseKey(key)

    return values


def detect_registry_changes(old_snapshot, new_snapshot):
    changes = []

    for key, current_values in new_snapshot.items():
        previous_values = old_snapshot.get(key, {})
        added = set(current_values) - set(previous_values)
        removed = set(previous_values) - set(current_values)
        modified = [name for name in set(current_values) & set(previous_values) if previous_values[name] != current_values[name]]

        if added or removed or modified:
            changes.append((key, added, removed, modified, current_values))

    return changes


def is_suspicious_registry_entry(value_text):
    normalized = normalize_key(value_text)
    if any(pattern in normalized for pattern in REGISTRY_SAFE_PATTERNS):
        return False
    return any(pattern in normalized for pattern in SUSPICIOUS_REGISTRY_PATTERNS)


def build_display_key(hive, subkey):
    hive_name = "HKLM" if hive == win32con.HKEY_LOCAL_MACHINE else "HKCU"
    return f"{hive_name}\\{subkey}"


def r_mon(stop_event, results, alert_queue=None, interval=config.REGISTRY_MON_INTERVAL):
    """注册表监控主循环。定期扫描指定启动项与服务路径。"""
    logging.info("注册表监控已启动")
    previous_snapshot = {}

    for hive, subkey in MONITORED_REGISTRY:
        previous_snapshot[(hive, subkey)] = read_registry_values(hive, subkey)

    try:
        while not stop_event.is_set():
            time.sleep(interval)
            current_snapshot = {}
            current_changes = []

            for hive, subkey in MONITORED_REGISTRY:
                current_values = read_registry_values(hive, subkey)
                current_snapshot[(hive, subkey)] = current_values

            current_changes = detect_registry_changes(previous_snapshot, current_snapshot)
            for (hive, subkey), added, removed, modified, current_values in current_changes:
                display_key = build_display_key(hive, subkey)
                event_time = time.strftime("%Y-%m-%d %H:%M:%S")
                for name in added:
                    reason = f"新增注册表项: {name}"
                    details = {
                        "time": event_time,
                        "key": display_key,
                        "name": name,
                        "action": "added",
                        "value": current_values.get(name, ""),
                        "reason": reason,
                        "type": "suspicious" if is_suspicious_registry_entry(name + current_values.get(name, "")) else "normal",
                    }
                    results.setdefault("registry_events", []).append(details)
                    logging.warning("注册表新增: %s %s", display_key, name)

                    if alert_queue is not None and details["type"] == "suspicious":
                        alert_queue.put({
                            "category": "registry",
                            "title": "注册表可疑新增",
                            "message": f"{display_key} 增加 {name}",
                            "severity": "critical",
                        })

                for name in removed:
                    details = {
                        "time": event_time,
                        "key": display_key,
                        "name": name,
                        "action": "removed",
                        "value": previous_snapshot[(hive, subkey)].get(name, ""),
                        "reason": f"移除注册表项: {name}",
                        "type": "removed",
                    }
                    results.setdefault("registry_events", []).append(details)
                    logging.info("注册表移除: %s %s", display_key, name)

                for name in modified:
                    before = previous_snapshot[(hive, subkey)].get(name, "")
                    after = current_values.get(name, "")
                    details = {
                        "time": event_time,
                        "key": display_key,
                        "name": name,
                        "action": "modified",
                        "value": after,
                        "reason": f"注册表项修改: {name}",
                        "type": "modified",
                    }
                    results.setdefault("registry_events", []).append(details)
                    logging.warning("注册表修改: %s %s", display_key, name)

                    if alert_queue is not None and is_suspicious_registry_entry(name + after):
                        alert_queue.put({
                            "category": "registry",
                            "title": "注册表可疑修改",
                            "message": f"{display_key} 修改 {name}",
                            "severity": "warning",
                        })

            previous_snapshot = current_snapshot
    finally:
        logging.info("注册表监控已停止")
