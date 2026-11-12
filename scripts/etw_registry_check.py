#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
注册表采集验证（需管理员权限）

用 Sysmon 的 RegistryEvent 验证注册表链路。
采集期间在当前用户的自启动项里写入一个探针值，1 秒后删除，
不会留下任何残留。

用法（管理员）:
    python scripts/etw_registry_check.py
"""

import os
import sys
import threading
import time
import winreg

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from core.monitor import MonitorService

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
VALUE_NAME = "WinMonitorProbe"


def _probe():
    """写入再删除一个自启动值，模拟持久化行为。"""
    try:
        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE
        ) as key:
            winreg.SetValueEx(
                key,
                VALUE_NAME,
                0,
                winreg.REG_SZ,
                r'C:\Windows\System32\cmd.exe /c echo winmonitor-probe',
            )
    except OSError as exc:
        print("  写入探针值失败:", exc)
        return

    time.sleep(1.0)

    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE
        ) as key:
            winreg.DeleteValue(key, VALUE_NAME)
    except OSError as exc:
        print("  清理探针值失败:", exc)


def main():
    service = MonitorService()
    started = service._start_etw_backend(service.process_data, service.alert_queue)
    print(f"[INFO] ETW 后端启动 = {started}   主提供者 = {service.etw_primary}")
    if not started:
        print(f"[INFO] 回退原因 = {service.etw_fallback_reason}")
        return 0

    print("[INFO] 采集 8 秒，期间在 HKCU Run 写入并删除一个探针值 ...")
    threading.Thread(target=_probe, daemon=True).start()
    time.sleep(8)

    events = service.registry_events
    print()
    print("=" * 62)
    print(f"注册表事件条数: {len(events)}")
    for entry in events[:10]:
        print(f"    [{entry['type']}] {entry['action'] or '-':12s} {entry['key']}")
        if entry["value"]:
            print(f"        value = {entry['value']}")
        if entry["reason"] and entry["type"] != "normal":
            print(f"        {entry['reason']}")

    collector = service.etw_collector
    if collector is not None:
        stats = collector.stats()
        print()
        print(f"采集统计: handled={stats.get('handled')}  解码异常={stats.get('decode_errors')}")
        counts = stats.get("event_counts") or {}
        for key, count in counts.items():
            print(f"    {key}: {count}")

    service._stop_etw_backend()

    print()
    probes = [e for e in events if VALUE_NAME in (e["key"] or "")]
    if probes:
        print(f"结论: 捕获到 {len(probes)} 条探针注册表事件。")
    else:
        print("结论: 没有捕获到探针事件，检查 Sysmon 是否启用了 RegistryEvent。")
    return 0 if probes else 7


if __name__ == "__main__":
    sys.exit(main())
