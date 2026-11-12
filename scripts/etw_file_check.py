#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
文件采集验证（需管理员权限）

用 Sysmon 的 FileCreate(11) / FileDelete(23) 验证文件链路：
采集期间在临时目录写入几个无害探针文件，其中一个伪装成可执行扩展名，
用于触发风险分类。

用法（管理员）:
    python scripts/etw_file_check.py
"""

import os
import sys
import tempfile
import threading
import time
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from core.monitor import MonitorService


def _probe():
    """在临时目录制造文件创建与删除。"""
    stamp = uuid.uuid4().hex[:8]
    temp_dir = tempfile.gettempdir()
    created = []
    for name in (f"wm_probe_{stamp}.txt", f"wm_probe_{stamp}.exe", f"wm_probe_{stamp}.ps1"):
        path = os.path.join(temp_dir, name)
        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("winmonitor probe\n")
            created.append(path)
        except OSError:
            pass

    time.sleep(1.0)
    for path in created:
        try:
            os.remove(path)
        except OSError:
            pass


def main():
    service = MonitorService()
    started = service._start_etw_backend(service.process_data, service.alert_queue)
    print(f"[INFO] ETW 后端启动 = {started}   主提供者 = {service.etw_primary}")
    if not started:
        print(f"[INFO] 回退原因 = {service.etw_fallback_reason}")
        return 0

    print("[INFO] 采集 8 秒，期间在临时目录创建 3 个探针文件并删除 ...")
    threading.Thread(target=_probe, daemon=True).start()
    time.sleep(8)

    events = service.file_events
    print()
    print("=" * 62)
    print(f"文件事件条数: {len(events)}")
    for entry in events[:10]:
        print(
            f"    [{entry['type']}] {entry['action']:7s} "
            f"{entry['process_name'] or '-':16s} {entry['path']}"
        )
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
    probes = [e for e in events if "wm_probe_" in e["path"]]
    if probes:
        print(f"结论: 捕获到 {len(probes)} 条探针文件事件。")
    else:
        print("结论: 没有捕获到探针文件事件，检查 Sysmon 是否启用了 FileCreate。")
    return 0 if probes else 7


if __name__ == "__main__":
    sys.exit(main())
