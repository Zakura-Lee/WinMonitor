#!/usr/bin/env python3.14
# -*- coding: utf-8 -*-
"""
模块名: file_mon.py
功能: windows文件监控
"""

import logging
import os
import time

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

IGNORE_EXTENSIONS = {
    ".tmp",
    ".swp",
    ".log",
    ".lock",
}

IGNORE_DIRECTORIES = {
    "__pycache__",
    ".git",
    "node_modules",
}

DANGEROUS_FILE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".jar",
}

WHITELISTED_CACHE_PATTERNS = [
    "\\tencent\\wechat",
    "\\wechat\\",
    "\\appdata\\local\\temp",
    "\\windows\\temp",
    "\\google\\chrome\\user data",
    "\\microsoft\\edge\\user data",
    "\\mozilla\\firefox\\profiles",
    "\\cache\\",
    "\\cache2\\",
]

SYSTEM_MAINTENANCE_PATTERNS = [
    "\\windows\\softwaredistribution",
    "\\windows\\winsxs",
    "\\windows\\servicing",
    "\\windows\\system32\\config",
    "\\programdata\\microsoft\\windows\\updates",
    "\\windows\\softwaredistribution\\download",
]

WINDOWS_SYSTEM_PATTERNS = [
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\windows\\system\\",
]


def is_whitelisted_cache_path(path):
    # 判断是否位于微信、浏览器缓存或临时目录，属于白名单路径
    if not path:
        return False
    normalized = path.lower().replace("/", "\\")
    if "tencent\\wechat" in normalized:
        return True
    if "appdata\\local\\temp" in normalized:
        return True
    if "windows\\temp" in normalized:
        return True
    if "google\\chrome\\user data" in normalized and "cache" in normalized:
        return True
    if "microsoft\\edge\\user data" in normalized and "cache" in normalized:
        return True
    if "mozilla\\firefox\\profiles" in normalized and "cache" in normalized:
        return True
    return False


def is_system_maintenance_path(path):
    if not path:
        return False
    normalized = path.lower().replace("/", "\\")
    return any(pattern in normalized for pattern in SYSTEM_MAINTENANCE_PATTERNS)


def is_windows_system_path(path):
    if not path:
        return False
    normalized = path.lower().replace("/", "\\")
    return any(pattern in normalized for pattern in WINDOWS_SYSTEM_PATTERNS)


def should_ignore_path(path):
    # 判断路径是否属于忽略清单，例如临时缓存、日志文件或常见开发目录
    if not path:
        return True
    if is_whitelisted_cache_path(path):
        return True
    lower_path = path.lower()
    if any(lower_path.endswith(ext) for ext in IGNORE_EXTENSIONS):
        return True
    if any(part in IGNORE_DIRECTORIES for part in lower_path.replace("\\", "/").split("/")):
        return True
    return False


def is_dangerous_file(path):
    if not path:
        return False
    return any(path.lower().endswith(ext) for ext in DANGEROUS_FILE_EXTENSIONS)


def get_windows_drives():
    # 枚举当前系统的所有可用驱动器，用于全盘文件监控
    drives = []
    if os.name != "nt":
        return drives

    try:
        import ctypes
        import string

        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for letter in string.ascii_uppercase:
            if bitmask & 1:
                drives.append(f"{letter}:\\")
            bitmask >>= 1
    except Exception:
        return drives

    return drives


def get_monitor_paths(monitor_path=None):
    # 返回需要观察的目录列表，默认情况下 Windows 监听所有可用驱动器
    if monitor_path:
        return [os.path.abspath(monitor_path)]

    if os.name == "nt":
        return [drive for drive in get_windows_drives() if os.path.isdir(drive)]

    return [os.path.abspath(os.sep)]


class FileMonitorHandler(FileSystemEventHandler):
    """处理文件系统事件并将记录存储到共享结果集中。"""
    def __init__(self, results, alert_queue=None):
        self.results = results
        self.alert_queue = alert_queue

    def on_created(self, event):
        self.record("created", event.src_path)

    def on_modified(self, event):
        self.record("modified", event.src_path)

    def on_deleted(self, event):
        self.record("deleted", event.src_path)

    def on_moved(self, event):
        self.record("moved", event.src_path, event.dest_path)

    def record(self, action, path, dest_path=None):
        # 处理文件系统事件，生成统一记录并判断是否需要告警
        if should_ignore_path(path):
            return

        normalized_path = os.path.abspath(path)
        details = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "action": action,
            "path": normalized_path,
            "type": "normal",
        }
        if dest_path and not should_ignore_path(dest_path):
            details["destination"] = os.path.abspath(dest_path)

        if is_windows_system_path(normalized_path):
            # Windows 系统文件操作属于正常系统维护，不弹窗告警，仅记录日志
            details["reason"] = "Windows 系统文件操作，记录日志不警报"
        elif is_system_maintenance_path(normalized_path):
            details["reason"] = "系统维护路径文件操作，记录日志不警报"
        elif is_dangerous_file(normalized_path):
            details["type"] = "danger"
            details["reason"] = f"危险文件操作: {action}"

        self.results.setdefault("file_events", []).append(details)
        logging.info("文件 %s: %s", action, details["path"])

        if details["type"] == "danger" and self.alert_queue is not None:
            self.alert_queue.put({
                "category": "file",
                "title": "危险文件操作",
                "message": f"{action} {details['path']}",
                "severity": "critical",
            })


def f_mon(stop_event, results, alert_queue=None, monitor_path=None):
    # 启动文件监控观察者，注册所有待监控路径并进入事件循环
    monitor_paths = get_monitor_paths(monitor_path)
    handler = FileMonitorHandler(results, alert_queue)
    observer = Observer()

    scheduled_count = 0
    for path in monitor_paths:
        try:
            observer.schedule(handler, path, recursive=True)
            logging.info("文件监控已启动，目录: %s", path)
            scheduled_count += 1
        except Exception as exc:
            logging.warning("无法监听目录 %s: %s", path, exc)

    if scheduled_count == 0:
        logging.error("未能启动任何文件监控目录，请检查权限或路径")
        return

    observer.start()

    try:
        while not stop_event.is_set():
            time.sleep(0.5)
    finally:
        observer.stop()
        observer.join()
        logging.info("文件监控已停止")
