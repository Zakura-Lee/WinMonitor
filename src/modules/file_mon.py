#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块名: file_mon.py
功能: Windows 文件监控与完整性检查
"""

import hashlib
import logging
import os
import time

import pythoncom
from win32com.client import Dispatch
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

import config

IGNORE_EXTENSIONS = config.IGNORE_EXTENSIONS
IGNORE_DIRECTORIES = config.IGNORE_DIRECTORIES
DANGEROUS_FILE_EXTENSIONS = config.DANGEROUS_FILE_EXTENSIONS
INTEGRITY_TARGETS = config.INTEGRITY_TARGETS

INTEGRITY_BASELINE = {}

WHITELISTED_CACHE_PATTERNS = config.WHITELISTED_CACHE_PATTERNS
SYSTEM_MAINTENANCE_PATTERNS = config.SYSTEM_MAINTENANCE_PATTERNS
WINDOWS_SYSTEM_PATTERNS = config.WINDOWS_SYSTEM_PATTERNS
FILE_MONITOR_TRUSTED_PATHS = config.FILE_MONITOR_TRUSTED_PATHS
FILE_MONITOR_SENSITIVE_PATHS = config.FILE_MONITOR_SENSITIVE_PATHS
IGNORED_FILENAME_PATTERNS = config.IGNORED_FILENAME_PATTERNS
FILE_MONITOR_EVENT_SCORE_THRESHOLD = config.FILE_MONITOR_EVENT_SCORE_THRESHOLD


def compute_sha256(path):
    try:
        with open(path, "rb") as f:
            digest = hashlib.sha256()
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                digest.update(chunk)
            return digest.hexdigest()
    except Exception:
        return ""


def build_integrity_baseline():
    for path in INTEGRITY_TARGETS:
        try:
            normalized = os.path.abspath(path).lower()
            if os.path.isfile(normalized):
                INTEGRITY_BASELINE[normalized] = compute_sha256(normalized)
        except Exception:
            continue


def is_whitelisted_cache_path(path):
    if not path:
        return False
    normalized = path.lower().replace("/", "\\")
    return any(pattern in normalized for pattern in WHITELISTED_CACHE_PATTERNS)


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


def is_trusted_path(path):
    if not path:
        return False
    normalized = os.path.abspath(path).lower().replace("/", "\\")
    return any(normalized.startswith(trusted) for trusted in FILE_MONITOR_TRUSTED_PATHS)


def is_sensitive_path(path):
    if not path:
        return False
    normalized = os.path.abspath(path).lower().replace("/", "\\")
    return any(normalized.startswith(sensitive) for sensitive in FILE_MONITOR_SENSITIVE_PATHS)


def _calculate_file_risk(action, path, dest_path, integrity_mismatch):
    score = 0
    reason_parts = []
    if integrity_mismatch:
        score += 3
        reason_parts.append("关键文件完整性异常")

    ext = os.path.splitext(path)[1].lower()
    if ext in DANGEROUS_FILE_EXTENSIONS:
        score += 2
        reason_parts.append(f"可疑扩展 {ext}")

    if is_windows_system_path(path):
        score += 1
        reason_parts.append("系统路径文件操作")

    if is_sensitive_path(path):
        score += 1
        reason_parts.append("敏感路径文件操作")

    if dest_path and not should_ignore_path(dest_path):
        dest_normalized = os.path.abspath(dest_path)
        if os.path.splitext(dest_normalized)[1].lower() in DANGEROUS_FILE_EXTENSIONS:
            score += 1
            reason_parts.append("移动到可疑目标文件")

    if is_trusted_path(path) and score < FILE_MONITOR_EVENT_SCORE_THRESHOLD:
        return 0, []

    return score, reason_parts


def should_ignore_path(path):
    if not path:
        return True
    normalized = path.lower().replace("/", "\\")
    if is_whitelisted_cache_path(path):
        return True
    if os.path.basename(normalized) in IGNORED_FILENAME_PATTERNS:
        return True
    if any(normalized.endswith(ext) for ext in IGNORE_EXTENSIONS):
        return True
    if any(part in IGNORE_DIRECTORIES for part in normalized.replace("\\", "/").split("/")):
        return True
    return False


def is_dangerous_file(path):
    if not path:
        return False
    return any(path.lower().endswith(ext) for ext in DANGEROUS_FILE_EXTENSIONS)


def normalize_text(value):
    return str(value).lower().strip() if value else ""


def _is_trusted_dotnet_parent():
    try:
        pythoncom.CoInitialize()
        try:
            wmi = Dispatch("WbemScripting.SWbemLocator").ConnectServer(".", "root\\cimv2")
            ngen_processes = wmi.ExecQuery("SELECT Name FROM Win32_Process WHERE Name='ngentask.exe'")
            for _ in ngen_processes:
                return True

            dotnet_services = wmi.ExecQuery(
                "SELECT Name, ProcessId, State FROM Win32_Service WHERE Name LIKE 'clr_optimization_v4.0.30319%'"
            )
            for svc in dotnet_services:
                state = normalize_text(getattr(svc, "State", ""))
                pid = int(getattr(svc, "ProcessId", 0))
                if state == "running" and pid > 0:
                    return True
        finally:
            try:
                pythoncom.CoUninitialize()
            except Exception:
                pass
    except Exception as exc:
        logging.debug("检查 .NET 优化父进程失败: %s", exc)
    return False


def _is_system32_core_dll(path):
    if not path:
        return False
    normalized = os.path.abspath(path).lower().replace("/", "\\")
    system_root = os.environ.get("SystemRoot", r"C:\\Windows").lower().replace("/", "\\")
    system32_root = os.path.join(system_root, "System32").lower().replace("/", "\\")
    return normalized.startswith(system32_root) and normalized.endswith(".dll")


def _is_dotnet_framework_path(path):
    if not path:
        return False
    normalized = os.path.abspath(path).lower().replace("/", "\\")
    return normalized.startswith(r"c:\\windows\\microsoft.net\\framework64\\v4.0.30319\\") or normalized.startswith(r"c:\\windows\\microsoft.net\\framework\\")


def _is_office_wps_path(path):
    if not path:
        return False
    normalized = os.path.abspath(path).lower().replace("/", "\\")
    return normalized.startswith(r"d:\\wps office\\") or normalized.startswith(r"c:\\program files (x86)\\microsoft office\\")


def _is_trusted_update_parent():
    try:
        pythoncom.CoInitialize()
        try:
            wmi = Dispatch("WbemScripting.SWbemLocator").ConnectServer(".", "root\\cimv2")
            
            services = wmi.ExecQuery("SELECT Name, State, ProcessId FROM Win32_Service WHERE Name='wuauserv'")
            for svc in services:
                if normalize_text(getattr(svc, "State", "")) == "running":
                    parent_pid = int(getattr(svc, "ProcessId", 0))
                    if parent_pid > 0:
                        procs = wmi.ExecQuery(f"SELECT Name FROM Win32_Process WHERE ProcessId={parent_pid}")
                        for proc in procs:
                            if normalize_text(getattr(proc, "Name", "")) == "svchost.exe":
                                return True
            
            tiworkers = wmi.ExecQuery("SELECT Name FROM Win32_Process WHERE Name='TiWorker.exe'")
            for _ in tiworkers:
                return True
            
            trusted_procs = wmi.ExecQuery("SELECT Name FROM Win32_Process WHERE Name IN ('TrustedInstaller.exe', 'ngentask.exe', 'msiexec.exe')")
            for proc in trusted_procs:
                if normalize_text(getattr(proc, "Name", "")) in {"trustedinstaller.exe", "ngentask.exe", "msiexec.exe"}:
                    return True
            
            defender_services = wmi.ExecQuery("SELECT Name, State FROM Win32_Service WHERE Name LIKE '%Defender%' OR Name LIKE '%Wd%'")
            for svc in defender_services:
                if normalize_text(getattr(svc, "State", "")) == "running":
                    return True
                    
        finally:
            try:
                pythoncom.CoUninitialize()
            except Exception:
                pass
    except Exception as exc:
        logging.debug("检查系统更新进程失败: %s", exc)
    return False


def check_integrity(path):
    normalized = os.path.abspath(path).lower()
    if normalized not in INTEGRITY_BASELINE or not os.path.isfile(normalized):
        return False, ""
    current_hash = compute_sha256(normalized)
    if not current_hash:
        return False, ""
    return current_hash != INTEGRITY_BASELINE[normalized], current_hash


def get_windows_drives():
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
        build_integrity_baseline()

    def on_created(self, event):
        self.record("created", event.src_path)

    def on_modified(self, event):
        self.record("modified", event.src_path)

    def on_deleted(self, event):
        self.record("deleted", event.src_path)

    def on_moved(self, event):
        self.record("moved", event.src_path, event.dest_path)

    def record(self, action, path, dest_path=None):
        if should_ignore_path(path):
            return

        normalized_path = os.path.abspath(path)
        details = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "action": action,
            "path": normalized_path,
            "type": "normal",
            "reason": "",
        }

        if dest_path and not should_ignore_path(dest_path):
            details["destination"] = os.path.abspath(dest_path)

        integrity_mismatch, current_hash = check_integrity(normalized_path)

        if _is_office_wps_path(normalized_path):
            details["type"] = "normal"
            details["reason"] = "Office/WPS 安装目录文件变动，白名单放行"
            self.results.setdefault("file_events", []).append(details)
            logging.info("信任 Office/WPS 目录文件变动: %s", normalized_path)
            return

        if _is_system32_core_dll(normalized_path):
            if _is_trusted_update_parent():
                details["type"] = "normal"
                details["reason"] = "System32 核心 DLL 修改由 Windows Update/TrustedInstaller 正常执行，记录日志不警报"
                self.results.setdefault("file_events", []).append(details)
                logging.info("信任 System32 核心 DLL 修改: %s", normalized_path)
                return
            details["type"] = "danger"
            details["reason"] = "System32 核心 DLL 异常修改，父进程非 svchost(wuauserv) 或 TiWorker"
            details["hash_before"] = INTEGRITY_BASELINE.get(normalized_path, "")
            details["hash_after"] = current_hash
            self.results.setdefault("file_events", []).append(details)
            logging.warning("核心 DLL 异常修改: %s", normalized_path)
            if self.alert_queue is not None:
                self.alert_queue.put({
                    "category": "file",
                    "title": "文件完整性告警",
                    "message": f"{action} {details['path']} {details['reason']}",
                    "severity": "critical",
                })
            return

        if _is_dotnet_framework_path(normalized_path):
            if _is_trusted_dotnet_parent():
                details["type"] = "normal"
                details["reason"] = ".NET 框架目录文件修改由 svchost/ngentask 正常执行，记录日志不警报"
                self.results.setdefault("file_events", []).append(details)
                logging.info("信任 .NET 框架目录修改: %s", normalized_path)
                return
            details["type"] = "danger"
            details["reason"] = ".NET 框架目录文件修改父进程非 svchost/ngentask，可能异常"
            details["hash_before"] = INTEGRITY_BASELINE.get(normalized_path, "")
            details["hash_after"] = current_hash
            self.results.setdefault("file_events", []).append(details)
            logging.warning("异常 .NET 框架目录修改: %s", normalized_path)
            if self.alert_queue is not None:
                self.alert_queue.put({
                    "category": "file",
                    "title": "文件安全警告",
                    "message": f"{action} {details['path']} {details['reason']}",
                    "severity": "critical",
                })
            return

        risk_score, risk_reasons = _calculate_file_risk(action, normalized_path, dest_path, integrity_mismatch)
        if integrity_mismatch:
            details["type"] = "integrity"
            details["reason"] = "系统关键文件完整性校验失败"
            details["hash_before"] = INTEGRITY_BASELINE.get(normalized_path, "")
            details["hash_after"] = current_hash
            self.results.setdefault("integrity_events", []).append(details)

        if details["type"] != "integrity":
            if is_windows_system_path(normalized_path):
                details["reason"] = details.get("reason", "") or "Windows 系统文件操作，记录日志不警报"
            elif is_system_maintenance_path(normalized_path):
                details["reason"] = details.get("reason", "") or "系统维护路径文件操作，记录日志不警报"
            elif risk_score >= FILE_MONITOR_EVENT_SCORE_THRESHOLD:
                details["type"] = "danger"
                details["reason"] = details.get("reason", "") or "; ".join(risk_reasons)
            elif is_dangerous_file(normalized_path) and is_sensitive_path(normalized_path):
                details["type"] = "danger"
                details["reason"] = details.get("reason", "") or f"敏感路径可疑文件操作: {action}"
            else:
                details["type"] = "normal"

        self.results.setdefault("file_events", []).append(details)
        logging.info("文件 %s: %s", action, details["path"])

        if details["type"] in {"danger", "integrity"} and self.alert_queue is not None:
            self.alert_queue.put({
                "category": "file",
                "title": "文件安全警告",
                "message": f"{action} {details['path']} {details['reason']}",
                "severity": "critical" if details["type"] == "integrity" else "warning",
            })


def f_mon(stop_event, results, alert_queue=None, monitor_path=None):
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
