#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块名: process_mon.py
功能: Windows 进程监控与阻断
"""

import hashlib
import logging
import os
import re
import time

import pythoncom
import win32api
import win32con
import win32process
from win32com.client import Dispatch
from plyer import notification

import config

WMI = None

SUS_PATH = config.SUS_PATH
SUS_CMD = config.SUS_CMD
SUS_PARENT = config.SUS_PARENT
SUS_STATUS = config.SUS_STATUS
SUS_CPU = config.SUS_CPU
SUS_MEM = config.SUS_MEM
CRITICAL_CPU = config.CRITICAL_CPU
CRITICAL_MEM = config.CRITICAL_MEM
PROCESS_TRUSTED_PATHS = config.PROCESS_TRUSTED_PATHS
PROCESS_SUSPICION_SCORE_THRESHOLD = config.PROCESS_SUSPICION_SCORE_THRESHOLD
PROCESS_CRITICAL_SCORE = config.PROCESS_CRITICAL_SCORE
PROCESS_RESOURCE_SCORE = config.PROCESS_RESOURCE_SCORE
PROCESS_HASH_SCORE = config.PROCESS_HASH_SCORE
PROCESS_CMDLINE_SCORE = config.PROCESS_CMDLINE_SCORE
PROCESS_PARENT_SCORE = config.PROCESS_PARENT_SCORE
PROCESS_PATH_SCORE = config.PROCESS_PATH_SCORE
PROCESS_STATUS_SCORE = config.PROCESS_STATUS_SCORE
PROCESS_SUMMARY_INTERVAL = config.PROCESS_SUMMARY_INTERVAL
INTEGRITY_TARGETS = config.INTEGRITY_TARGETS
SYS_PROCESS_WHITELIST = config.SYS_PROCESS_WHITELIST
PROCESS_TRUSTED_PARENT_NAMES = config.PROCESS_TRUSTED_PARENT_NAMES

INTEGRITY_BASELINE = {}
PROCESS_CPU_HISTORY = {}


def normalize_text(value):
    return str(value).lower().strip() if value else ""


def init_wmi():
    global WMI
    if WMI is None:
        try:
            WMI = Dispatch("WbemScripting.SWbemLocator").ConnectServer(".", "root\\cimv2")
        except Exception:
            WMI = None
    return WMI


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


def is_whitelisted_process(name):
    return normalize_text(name) in SYS_PROCESS_WHITELIST


def is_trusted_parent(name):
    return normalize_text(name) in PROCESS_TRUSTED_PARENT_NAMES


def is_safe_maintenance_process(info):
    if not info["exe_path"]:
        return False
    if not is_trusted_parent(info["pname"]):
        return False
    if any(info["exe_path"].startswith(path) for path in PROCESS_TRUSTED_PATHS):
        return True
    if info["name"] in {"ngentask.exe", "wuauclt.exe", "trustedinstaller.exe", "tiworker.exe"}:
        return True
    return False


def notify(title, message, timeout=5):
    notification.notify(
        title=title,
        message=message.strip(),
        timeout=timeout,
        app_name="WinMonitor",
    )


def query_wmi_process(pid):
    if init_wmi() is None:
        return "", 0
    try:
        items = WMI.ExecQuery(f"SELECT CommandLine, ParentProcessId FROM Win32_Process WHERE ProcessId={pid}")
        for item in items:
            return normalize_text(getattr(item, "CommandLine", "")), int(getattr(item, "ParentProcessId", 0))
    except Exception:
        pass
    return "", 0


def get_process_info(pid):
    info = {
        "pid": pid,
        "name": "",
        "exe_path": "",
        "cmdline": [],
        "ppid": 0,
        "pname": "",
        "status": "",
        "cpu": 0.0,
        "mem": 0.0,
        "hash_mismatch": False,
    }

    handle = None
    try:
        handle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ, False, pid)
        modules = win32process.EnumProcessModules(handle)
        if modules:
            exe = win32process.GetModuleFileNameEx(handle, modules[0])
            info["exe_path"] = normalize_text(exe)
            info["name"] = os.path.basename(exe).lower()

        try:
            mem_info = win32process.GetProcessMemoryInfo(handle)
            info["mem"] = round(mem_info.get("WorkingSetSize", 0) / 1024 ** 2, 2)
        except Exception:
            info["mem"] = 0.0

        try:
            times = win32process.GetProcessTimes(handle)
            cpu_seconds = (times[2] + times[3]) / 10000000.0
            info["cpu"] = compute_cpu_percent(pid, cpu_seconds)
        except Exception:
            info["cpu"] = 0.0
    except Exception:
        pass
    finally:
        if handle:
            try:
                win32api.CloseHandle(handle)
            except Exception:
                pass

    cmdline_text, ppid = query_wmi_process(pid)
    info["cmdline"] = [normalize_text(x) for x in re.split(r"\s+", cmdline_text) if x]
    info["ppid"] = ppid
    if ppid > 0:
        try:
            parent_handle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ, False, ppid)
            parent_modules = win32process.EnumProcessModules(parent_handle)
            if parent_modules:
                info["pname"] = os.path.basename(win32process.GetModuleFileNameEx(parent_handle, parent_modules[0])).lower()
            win32api.CloseHandle(parent_handle)
        except Exception:
            info["pname"] = ""

    if info["exe_path"]:
        normalized_path = os.path.abspath(info["exe_path"]).lower()
        if normalized_path in INTEGRITY_BASELINE:
            current_hash = compute_sha256(normalized_path)
            if current_hash and current_hash != INTEGRITY_BASELINE[normalized_path]:
                info["hash_mismatch"] = True

    return info


def compute_cpu_percent(pid, cpu_seconds):
    timestamp = time.time()
    previous = PROCESS_CPU_HISTORY.get(pid)
    PROCESS_CPU_HISTORY[pid] = {"cpu_seconds": cpu_seconds, "timestamp": timestamp}

    if not previous:
        return 0.0

    elapsed = timestamp - previous["timestamp"]
    if elapsed <= 0:
        return 0.0

    delta = cpu_seconds - previous["cpu_seconds"]
    if delta < 0:
        return 0.0

    cores = os.cpu_count() or 1
    return round((delta / elapsed) / cores * 100.0, 2)


def is_trusted_path(path):
    normalized = os.path.abspath(path).lower()
    return any(normalized.startswith(trusted) for trusted in PROCESS_TRUSTED_PATHS)


def evaluate_suspicion(info):
    score = 0
    reasons = []

    if any(info["exe_path"].startswith(path) for path in SUS_PATH):
        score += PROCESS_PATH_SCORE
        reasons.append("可疑执行路径")

    cmdline_str = " ".join(info["cmdline"])
    if any(key in cmdline_str for key in SUS_CMD):
        score += PROCESS_CMDLINE_SCORE
        reasons.append("命令行可疑")

    if info["pname"] and info["pname"] in SUS_PARENT:
        score += PROCESS_PARENT_SCORE
        reasons.append("父进程异常")

    if info.get("status") in SUS_STATUS:
        score += PROCESS_STATUS_SCORE
        reasons.append(f"异常状态: {info.get('status')}")

    if info["hash_mismatch"]:
        score += PROCESS_HASH_SCORE
        reasons.append("完整性检查失败")

    if info["cpu"] > CRITICAL_CPU and info["mem"] > CRITICAL_MEM:
        score += PROCESS_RESOURCE_SCORE * 2
        reasons.append("严重异常资源占用")
    else:
        if info["cpu"] > SUS_CPU:
            score += PROCESS_RESOURCE_SCORE
            reasons.append(f"CPU 占用高: {info['cpu']:.2f}%")
        if info["mem"] > SUS_MEM:
            score += PROCESS_RESOURCE_SCORE
            reasons.append(f"内存占用高: {info['mem']:.2f}MB")

    if is_whitelisted_process(info["name"]) and not info["hash_mismatch"]:
        if score < PROCESS_CRITICAL_SCORE:
            return []

    if is_safe_maintenance_process(info) and score < PROCESS_SUSPICION_SCORE_THRESHOLD:
        return []

    if is_trusted_path(info["exe_path"]) and score < PROCESS_SUSPICION_SCORE_THRESHOLD:
        return []

    return reasons if score >= PROCESS_SUSPICION_SCORE_THRESHOLD else []


def build_alert_message(info, reasons):
    lines = [f"pid: {info['pid']}", f"name: {info['name']}"]
    if info["exe_path"]:
        lines.append(f"path: {info['exe_path']}")
    if info["ppid"]:
        lines.append(f"parent: {info['ppid']} / {info['pname']}")
    if info["cpu"]:
        lines.append(f"cpu: {info['cpu']:.2f}%")
    if info["mem"]:
        lines.append(f"mem: {info['mem']:.2f}MB")
    lines.append("原因:")
    lines.extend(reasons)
    return "\n".join(lines)


def block_process(pid, reason):
    try:
        handle = win32api.OpenProcess(win32con.PROCESS_TERMINATE | win32con.PROCESS_QUERY_INFORMATION, False, pid)
        win32process.TerminateProcess(handle, 1)
        win32api.CloseHandle(handle)
        logging.warning("已阻断可疑进程 pid=%s, 原因=%s", pid, reason)
        return True
    except Exception as exc:
        logging.debug("阻断进程失败 pid=%s: %s", pid, exc)
        return False


def report_process_changes(new_pids, gone_pids):
    if not new_pids and not gone_pids:
        return
    summary_parts = []
    if new_pids:
        summary_parts.append(f"New: {len(new_pids)}")
    if gone_pids:
        summary_parts.append(f"Gone: {len(gone_pids)}")
    message = "  ".join(summary_parts)
    logging.info("Process change summary: %s", message)
    notify("WinMonitor 进程变化", message)


def inspect_new_processes(processes, new_pids, results, alert_queue=None):
    for pid in new_pids:
        info = get_process_info(pid)
        if not info["name"]:
            continue
        reasons = evaluate_suspicion(info)
        detail = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "pid": info["pid"],
            "name": info["name"],
            "exe_path": info["exe_path"],
            "ppid": info["ppid"],
            "pname": info["pname"],
            "cpu": info["cpu"],
            "mem": info["mem"],
            "cmdline": info["cmdline"],
            "reasons": reasons,
        }

        if reasons:
            results.setdefault("process_events", []).append(detail)
            logging.warning("可疑进程: %s %s", pid, "; ".join(reasons))
            if alert_queue is not None:
                alert_queue.put({
                    "category": "process",
                    "title": "进程可疑告警",
                    "message": build_alert_message(info, reasons),
                    "severity": "critical",
                })
            if not is_whitelisted_process(info["name"]) and (info["cpu"] > CRITICAL_CPU or info["mem"] > CRITICAL_MEM or info["hash_mismatch"]):
                block_process(pid, "; ".join(reasons))
        else:
            logging.debug("正常进程启动已过滤: %s (%s)", pid, info["name"])


def p_mon(stop_event, results, alert_queue=None, interval=config.PROCESS_MON_INTERVAL):
    pythoncom.CoInitialize()
    try:
        init_wmi()
        build_integrity_baseline()
        previous_pids = set()
        pending_new_pids = set()
        pending_gone_pids = set()
        last_summary_time = time.monotonic()
        logging.info("进程监控已启动")
        try:
            while not stop_event.is_set():
                try:
                    process_ids = win32process.EnumProcesses()
                except Exception as exc:
                    logging.debug("无法枚举进程: %s", exc)
                    time.sleep(interval)
                    continue

                current_pids = set(process_ids)
                new_pids = current_pids - previous_pids
                gone_pids = previous_pids - current_pids
                if new_pids:
                    pending_new_pids.update(new_pids)
                if gone_pids:
                    pending_gone_pids.update(gone_pids)

                inspect_new_processes({}, new_pids, results, alert_queue)
                previous_pids = current_pids

                now = time.monotonic()
                if now - last_summary_time >= PROCESS_SUMMARY_INTERVAL:
                    if pending_new_pids or pending_gone_pids:
                        report_process_changes(pending_new_pids, pending_gone_pids)
                        pending_new_pids.clear()
                        pending_gone_pids.clear()
                    last_summary_time = now

                time.sleep(interval)

            if pending_new_pids or pending_gone_pids:
                report_process_changes(pending_new_pids, pending_gone_pids)
        finally:
            logging.info("进程监控已停止")
    finally:
        try:
            pythoncom.CoUninitialize()
        except Exception:
            pass
