#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块名: network_mon.py
功能: Windows 网络连接监控与阻断
"""

import logging
import re
import socket
import subprocess
import time

import pythoncom
import win32api
import win32con
import win32process
from win32com.client import Dispatch

import config
from modules.process_mon import normalize_text

WMI = None
WMI_STD = None

HIGH_RISK_REMOTE_PORTS = config.HIGH_RISK_REMOTE_PORTS
SQL_REMOTE_PORTS = config.SQL_REMOTE_PORTS
ATTACK_STATUSES = config.ATTACK_STATUSES
SAFE_PUBLIC_PORTS = config.SAFE_PUBLIC_PORTS
PRIVATE_PREFIXES = config.PRIVATE_PREFIXES
NETWORK_TRUSTED_PROCESS_NAMES = config.NETWORK_TRUSTED_PROCESS_NAMES
NETWORK_TRUSTED_PROCESS_PATHS = config.NETWORK_TRUSTED_PROCESS_PATHS
NETWORK_TRUSTED_REMOTE_HOST_PATTERNS = config.NETWORK_TRUSTED_REMOTE_HOST_PATTERNS
NETWORK_SUSPICION_SCORE_THRESHOLD = config.NETWORK_SUSPICION_SCORE_THRESHOLD
NETWORK_HIGH_RISK_SCORE = config.NETWORK_HIGH_RISK_SCORE
NETWORK_STATUS_SCORE = config.NETWORK_STATUS_SCORE
NETWORK_PROCESS_SCORE = config.NETWORK_PROCESS_SCORE
NETWORK_REMOTE_SCORE = config.NETWORK_REMOTE_SCORE
TEMP_PATH_PATTERNS = config.TEMP_PATH_PATTERNS
SUSPICIOUS_PARENT_NAMES = config.SUSPICIOUS_PARENT_NAMES
REMOTE_HOST_CACHE = {}


def _is_public_address(remote):
    if not remote:
        return False
    address = remote.split(":")[0]
    return not address.startswith(PRIVATE_PREFIXES)


def _get_remote_port(remote):
    try:
        return int(remote.split(":")[-1])
    except (ValueError, IndexError):
        return 0


def _normalize_path(path):
    if not path:
        return ""
    return path.lower().replace("/", "\\")


def _build_connection_from_wmi_event(event):
    target = getattr(event, "TargetInstance", None)
    if target is None:
        return None

    pid = int(getattr(target, "OwningProcess", 0))
    local_address = normalize_text(getattr(target, "LocalAddress", ""))
    local_port = getattr(target, "LocalPort", "")
    remote_address = normalize_text(getattr(target, "RemoteAddress", ""))
    remote_port = getattr(target, "RemotePort", "")
    status = normalize_text(getattr(target, "State", ""))

    local = f"{local_address}:{local_port}"
    remote = f"{remote_address}:{remote_port}"
    return pid, local, remote, status


def _subscribe_network_events():
    if WMI_STD is None:
        return None
    try:
        query = "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'MSFT_NetTCPConnection'"
        return WMI_STD.ExecNotificationQuery(query)
    except Exception as exc:
        logging.info("WMI 实时网络事件订阅不可用，回退到轮询模式: %s", exc)
        return None


def _fetch_wmi_connections():
    connections = set()
    if WMI_STD is None:
        return connections
    try:
        items = WMI_STD.ExecQuery("SELECT * FROM MSFT_NetTCPConnection")
        for item in items:
            pid = int(getattr(item, "OwningProcess", 0))
            local = f"{normalize_text(getattr(item, 'LocalAddress', ''))}:{getattr(item, 'LocalPort', '')}"
            remote = f"{normalize_text(getattr(item, 'RemoteAddress', ''))}:{getattr(item, 'RemotePort', '')}"
            status = normalize_text(getattr(item, "State", ""))
            connections.add((pid, local, remote, status))
    except Exception as exc:
        logging.debug("WMI 连接轮询失败: %s", exc)
    return connections


def _resolve_remote_hostname(address):
    if not address or address in {"*", "0.0.0.0", "::"}:
        return ""
    if address in REMOTE_HOST_CACHE:
        return REMOTE_HOST_CACHE[address]
    try:
        hostname = socket.gethostbyaddr(address)[0].lower()
    except Exception:
        hostname = ""
    REMOTE_HOST_CACHE[address] = hostname
    return hostname


def init_wmi():
    global WMI, WMI_STD
    if WMI is None:
        try:
            WMI = Dispatch("WbemScripting.SWbemLocator").ConnectServer(".", "root\\cimv2")
        except Exception:
            WMI = None
    if WMI_STD is None:
        try:
            WMI_STD = Dispatch("WbemScripting.SWbemLocator").ConnectServer(".", "root\\StandardCimv2")
        except Exception:
            WMI_STD = None
    return WMI, WMI_STD


def _is_trusted_remote_host(remote):
    if not remote or ":" not in remote:
        return False
    address = remote.split(":")[0]
    hostname = _resolve_remote_hostname(address)
    if not hostname:
        return False
    return any(pattern in hostname for pattern in NETWORK_TRUSTED_REMOTE_HOST_PATTERNS)


def _get_process_context(pid):
    context = {
        "pid": pid,
        "name": "",
        "exe_path": "",
        "parent_name": "",
        "is_temp_path": False,
        "has_suspicious_parent": False,
    }

    if pid <= 0:
        return context

    try:
        items = WMI.ExecQuery(f"SELECT Name, ExecutablePath, ParentProcessId FROM Win32_Process WHERE ProcessId={pid}")
        for item in items:
            context["name"] = normalize_text(getattr(item, "Name", ""))
            context["exe_path"] = _normalize_path(getattr(item, "ExecutablePath", ""))
            parent_pid = int(getattr(item, "ParentProcessId", 0))
            if parent_pid > 0:
                try:
                    parent_items = WMI.ExecQuery(f"SELECT Name FROM Win32_Process WHERE ProcessId={parent_pid}")
                    for parent in parent_items:
                        context["parent_name"] = normalize_text(getattr(parent, "Name", ""))
                except Exception:
                    context["parent_name"] = ""
            break
    except Exception:
        return context

    normalized_exe = context["exe_path"]
    context["is_temp_path"] = any(part in normalized_exe for part in TEMP_PATH_PATTERNS)
    context["has_suspicious_parent"] = context["parent_name"] in SUSPICIOUS_PARENT_NAMES
    return context


def _is_trusted_process_context(context):
    if context["name"] in NETWORK_TRUSTED_PROCESS_NAMES:
        return True
    if context["parent_name"] in NETWORK_TRUSTED_PROCESS_NAMES:
        return True
    if any(context["exe_path"].startswith(path) for path in NETWORK_TRUSTED_PROCESS_PATHS):
        return True
    return False


def _is_suspicious_process(context):
    if _is_trusted_process_context(context):
        return False
    return context["is_temp_path"] or context["has_suspicious_parent"]


def _network_risk_score(context, remote_port, status, is_external):
    score = 0
    if not _is_trusted_process_context(context):
        if context["is_temp_path"] or context["has_suspicious_parent"]:
            score += NETWORK_PROCESS_SCORE
    if remote_port in HIGH_RISK_REMOTE_PORTS or remote_port in SQL_REMOTE_PORTS:
        score += NETWORK_REMOTE_SCORE
    if status in ATTACK_STATUSES and is_external:
        score += NETWORK_STATUS_SCORE
    return score


def block_network_process(pid, reason):
    try:
        handle = win32api.OpenProcess(win32con.PROCESS_TERMINATE | win32con.PROCESS_QUERY_INFORMATION, False, pid)
        win32process.TerminateProcess(handle, 1)
        win32api.CloseHandle(handle)
        logging.warning("已阻断可疑网络进程 pid=%s, 原因=%s", pid, reason)
        return True
    except Exception as exc:
        logging.debug("阻断网络进程失败 pid=%s: %s", pid, exc)
        return False


def _parse_netstat():
    connections = set()
    try:
        proc = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, errors="ignore", shell=False, timeout=10)
        lines = proc.stdout.splitlines()
        for line in lines:
            line = line.strip()
            if not line or not (line.startswith("TCP") or line.startswith("UDP")):
                continue
            # 使用正则表达式更健壮地解析
            match = re.match(r'(TCP|UDP)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s*(.*)', line)
            if match:
                proto, local, remote, status, pid = match.groups()
                if proto == "UDP" and not status:
                    status = "NONE"
                    pid = remote  # 对于 UDP，pid 在 remote 位置
                    remote = "*:*"
                try:
                    pid = int(pid)
                except ValueError:
                    pid = 0
                connections.add((pid, local, remote, status))
            else:
                logging.debug("无法解析 netstat 行: %s", line)
    except subprocess.TimeoutExpired:
        logging.warning("netstat 命令超时")
    except Exception as exc:
        logging.debug("解析 netstat 输出失败: %s", exc)
    return connections


def n_mon(stop_event, results, alert_queue=None):
    previous_connections = set()
    syn_sent_history = {}
    logging.info("网络监控已启动")
    pythoncom.CoInitialize()
    try:
        init_wmi()
        event_source = _subscribe_network_events()

        while not stop_event.is_set():
            if event_source is not None:
                try:
                    event = event_source.NextEvent(1000)
                    conn = _build_connection_from_wmi_event(event)
                    current_connections = {conn} if conn else set()
                except Exception:
                    current_connections = set()
            else:
                if WMI_STD is not None:
                    current_connections = _fetch_wmi_connections()
                    if not current_connections:
                        current_connections = _parse_netstat()
                else:
                    current_connections = _parse_netstat()

            now = time.monotonic()
            for pid, timestamps in list(syn_sent_history.items()):
                syn_sent_history[pid] = [ts for ts in timestamps if now - ts <= 1.0]
                if not syn_sent_history[pid]:
                    del syn_sent_history[pid]

            new_connections = current_connections - previous_connections
            for pid, local, remote, status in new_connections:
                remote_port = _get_remote_port(remote)
                is_external = _is_public_address(remote)
                process_context = _get_process_context(pid)
                high_risk_remote = remote_port in HIGH_RISK_REMOTE_PORTS
                sql_remote = remote_port in SQL_REMOTE_PORTS
                trusted_remote = _is_trusted_remote_host(remote)
                abnormal_status = status in ATTACK_STATUSES and remote_port not in SAFE_PUBLIC_PORTS and is_external
                risk_score = _network_risk_score(process_context, remote_port, status, is_external)

                if trusted_remote and not high_risk_remote and not sql_remote:
                    risk_score = 0
                    abnormal_status = False

                if _is_trusted_process_context(process_context) and trusted_remote:
                    risk_score = 0
                    abnormal_status = False

                if status == "SYN_SENT" and is_external:
                    syn_sent_history.setdefault(pid, []).append(now)

                syn_sent_count = len(syn_sent_history.get(pid, []))
                syn_sent_alert = syn_sent_count >= 10
                single_syn_sent = status == "SYN_SENT" and is_external and syn_sent_count < 10 and not trusted_remote

                event_type = "normal"
                reason = "新连接"
                log_only = False
                alert_severity = None
                blocked = False

                if single_syn_sent:
                    event_type = "abnormal"
                    reason = f"SYN_SENT 单次尝试 ({syn_sent_count})"
                    log_only = True
                elif risk_score >= NETWORK_SUSPICION_SCORE_THRESHOLD:
                    if high_risk_remote:
                        event_type = "attack"
                        reason = f"高危端口连接 {remote_port}"
                        alert_severity = "critical"
                    elif sql_remote:
                        event_type = "attack"
                        reason = f"可能SQL注入端口 {remote_port}"
                        alert_severity = "warning"
                    elif syn_sent_alert:
                        event_type = "attack"
                        reason = f"短时间内大量 SYN_SENT 失败 ({syn_sent_count})"
                        alert_severity = "critical"
                    elif abnormal_status:
                        event_type = "abnormal"
                        reason = f"异常连接状态 {status}"
                        log_only = True
                    else:
                        event_type = "abnormal"
                        reason = "多维度异常网络连接"
                elif high_risk_remote and is_external:
                    event_type = "abnormal"
                    reason = f"高危端口连接 {remote_port}"
                elif sql_remote and is_external:
                    event_type = "abnormal"
                    reason = f"SQL 目标端口 {remote_port}"
                elif abnormal_status:
                    event_type = "abnormal"
                    reason = f"异常连接状态 {status}"

                details = {
                    "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "pid": pid,
                    "local": local,
                    "remote": remote,
                    "status": status,
                    "type": event_type,
                    "reason": reason,
                    "process_name": process_context["name"],
                    "process_exe": process_context["exe_path"],
                    "parent_name": process_context["parent_name"],
                    "blocked": False,
                }
                if event_type == "attack" and pid > 0:
                    blocked = block_network_process(pid, reason)
                    details["blocked"] = blocked
                    if blocked:
                        reason += "，已阻断可疑进程"
                        details["reason"] = reason

                results.setdefault("network_events", []).append(details)

                if event_type == "normal":
                    logging.info("新网络连接: %s -> %s (%s)", local, remote, status)
                elif event_type == "abnormal":
                    logging.warning("网络异常: %s -> %s (%s) %s", local, remote, status, reason)
                    if not log_only and alert_queue is not None:
                        alert_queue.put({
                            "category": "network",
                            "title": "网络异常连接",
                            "message": f"{local} -> {remote} ({reason})",
                            "severity": "warning",
                        })
                else:
                    logging.error("网络攻击警报: %s -> %s (%s) %s", local, remote, status, reason)
                    if alert_queue is not None and alert_severity is not None:
                        alert_queue.put({
                            "category": "network",
                            "title": "网络攻击警报",
                            "message": f"{local} -> {remote} ({reason})",
                            "severity": alert_severity,
                        })

            if event_source is None:
                time.sleep(0.2)
            previous_connections = current_connections
    finally:
        try:
            pythoncom.CoUninitialize()
        except Exception:
            pass
        logging.info("网络监控已停止")
