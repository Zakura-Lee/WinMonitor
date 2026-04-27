#!/usr/bin/env python3.14
# -*- coding: utf-8 -*-
"""
模块名: network_mon.py
功能: windows网络连接监控
"""

import logging
import time

import psutil

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def _addr_to_str(addr):
    # 将 psutil 地址对象转换为字符串表示形式 ip:port
    if not addr:
        return ""
    if hasattr(addr, "ip"):
        return f"{addr.ip}:{addr.port}"
    return f"{addr[0]}:{addr[1]}"


# 网络端口与状态规则，用于区分普通连接、异常连接与攻击告警
SUSPICIOUS_NETWORK_PORTS = {
    23, 445, 3389, 5900, 6667, 2222
}

DANGEROUS_REMOTE_PORTS = {
    4444, 5555, 12345, 27374, 31337
}

HIGH_RISK_REMOTE_PORTS = {4444, 1337, 3389, 445}
SQL_REMOTE_PORTS = {1433, 3306, 5432, 1521, 1434, 33060}

ATTACK_STATUSES = {"SYN_SENT", "SYN_RECV"}
SAFE_PUBLIC_PORTS = {80, 443, 53, 123, 25, 587, 110, 995, 993, 143}

PRIVATE_PREFIXES = ("10.", "172.", "192.168.", "127.")
TEMP_PATH_PATTERNS = ("\\temp\\", "\\appdata\\local\\temp", "\\windows\\temp")
SUSPICIOUS_PARENT_NAMES = {
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "wmic.exe",
    "mshta.exe",
    "svchost.exe",
}


def _is_public_address(remote):
    # 判断远程地址是否为公网地址，排除私有网段和本机环回地址
    if not remote:
        return False
    address = remote.split(":")[0]
    return not address.startswith(PRIVATE_PREFIXES)


def _get_remote_port(remote):
    # 从远程地址字符串中提取端口号，用于端口风险判断
    try:
        return int(remote.split(":")[-1])
    except (ValueError, IndexError):
        return 0


def _normalize_path(path):
    # 标准化进程路径，方便后续路径匹配和临时目录判断
    if not path:
        return ""
    return path.lower().replace("/", "\\")


def _get_process_context(pid):
    # 获取进程基础信息并判断是否为临时目录程序或可疑父进程启动
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
        proc = psutil.Process(pid)
        context["name"] = proc.name().lower()
        context["exe_path"] = _normalize_path(proc.exe())
        parent = proc.parent()
        context["parent_name"] = parent.name().lower() if parent is not None else ""
    except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError, OSError):
        return context

    normalized_exe = context["exe_path"]
    context["is_temp_path"] = any(part in normalized_exe for part in TEMP_PATH_PATTERNS)
    context["has_suspicious_parent"] = context["parent_name"] in SUSPICIOUS_PARENT_NAMES
    return context


def _is_suspicious_process(context):
    # 进程被判定为可疑的条件：临时目录执行或启动父进程不寻常
    return context["is_temp_path"] or context["has_suspicious_parent"]


def _is_high_risk_remote(remote_port):
    return remote_port in HIGH_RISK_REMOTE_PORTS


def _is_sql_remote(remote_port):
    return remote_port in SQL_REMOTE_PORTS


def n_mon(stop_event, results, alert_queue=None, interval=1):
    # 网络监控主循环：比较当前与上次连接状态，识别新增连接并分类记录/告警
    previous_connections = set()
    syn_sent_history = {}
    logging.info("网络监控已启动")

    try:
        while not stop_event.is_set():
            current_connections = set()
            try:
                # 获取当前所有 TCP/UDP 连接，逐条转换为可比较的字符串形式
                for conn in psutil.net_connections(kind="inet"):
                    if not conn.raddr:
                        continue
                    local = _addr_to_str(conn.laddr)
                    remote = _addr_to_str(conn.raddr)
                    current_connections.add((conn.pid or 0, local, remote, conn.status))
            except (psutil.AccessDenied, psutil.NoSuchProcess, PermissionError):
                logging.debug("读取网络连接时遇到权限或进程错误，已忽略")

            now = time.monotonic()
            # 清理旧的 SYN_SENT 记录，保留最近 1 秒内的连接尝试
            for pid, timestamps in list(syn_sent_history.items()):
                syn_sent_history[pid] = [ts for ts in timestamps if now - ts <= 1.0]
                if not syn_sent_history[pid]:
                    del syn_sent_history[pid]

            new_connections = current_connections - previous_connections
            for pid, local, remote, status in new_connections:
                remote_port = _get_remote_port(remote)
                is_external = _is_public_address(remote)
                process_context = _get_process_context(pid)
                suspicious_process = _is_suspicious_process(process_context)
                high_risk_remote = _is_high_risk_remote(remote_port)
                sql_remote = _is_sql_remote(remote_port)
                abnormal_status = status in ATTACK_STATUSES and remote_port not in SAFE_PUBLIC_PORTS and is_external

                if status == "SYN_SENT" and is_external:
                    syn_sent_history.setdefault(pid, []).append(now)

                syn_sent_count = len(syn_sent_history.get(pid, []))
                syn_sent_alert = syn_sent_count >= 10
                single_syn_sent = status == "SYN_SENT" and is_external and syn_sent_count < 10

                event_type = "normal"
                reason = "新连接"
                log_only = False
                alert_severity = None

                if single_syn_sent:
                    event_type = "abnormal"
                    reason = f"SYN_SENT 单次尝试 ({syn_sent_count})"
                    log_only = True

                elif is_external and suspicious_process:
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
                }
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

            previous_connections = current_connections
            time.sleep(interval)
    finally:
        logging.info("网络监控已停止")
