#!/usr/bin/env python3.14
# -*- coding: utf-8 -*-
"""
模块名: process_mon.py
功能: windows进程监控
"""

import datetime
import logging
import time

import psutil
from plyer import notification

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

SUS_PATH = [
    "c:\\users\\admin\\appdata\\local\\temp\\",
    "c:\\users\\admin\\desktop\\",
    "c:\\users\\admin\\downloads\\",
    "c:\\windows\\temp\\",
]

SUS_CMD = [
    "-enc",
    "-encoded",
    "-encodedcommand",
    "-w hidden",
    "-windowstyle hidden",
    "-nop",
    "-nologo",
    "certutil",
    "bitsadmin",
    "regsvr32",
    "rundll32",
    "whoami",
    "setuid",
    "meterpreter",
    "reverse_shell",
]

SUS_PARENT = [
    "notepad.exe",
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
]

SUS_STATUS = ["zombie", "parked", "stopped"]
SUS_CPU = 70
SUS_MEM = 35
CRITICAL_CPU = 85
CRITICAL_MEM = 50

# 系统进程白名单：这些进程常见于 Windows 系统，默认不因普通资源峰值触发告警
SYS_PROCESS_WHITELIST = {
    "lockapp.exe",
    "systemsettings.exe",
    "backgroundtaskhost.exe",
    "searchhost.exe",
    "shellexperiencehost.exe",
    "textinputhost.exe",
    "winlogon.exe",
    "storedesktopextension.exe",
    "wsappx.exe",
    "apphost.exe",
    "runtimebroker.exe",
    "svchost.exe",
    "services.exe",
    "csrss.exe",
    "smss.exe",
    "taskhostw.exe",
    "taskhost.exe",
    "dwm.exe",
    "explorer.exe",
    "calculator.exe",
    "photos.exe",
    "mail.exe",
    "calendar.exe",
    "weather.exe",
    "yourphone.exe",
    "maps.exe",
    "alarmsandclock.exe",
    "ctfmon.exe",
    "tabtip.exe",
    "mrt.exe",
    "audiodg.exe",
    "fontdrvhost.exe",
    "conhost.exe",
    "taskeng.exe",
    "lsass.exe",
    "spoolsv.exe",
    "wininit.exe",
    "trustedinstaller.exe",
}


def normalize_text(value):
    # 统一文本格式，防止大小写和空白干扰比较逻辑
    return str(value).lower().strip() if value else ""


def is_whitelisted_process(name):
    return normalize_text(name) in SYS_PROCESS_WHITELIST


def notify(title, message, timeout=5):
    # 调用系统通知接口显示桌面通知
    notification.notify(
        title=title,
        message=message.strip(),
        timeout=timeout,
        app_name="WinMonitor",
    )


def get_safe_parent(process):
    # 安全地读取父进程信息，避免在进程消失或拒绝访问时抛出异常
    try:
        parent = process.parent()
        if parent is None:
            return 0, ""
        return parent.pid, normalize_text(parent.name())
    except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError, AttributeError):
        return 0, ""


def get_process_stats(process):
    # 获取进程 CPU/内存占用，权限异常时返回 0
    try:
        cpu = process.cpu_percent(interval=None)
    except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError):
        cpu = 0.0

    try:
        mem = process.memory_percent()
    except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError):
        mem = 0.0

    return cpu, mem


def collect_process_info(process):
    # 汇总进程基础信息，用于后续可疑判定和告警描述
    exe_path = ""
    cmdline = []
    try:
        exe_path = normalize_text(process.exe())
    except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError):
        pass

    try:
        cmdline = process.cmdline() or []
    except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError):
        cmdline = []

    ppid, pname = get_safe_parent(process)
    cpu, mem = get_process_stats(process)

    return {
        "pid": process.info.get("pid", 0),
        "name": normalize_text(process.info.get("name")),
        "status": normalize_text(process.info.get("status")),
        "exe_path": exe_path,
        "cmdline": [normalize_text(x) for x in cmdline],
        "ppid": ppid,
        "pname": pname,
        "cpu": cpu,
        "mem": mem,
    }


def evaluate_suspicion(info):
    # 基于路径、命令行、父进程、状态及资源占用，生成可疑理由列表
    reasons = []

    if any(info["exe_path"].startswith(path) for path in SUS_PATH):
        reasons.append("Suspicious exe_path")

    cmdline_str = " ".join(info["cmdline"])
    if any(key in cmdline_str for key in SUS_CMD):
        reasons.append("Suspicious cmdline")

    if info["pname"] and info["pname"] in SUS_PARENT:
        reasons.append("Suspicious parent process")

    if info["status"] in SUS_STATUS:
        reasons.append(f"Abnormal status: {info['status']}")

    if not is_whitelisted_process(info["name"]):
        if info["cpu"] > SUS_CPU:
            reasons.append(f"High CPU: {info['cpu']:.2f}%")

        if info["mem"] > SUS_MEM:
            reasons.append(f"High memory: {info['mem']:.2f}%")

        if info["cpu"] > CRITICAL_CPU and info["mem"] > CRITICAL_MEM:
            reasons.append("Critical CPU+memory usage")
    else:
        # 系统白名单进程仅在真正可疑行为时报警，避免普通资源峰值误报
        if info["cpu"] > CRITICAL_CPU and info["mem"] > CRITICAL_MEM and reasons:
            reasons.append("Critical CPU+memory usage")

    return reasons


def build_alert_message(info, reasons):
    # 构建警报通知内容，将进程信息与可疑原因组合成多行文本
    lines = [f"pid: {info['pid']}", f"name: {info['name']}"]
    if info["exe_path"]:
        lines.append(f"path: {info['exe_path']}")
    if info["ppid"]:
        lines.append(f"parent: {info['ppid']} / {info['pname']}")
    if info["cpu"]:
        lines.append(f"cpu: {info['cpu']:.2f}%")
    if info["mem"]:
        lines.append(f"mem: {info['mem']:.2f}%")
    lines.append("原因:")
    lines.extend(reasons)
    return "\n".join(lines)


def report_process_changes(new_pids, gone_pids):
    # 输出新增/退出进程摘要，方便监控周期内变化统计
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
    # 检查新增进程，评估是否符合可疑条件并记录告警事件
    for pid in new_pids:
        process = processes.get(pid)
        if not process:
            continue

        info = collect_process_info(process)
        reasons = evaluate_suspicion(info)
        if not reasons:
            continue

        event = {
            "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "pid": info["pid"],
            "name": info["name"],
            "reasons": reasons,
        }
        results.setdefault("process_events", []).append(event)

        title = f"Suspicious process: {info['name']} ({info['pid']})"
        message = build_alert_message(info, reasons)
        logging.warning("%s %s", title, "; ".join(reasons))
        notify(title, message, timeout=8)

        if alert_queue is not None:
            severity = "critical" if any(key in " ".join(reasons) for key in ["Abnormal status", "Critical CPU+memory usage", "Suspicious exe_path", "Suspicious cmdline", "Suspicious parent process"]) else "warning"
            alert_queue.put({
                "category": "process",
                "title": title,
                "message": message,
                "severity": severity,
            })


def p_mon(stop_event, results, alert_queue=None):
    """
    进程监控主函数：循环获取系统所有进程
    持续运行，每秒扫描一次系统进程
    识别：新增进程、死亡进程、可疑进程
    全程异常保护，不崩溃、不误报
    """
    old_pids = set()
    first_run = True

    while not stop_event.is_set():
        # 每次循环扫描当前进程列表并计算新增/退出进程
        processes = {}
        for process in psutil.process_iter(["pid", "name", "cmdline", "status"]):
            try:
                processes[process.pid] = process
                process.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError):
                continue

        current_pids = set(processes.keys())
        new_pids = current_pids - old_pids
        gone_pids = old_pids - current_pids

        if first_run:
            logging.info("首次扫描完成，进入持续监控")
            first_run = False
        else:
            report_process_changes(new_pids, gone_pids)
            inspect_new_processes(processes, new_pids, results, alert_queue)

        old_pids = current_pids
        time.sleep(1)

    logging.info("进程监控已停止")
