#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
文件名: main.py
功能: 主程序入口（GUI）
作者: Zakura_Lee
日期: 2026-04-15
"""

import logging
from logging.handlers import RotatingFileHandler
import queue
import threading
import tkinter as tk
from tkinter import ttk

LOG_FILE = "winmonitor.log"
LOG_MAX_BYTES = 5 * 1024 * 1024
LOG_BACKUP_COUNT = 3

# 日志滚动配置：当日志文件超过 5MB 时保留最近 3 个备份
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        RotatingFileHandler(
            LOG_FILE,
            maxBytes=LOG_MAX_BYTES,
            backupCount=LOG_BACKUP_COUNT,
            encoding="utf-8",
        ),
        logging.StreamHandler(),
    ],
)

import file_mon
import network_mon
import process_mon


class WinMonitorApp:
    """主窗口应用，负责界面展示、线程管理和告警处理。"""

    def __init__(self, root):
        self.root = root
        self.root.title("WinMonitor")
        self.root.resizable(False, False)

        self.stop_event = None
        self.results = None
        self.threads = []
        self.alert_queue = queue.Queue()
        self.shown_alert_signatures = set()

        self._build_ui()
        self._check_alerts()

    def _build_ui(self):
        logo_frame = ttk.Frame(self.root, padding=12)
        logo_frame.grid(row=0, column=0, sticky="ew")

        logo_label = ttk.Label(logo_frame, text="🛡️", font=("Arial", 28))
        logo_label.grid(row=0, column=0, rowspan=2, padx=(0, 12))

        title_label = ttk.Label(logo_frame, text="WinMonitor", font=("Arial", 18, "bold"))
        title_label.grid(row=0, column=1, sticky="w")

        subtitle_label = ttk.Label(
            logo_frame,
            text="Windows 进程、文件、网络监控工具",
            font=("Arial", 10),
        )
        subtitle_label.grid(row=1, column=1, sticky="w")

        info_frame = ttk.LabelFrame(self.root, text="项目说明", padding=10)
        info_frame.grid(row=1, column=0, padx=12, pady=(0, 12), sticky="ew")

        info_text = (
            "支持三个并发模块：进程检测、文件监控、网络连接监控。\n"
            "点击开始启动监控，暂停停止监控并打印本次检测结果。"
        )
        info_label = ttk.Label(info_frame, text=info_text, justify="left")
        info_label.grid(row=0, column=0, sticky="w")

        button_frame = ttk.Frame(self.root, padding=10)
        button_frame.grid(row=2, column=0, sticky="ew")

        self.start_button = ttk.Button(button_frame, text="开始", command=self.start_monitoring)
        self.start_button.grid(row=0, column=0, padx=4)

        self.pause_button = ttk.Button(button_frame, text="暂停", command=self.pause_monitoring, state="disabled")
        self.pause_button.grid(row=0, column=1, padx=4)

        self.exit_button = ttk.Button(button_frame, text="退出", command=self.exit_app)
        self.exit_button.grid(row=0, column=2, padx=4)

        self.status_var = tk.StringVar(value="状态：未运行")
        status_label = ttk.Label(self.root, textvariable=self.status_var, padding=(10, 0))
        status_label.grid(row=3, column=0, sticky="w")

        log_frame = ttk.LabelFrame(self.root, text="监控结果预览", padding=10)
        log_frame.grid(row=4, column=0, padx=12, pady=(0, 12), sticky="nsew")

        self.log_text = tk.Text(log_frame, width=60, height=14, wrap="word", state="disabled")
        self.log_text.grid(row=0, column=0, sticky="nsew")

        scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=scrollbar.set)

        self.root.protocol("WM_DELETE_WINDOW", self.exit_app)

    def _append_log(self, message):
        # 将日志消息追加到 GUI 文本区域，并滚动到底部
        self.log_text.configure(state="normal")
        self.log_text.insert("end", message + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _show_alert_window(self, alert):
        # 使用独立弹窗显示单条告警，避免阻塞主界面
        title = alert.get("title", "警告")
        message = alert.get("message", "")
        severity = alert.get("severity", "warning")

        window = tk.Toplevel(self.root)
        window.title(title)
        window.attributes("-topmost", True)
        window.resizable(False, False)

        frame = ttk.Frame(window, padding=12)
        frame.grid(row=0, column=0, sticky="nsew")

        label = ttk.Label(frame, text=title, font=("Arial", 12, "bold"))
        label.grid(row=0, column=0, sticky="w")

        msg = ttk.Label(frame, text=message, wraplength=380, justify="left")
        msg.grid(row=1, column=0, pady=(8, 12), sticky="w")

        close_button = ttk.Button(frame, text="关闭", command=window.destroy)
        close_button.grid(row=2, column=0, sticky="e")

        window.after(20000, window.destroy)

    def _check_alerts(self):
        # 轮询告警队列，将新告警弹出到独立窗口，避免重复弹窗
        while True:
            try:
                alert = self.alert_queue.get_nowait()
            except queue.Empty:
                break

            signature = (
                alert.get("category"),
                alert.get("title"),
                alert.get("message"),
            )
            if signature in self.shown_alert_signatures:
                continue
            self.shown_alert_signatures.add(signature)
            self._show_alert_window(alert)

        self.root.after(500, self._check_alerts)

    def _summary_text(self, results):
        # 生成暂停时显示的结果摘要文本，包括进程、文件和网络事件
        lines = ["=== 本次监控结果 ==="]
        process_events = results.get("process_events", [])
        file_events = results.get("file_events", [])
        network_events = results.get("network_events", [])

        lines.append(f"进程告警: {len(process_events)} 条")
        for event in process_events[-5:]:
            lines.append(f"  [{event['time']}] PID={event['pid']} {event['name']} -> {'; '.join(event['reasons'])}")

        lines.append(f"文件变化: {len(file_events)} 条")
        for event in file_events[-5:]:
            if event.get("destination"):
                lines.append(f"  [{event['time']}] {event['action']} {event['path']} -> {event['destination']}")
            else:
                lines.append(f"  [{event['time']}] {event['action']} {event['path']}")

        normal_count = sum(1 for event in network_events if event.get("type") == "normal")
        abnormal_events = [event for event in network_events if event.get("type") == "abnormal"]
        attack_events = [event for event in network_events if event.get("type") == "attack"]

        lines.append(f"网络连接: {normal_count} 条普通新增链接")
        if abnormal_events:
            lines.append(f"异常网络连接: {len(abnormal_events)} 条")
            for event in abnormal_events[-5:]:
                lines.append(
                    f"  [{event['time']}] {event['status']} {event['local']} -> {event['remote']} ({event['reason']}) pid={event['pid']}"
                )

        if attack_events:
            lines.append(f"网络攻击告警: {len(attack_events)} 条")
            for event in attack_events[-5:]:
                lines.append(
                    f"  [{event['time']}] {event['status']} {event['local']} -> {event['remote']} ({event['reason']}) pid={event['pid']}"
                )

        lines.append("====================")
        return "\n".join(lines)

    def start_monitoring(self):
        # 启动各模块监控线程，并初始化结果与告警队列
        if self.stop_event is not None and not self.stop_event.is_set():
            return

        self.stop_event = threading.Event()
        self.results = {
            "process_events": [],
            "file_events": [],
            "network_events": [],
        }
        self.shown_alert_signatures.clear()

        self.threads = [
            threading.Thread(target=process_mon.p_mon, args=(self.stop_event, self.results, self.alert_queue), daemon=True),
            threading.Thread(target=file_mon.f_mon, args=(self.stop_event, self.results, self.alert_queue), daemon=True),
            threading.Thread(target=network_mon.n_mon, args=(self.stop_event, self.results, self.alert_queue), daemon=True),
        ]

        for thread in self.threads:
            thread.start()

        self.status_var.set("状态：监控中")
        self.start_button.configure(state="disabled")
        self.pause_button.configure(state="normal")
        self._append_log("监控已启动，点击“暂停”停止并查看本次结果。")

    def pause_monitoring(self):
        # 停止监控线程，打印本次采集结果摘要
        if self.stop_event is None or self.stop_event.is_set():
            return

        self.stop_event.set()
        for thread in self.threads:
            thread.join(timeout=5)

        self.status_var.set("状态：已暂停")
        self.start_button.configure(state="normal")
        self.pause_button.configure(state="disabled")

        summary = self._summary_text(self.results)
        self._append_log(summary)
        print(summary)

    def exit_app(self):
        if self.stop_event is not None and not self.stop_event.is_set():
            self.stop_event.set()
            for thread in self.threads:
                thread.join(timeout=5)

        self.root.quit()
        self.root.destroy()


def main():
    """程序入口。创建 Tk 窗口并启动 WinMonitor 应用。"""
    print(r"""
    __        __   _    _   _    __  __
    \ \      / /  | |  | \ | |  |  \/  |
     \ \ /\ / /   | |  |  \| |  | |\/| |
      \ V  V /    | |  | |\  |  | |  | |
       \_/\_/     |_|  |_| \_|  |_|  |_|
    """)
    print("Welcome to WinMonitor！")
    root = tk.Tk()
    app = WinMonitorApp(root)
    root.mainloop()


if __name__ == '__main__':
    main()