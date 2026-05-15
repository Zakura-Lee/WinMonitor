#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块名: audit_mon.py
功能: Windows 日志与审计分析
"""

import logging
import time

import win32evtlog

import config

SUSPICIOUS_EVENT_IDS = config.SUSPICIOUS_EVENT_IDS
MONITORED_LOGS = config.MONITORED_LOGS


def parse_event(event):
    event_id = event.EventID & 0xFFFF
    if event_id not in SUSPICIOUS_EVENT_IDS:
        return None

    inserted = []
    try:
        inserted = list(event.StringInserts or [])
    except Exception:
        inserted = []

    timestamp = 0
    try:
        timestamp = time.mktime(event.TimeGenerated.timetuple())
    except Exception:
        try:
            timestamp = time.mktime(time.strptime(event.TimeGenerated.Format(), "%Y-%m-%d %H:%M:%S"))
        except Exception:
            timestamp = time.time()

    return {
        "time": event.TimeGenerated.Format() if hasattr(event.TimeGenerated, "Format") else str(event.TimeGenerated),
        "source": event.SourceName,
        "event_id": event_id,
        "description": SUSPICIOUS_EVENT_IDS[event_id],
        "details": "; ".join(str(x) for x in inserted if x),
        "timestamp": timestamp,
    }


def read_recent_events(server, log_type, last_time):
    records = []
    try:
        handle = win32evtlog.OpenEventLog(server, log_type)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events = win32evtlog.ReadEventLog(handle, flags, 0)

        if events:
            for event in events[:50]:
                record = parse_event(event)
                if record is None:
                    continue
                if record["timestamp"] > last_time:
                    records.append(record)
    except Exception as exc:
        logging.debug("读取审计日志失败 %s: %s", log_type, exc)
    finally:
        try:
            win32evtlog.CloseEventLog(handle)
        except Exception:
            pass

    return records


def audit_mon(stop_event, results, alert_queue=None, interval=config.AUDIT_MON_INTERVAL):
    logging.info("审计分析已启动")
    last_seen = 0
    try:
        while not stop_event.is_set():
            for log_type in MONITORED_LOGS:
                records = read_recent_events(None, log_type, last_seen)
                for record in records:
                    if record["timestamp"] > last_seen:
                        last_seen = record["timestamp"]
                    results.setdefault("audit_events", []).append(record)
                    logging.warning("审计事件: %s %s", record["event_id"], record["description"])
                    if alert_queue is not None:
                        alert_queue.put({
                            "category": "audit",
                            "title": f"审计异常: {record['description']}",
                            "message": f"{record['source']} {record['details']}",
                            "severity": "warning",
                        })
            for _ in range(interval):
                if stop_event.is_set():
                    break
                time.sleep(1)
    finally:
        logging.info("审计分析已停止")
