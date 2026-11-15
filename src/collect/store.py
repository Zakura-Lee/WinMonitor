#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
事件持久化

为什么需要:
    检测层要训练，就必须有历史事件；而目前只有「告警」会入库，
    正常事件全在内存里滚动，进程一停就没了。

实现约定:
    - 按小时切分文件：<root>/YYYYMMDD/HH.jsonl
    - 单小时超过上限后采样丢弃，避免文件事件刷爆磁盘
    - 保留 N 天，启动与切换小时时清理
    - 写入是追加式的，崩溃最多丢最后一行
"""

import json
import os
import threading
import time

# 落盘时只保留这些字段，多余的（如 extra.fields）会让文件迅速膨胀
RECORD_KEYS = (
    "ts_ns",
    "provider",
    "event_id",
    "pid",
    "ppid",
    "tid",
    "process_guid",
    "parent_guid",
    "image",
    "cmdline",
    "path",
    "key",
    "value",
    "saddr",
    "sport",
    "daddr",
    "dport",
    "proto",
    "user",
    "integrity",
)


def event_to_record(event):
    """把 Event 压成适合落盘的紧凑字典。"""
    values = {}
    for name in RECORD_KEYS:
        value = getattr(event, name, None)
        if value in (None, "", 0):
            continue  # 空值不写，文件能小一半
        values[name] = value
    return values


class EventStore:
    def __init__(self, root, retain_days=3, max_per_hour=200000, enabled=True):
        self.root = os.path.abspath(root)
        self.retain_days = max(1, int(retain_days))
        self.max_per_hour = max(1, int(max_per_hour))
        self.enabled = enabled

        self._lock = threading.Lock()
        self._handle = None
        self._hour_key = None
        self._hour_count = 0

        self.written = 0
        self.dropped = 0
        self.rotations = 0

        if self.enabled:
            os.makedirs(self.root, exist_ok=True)
            self._prune()

    # -- 写入 -------------------------------------------------------------

    def write(self, event):
        if not self.enabled:
            return False
        with self._lock:
            self._ensure_file()
            if self._hour_count >= self.max_per_hour:
                self.dropped += 1
                return False
            try:
                self._handle.write(json.dumps(event_to_record(event), ensure_ascii=False))
                self._handle.write("\n")
            except (OSError, TypeError):
                self.dropped += 1
                return False
            self._hour_count += 1
            self.written += 1
            return True

    def flush(self):
        with self._lock:
            if self._handle is not None:
                try:
                    self._handle.flush()
                except OSError:
                    pass

    def close(self):
        with self._lock:
            if self._handle is not None:
                try:
                    self._handle.close()
                except OSError:
                    pass
                self._handle = None

    # -- 内部 -------------------------------------------------------------

    def _current_hour(self):
        now = time.localtime()
        return time.strftime("%Y%m%d", now), time.strftime("%H", now)

    def _ensure_file(self):
        day, hour = self._current_hour()
        key = (day, hour)
        if self._hour_key == key and self._handle is not None:
            return

        if self._handle is not None:
            try:
                self._handle.close()
            except OSError:
                pass
            self._handle = None

        directory = os.path.join(self.root, day)
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, f"{hour}.jsonl")
        self._handle = open(path, "a", encoding="utf-8")
        self._hour_key = key
        self._hour_count = 0
        self.rotations += 1
        self._prune()

    def _prune(self):
        """删除超过保留天数的目录。目录名即 YYYYMMDD。"""
        if not os.path.isdir(self.root):
            return
        cutoff = time.time() - self.retain_days * 86400
        for name in os.listdir(self.root):
            path = os.path.join(self.root, name)
            if not os.path.isdir(path) or len(name) != 8 or not name.isdigit():
                continue
            try:
                stamp = time.mktime(time.strptime(name, "%Y%m%d"))
            except ValueError:
                continue
            if stamp < cutoff:
                for inner in os.listdir(path):
                    try:
                        os.remove(os.path.join(path, inner))
                    except OSError:
                        pass
                try:
                    os.rmdir(path)
                except OSError:
                    pass

    def stats(self):
        return {
            "enabled": self.enabled,
            "root": self.root,
            "written": self.written,
            "dropped": self.dropped,
            "rotations": self.rotations,
        }
