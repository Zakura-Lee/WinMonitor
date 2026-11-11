#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
有界事件总线

职责:
    1. 在 ETW 回调线程与业务线程之间做缓冲；
    2. 缓冲满时按「丢弃并计数」处理，绝不阻塞回调（阻塞会导致 ETW 丢缓冲）；
    3. 提供可观测的统计，便于判断是否需要降级或过滤。
"""

import queue
import threading


class EventBus:
    def __init__(self, maxsize=10000):
        if maxsize <= 0:
            raise ValueError("maxsize 必须为正数")
        self._queue = queue.Queue(maxsize=maxsize)
        self._lock = threading.Lock()
        self.maxsize = maxsize
        self.put_count = 0
        self.drop_count = 0
        self.get_count = 0

    def put(self, item):
        """非阻塞入队。返回 True 表示入队成功，False 表示因队列满被丢弃。"""
        try:
            self._queue.put_nowait(item)
        except queue.Full:
            with self._lock:
                self.drop_count += 1
            return False
        with self._lock:
            self.put_count += 1
        return True

    def get(self, timeout=0.5):
        """取一条事件，超时返回 None。"""
        try:
            item = self._queue.get(timeout=timeout)
        except queue.Empty:
            return None
        with self._lock:
            self.get_count += 1
        return item

    def drain(self, limit=1000):
        """尽可能多地取出事件，最多 limit 条。"""
        items = []
        while len(items) < limit:
            try:
                items.append(self._queue.get_nowait())
            except queue.Empty:
                break
        with self._lock:
            self.get_count += len(items)
        return items

    def qsize(self):
        return self._queue.qsize()

    def stats(self):
        with self._lock:
            return {
                "maxsize": self.maxsize,
                "qsize": self._queue.qsize(),
                "put": self.put_count,
                "get": self.get_count,
                "drop": self.drop_count,
            }
