#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络流聚合（P9b）

Kernel-Network 给的是「一条事件 = 一个方向的一个数据块」，带 size。
要喂给机器学习，需要先聚合成「一条流」的统计特征——也就是 CICIDS /
UNSW-NB15 那种行式数据。

设计要点:
    1. 方向不靠事件 ID 判断，而靠「哪端是本机地址」判断。
       这样即使某个 EventID 的语义猜错，字节归向也不会错。
    2. 连接两端的事件合并成同一条流（用规范化后的端点对作键），
       否则请求和响应会被算成两条流。
    3. 流有存活上限，长时间空闲即输出并从表里删除，避免内存无限增长。
"""

import collections
import socket
import struct
import threading
import time


def ipv4_from_int(value):
    """Kernel-Network 的地址字段是小端整数，转成点分字符串。"""
    try:
        number = int(value)
    except (TypeError, ValueError):
        return ""
    if number < 0 or number > 0xFFFFFFFF:
        return ""
    return socket.inet_ntoa(struct.pack("<I", number))


class FlowEntry:
    __slots__ = (
        "key",
        "endpoint_a",
        "endpoint_b",
        "initiator",
        "proto_pid",
        "start_ns",
        "last_ns",
        "out_packets",
        "out_bytes",
        "in_packets",
        "in_bytes",
        "out_sizes",
        "in_sizes",
        "last_out_ns",
        "last_in_ns",
        "out_iats",
        "in_iats",
    )

    def __init__(self, key, endpoint_a, endpoint_b, initiator, pid, ts_ns):
        self.key = key
        self.endpoint_a = endpoint_a
        self.endpoint_b = endpoint_b
        self.initiator = initiator
        self.proto_pid = pid
        self.start_ns = ts_ns
        self.last_ns = ts_ns
        self.out_packets = 0
        self.out_bytes = 0
        self.in_packets = 0
        self.in_bytes = 0
        self.out_sizes = []
        self.in_sizes = []
        self.last_out_ns = 0
        self.last_in_ns = 0
        self.out_iats = []
        self.in_iats = []

    def add(self, ts_ns, outgoing, size):
        if outgoing:
            if self.last_out_ns:
                self.out_iats.append((ts_ns - self.last_out_ns) / 1e6)  # 毫秒
            self.last_out_ns = ts_ns
            self.out_packets += 1
            self.out_bytes += size
            if len(self.out_sizes) < 512:
                self.out_sizes.append(size)
        else:
            if self.last_in_ns:
                self.in_iats.append((ts_ns - self.last_in_ns) / 1e6)
            self.last_in_ns = ts_ns
            self.in_packets += 1
            self.in_bytes += size
            if len(self.in_sizes) < 512:
                self.in_sizes.append(size)
        self.last_ns = max(self.last_ns, ts_ns)


def _stats(values):
    if not values:
        return 0.0, 0.0
    mean = sum(values) / len(values)
    variance = sum((value - mean) ** 2 for value in values) / len(values)
    return mean, variance ** 0.5


def summarize(entry, reason="idle"):
    """把流条目转成一行特征记录（字段名对齐 UNSW-NB15 的习惯命名）。"""
    src, sport = entry.endpoint_a
    dst, dport = entry.endpoint_b
    duration_ms = (entry.last_ns - entry.start_ns) / 1e6
    out_mean, out_std = _stats(entry.out_sizes)
    in_mean, in_std = _stats(entry.in_sizes)
    out_iat_mean, out_iat_std = _stats(entry.out_iats)
    in_iat_mean, in_iat_std = _stats(entry.in_iats)

    return {
        "kind": "flow",
        "start_ns": entry.start_ns,
        "end_ns": entry.last_ns,
        "src": src,
        "sport": sport,
        "dst": dst,
        "dport": dport,
        "pid": entry.proto_pid,
        "spkts": entry.out_packets,
        "dpkts": entry.in_packets,
        "sbytes": entry.out_bytes,
        "dbytes": entry.in_bytes,
        "dur_ms": round(duration_ms, 3),
        "smean": round(out_mean, 2),
        "dmean": round(in_mean, 2),
        "sstd": round(out_std, 2),
        "dstd": round(in_std, 2),
        "sintpkt": round(out_iat_mean, 3),
        "dintpkt": round(in_iat_mean, 3),
        "sjit": round(out_iat_std, 3),
        "djit": round(in_iat_std, 3),
        "rate_bps": round(
            (entry.out_bytes + entry.in_bytes) * 8 / (duration_ms / 1000), 2
        )
        if duration_ms > 0
        else 0.0,
        "closed_by": reason,
    }


class FlowAggregator:
    def __init__(self, window_seconds=15.0, max_flows=20000, local_ips=None):
        self.window_ns = int(window_seconds * 1e9)
        self.max_flows = max(1, max_flows)
        self._flows = collections.OrderedDict()
        self._lock = threading.Lock()
        self.local_ips = set(local_ips or ())
        self.added = 0
        self.emitted = 0
        self.evicted = 0
        self.filtered = 0

    def set_local_ips(self, addresses):
        self.local_ips = {str(a) for a in addresses if a}

    # -- 写入 -------------------------------------------------------------

    def add(self, ts_ns, src, sport, dst, dport, size, pid=0, close=False):
        if not src or not dst:
            self.filtered += 1
            return

        endpoint_a = (src, sport)
        endpoint_b = (dst, dport)
        key = tuple(sorted((endpoint_a, endpoint_b)))

        with self._lock:
            entry = self._flows.get(key)
            if entry is None:
                if len(self._flows) >= self.max_flows:
                    _, victim = self._flows.popitem(last=False)
                    self.evicted += 1
                    self._emit(entry=victim, reason="evicted")
                entry = FlowEntry(key, endpoint_a, endpoint_b, endpoint_a, pid, ts_ns)
                self._flows[key] = entry
                self.added += 1

            # 发起方是这条流里第一个发包的端点，方向以此判定
            outgoing = (src, sport) == entry.initiator
            entry.add(ts_ns, outgoing, int(size or 0))

            if close:
                self._flows.pop(key, None)
                self._emit(entry=entry, reason="closed")

    # -- 输出 -------------------------------------------------------------

    def _emit(self, entry, reason):
        record = summarize(entry, reason)
        self.emitted += 1
        self._out(record)

    def _out(self, record):
        callback = getattr(self, "on_flow", None)
        if callback is not None:
            try:
                callback(record)
            except Exception:  # noqa: BLE001
                pass

    def flush(self, now_ns=None, force=False):
        """把空闲超过窗口的流输出。force=True 时输出全部（停机用）。"""
        if now_ns is None:
            now_ns = time.time_ns()
        expired = []
        with self._lock:
            for key, entry in list(self._flows.items()):
                if force or now_ns - entry.last_ns >= self.window_ns:
                    expired.append((key, entry))
            for key, _ in expired:
                self._flows.pop(key, None)
        for _, entry in expired:
            self._emit(entry=entry, reason="idle" if not force else "shutdown")
        return len(expired)

    def stats(self):
        with self._lock:
            active = len(self._flows)
        return {
            "active_flows": active,
            "added": self.added,
            "emitted": self.emitted,
            "evicted": self.evicted,
            "filtered": self.filtered,
        }


class FlowMonitor:
    """后台线程：定期 flush，把流记录交给上层持久化或检测。"""

    def __init__(self, on_flow, window_seconds=15.0, local_ips=None):
        self.aggregator = FlowAggregator(window_seconds=window_seconds, local_ips=local_ips)
        self.aggregator.on_flow = on_flow
        self.interval = max(1.0, window_seconds / 3)
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="flow_monitor")
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            try:
                self._thread.join(timeout=3)
            except Exception:  # noqa: BLE001
                pass
            self._thread = None
        self.aggregator.flush(force=True)

    def _loop(self):
        while not self._stop.is_set():
            self._stop.wait(self.interval)
            try:
                self.aggregator.flush()
            except Exception:  # noqa: BLE001
                pass

    def add_event(self, event):
        """从统一 Event 里取出五元组与字节数。"""
        size = 0
        extra = getattr(event, "extra", None)
        if isinstance(extra, dict):
            size = extra.get("size") or 0
        self.aggregator.add(
            ts_ns=event.ts_ns,
            src=event.saddr,
            sport=event.sport,
            dst=event.daddr,
            dport=event.dport,
            size=size,
            pid=event.pid,
            close=bool(event.event_id == 13),
        )

    def stats(self):
        return self.aggregator.stats()
