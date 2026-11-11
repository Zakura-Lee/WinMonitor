#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
进程树/活跃进程表

为什么需要它:
    1. Sysmon 的 ProcessTerminate 事件不带父进程字段，只能查表补全；
    2. PID 会被复用，用 PID 做键会串味，必须用 ProcessGuid（Sysmon）
       或 进程序号（Kernel-Process）做键；
    3. 检测规则需要问「这条进程的祖先链里有没有 Office / 浏览器」，
       这要求我们能从任意进程回溯到根。

本模块只做记录与查询，不做判定。
"""

from dataclasses import dataclass


@dataclass
class ProcessRecord:
    key: str
    pid: int
    ppid: int
    image: str = ""
    cmdline: str = ""
    user: str = ""
    integrity: str = ""
    started_ns: int = 0
    parent_key: str = ""
    stopped_ns: int = 0

    @property
    def alive(self):
        return self.stopped_ns == 0

    def to_dict(self):
        return {
            "key": self.key,
            "pid": self.pid,
            "ppid": self.ppid,
            "image": self.image,
            "cmdline": self.cmdline,
            "user": self.user,
            "integrity": self.integrity,
            "started_ns": self.started_ns,
            "parent_key": self.parent_key,
            "alive": self.alive,
        }


class ProcessTable:
    def __init__(self, max_records=5000):
        self.max_records = max_records
        self._records = {}      # key -> ProcessRecord
        self._by_pid = {}       # pid -> 最近一次出现的 key
        self.started = 0
        self.stopped = 0
        self.unresolved_parent = 0

    # -- 键 -----------------------------------------------------------------

    @staticmethod
    def key_for(event):
        """优先用 GUID，其次用 PID + 进程序号，最后退回启动时间戳。"""
        if event.process_guid:
            return f"guid:{event.process_guid}"
        if event.process_key:
            return f"pid:{event.pid}:{event.process_key}"
        return f"pid:{event.pid}:{event.ts_ns}"

    # -- 写入 ---------------------------------------------------------------

    def add_start(self, event):
        key = self.key_for(event)

        parent_key = ""
        if event.parent_guid:
            parent_key = f"guid:{event.parent_guid}"
        elif event.ppid:
            parent_key = self._by_pid.get(event.ppid, "")

        if not parent_key and event.ppid:
            self.unresolved_parent += 1

        record = ProcessRecord(
            key=key,
            pid=event.pid,
            ppid=event.ppid,
            image=event.image,
            cmdline=event.cmdline,
            user=event.user,
            integrity=event.integrity,
            started_ns=event.ts_ns,
            parent_key=parent_key,
        )
        self._records[key] = record
        self._by_pid[event.pid] = key
        self.started += 1

        if len(self._records) > self.max_records:
            self._evict_oldest()
        return record

    def mark_stop(self, event):
        key = self.key_for(event)
        record = self._records.get(key)
        if record is not None:
            record.stopped_ns = event.ts_ns or record.started_ns
            self.stopped += 1
        return record

    # -- 查询 ---------------------------------------------------------------

    def get(self, key):
        return self._records.get(key)

    def latest_by_pid(self, pid):
        key = self._by_pid.get(pid)
        return self._records.get(key) if key else None

    def ancestry(self, key, depth=10):
        """从自身向上回溯到根，返回 [自身, 父, 祖父, ...]。"""
        chain = []
        seen = set()
        current = key
        while current and current not in seen and len(chain) < depth:
            seen.add(current)
            record = self._records.get(current)
            if record is None:
                break
            chain.append(record)
            current = record.parent_key
        return chain

    def ancestors_names(self, key, depth=10):
        return [r.image for r in self.ancestry(key, depth) if r.image]

    def children_of(self, key):
        return [r for r in self._records.values() if r.parent_key == key]

    def alive_count(self):
        return sum(1 for r in self._records.values() if r.alive)

    # -- 维护 ---------------------------------------------------------------

    def _evict_oldest(self):
        dead = [r for r in self._records.values() if not r.alive]
        pool = dead or list(self._records.values())
        victim = min(pool, key=lambda r: r.started_ns)
        self._records.pop(victim.key, None)
        if self._by_pid.get(victim.pid) == victim.key:
            self._by_pid.pop(victim.pid, None)

    def stats(self):
        return {
            "records": len(self._records),
            "alive": self.alive_count(),
            "started": self.started,
            "stopped": self.stopped,
            "unresolved_parent": self.unresolved_parent,
        }
