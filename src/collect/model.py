#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
采集层统一事件模型

设计要点:
    1. RawEvent 是回调线程里构造的轻量对象，只做内存拷贝，不做任何解析；
    2. Event 是解码后的结构，供规则引擎与检测模型消费；
    3. 两者分离是为了让 ETW 回调尽可能快，避免在高频事件下丢缓冲。
"""

from dataclasses import asdict, dataclass, field

# 1601-01-01 到 1970-01-01 的 100ns 数，用于把 FILETIME 换算成 Unix 纳秒
FILETIME_EPOCH_DELTA = 116444736000000000


@dataclass(slots=True)
class RawEvent:
    """回调线程里生成的原始事件，只含可安全拷贝的字段。"""

    ts_ns: int
    provider_id: bytes
    event_id: int
    level: int
    keyword: int
    pid: int
    tid: int
    payload: bytes

    # 由 TDH 缓存下来的事件布局，nil 表示该事件没有可用布局
    version: int = 0
    event_name: str = ""
    properties: tuple = ()
    # 关注的事件类型才会填，走 TdhGetProperty 精确取值
    decoded: dict = field(default_factory=dict)


@dataclass(slots=True)
class Event:
    """解码后的统一事件，字段覆盖进程、文件、网络、注册表四类来源。"""

    ts_ns: int
    source: str = "etw"
    provider: str = ""
    event_id: int = 0
    level: int = 0
    keyword: int = 0

    pid: int = 0
    ppid: int = 0
    tid: int = 0
    process_key: int = 0
    # Sysmon 提供进程 GUID，比 PID 更适合做进程树的主键
    process_guid: str = ""
    parent_guid: str = ""

    image: str = ""
    cmdline: str = ""

    path: str = ""
    dest_path: str = ""

    key: str = ""
    value: str = ""

    saddr: str = ""
    sport: int = 0
    daddr: str = ""
    dport: int = 0
    proto: str = ""

    user: str = ""
    integrity: str = ""
    session_id: int = 0

    lost_before: int = 0
    extra: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)

    def timestamp_seconds(self):
        return self.ts_ns / 1e9
