#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ETW 采集器门面

把会话、消费者、事件总线、归一化串成一条完整链路:
    ETW 回调线程 -> EventBus（有界、可丢弃）
                          -> 解码线程 -> normalize -> on_event(Event)

上层只依赖 on_event 回调，不感知 ETW 细节。
"""

import logging
import threading

from .bus import EventBus
from .etw import providers
from .etw.consumer import EtwConsumer
from .etw.session import EtwSession
from .normalize import to_event

logger = logging.getLogger(__name__)


class EtwCollector:
    def __init__(
        self,
        session_name="WinMonitorEtw",
        provider_specs=None,
        bus=None,
        on_event=None,
        buffer_size_kb=64,
        min_buffers=4,
        max_buffers=32,
    ):
        self.session_name = session_name
        self.provider_specs = tuple(provider_specs or providers.DEFAULT_PROVIDERS)
        self.bus = bus or EventBus()
        self._on_event = on_event

        self._session = None
        self._consumer = None
        self._worker = None
        self._running = threading.Event()
        self.decode_errors = 0
        self.handled = 0
        self._consumer_snapshot = None
        self.disabled_providers = []

        self._config = {
            "buffer_size_kb": buffer_size_kb,
            "min_buffers": min_buffers,
            "max_buffers": max_buffers,
        }

    # -- 生命周期 ---------------------------------------------------------

    def start(self):
        if self._running.is_set():
            return
        self._running.set()

        session = EtwSession(self.session_name, **self._config)
        session.start()
        for spec in self.provider_specs:
            try:
                session.enable(spec)
            except Exception as exc:  # noqa: BLE001
                # 单个提供者不可用不应让整条链路失败，比如机器上没装 Sysmon
                logger.warning("启用提供者失败，已跳过 %s: %s", spec.name, exc)
                self.disabled_providers.append(spec.name)
        self._session = session

        self._worker = threading.Thread(target=self._decode_loop, daemon=True)
        self._worker.start()

        # 消费者最后启动，确保会话与提供者已就绪
        self._consumer = EtwConsumer(self.session_name, self.bus.put)
        self._consumer.start()
        logger.info("ETW 采集器已启动: %s", self.session_name)

    def stop(self):
        if not self._running.is_set():
            return

        # 先停生产者，再让解码线程把总线里剩下的排空
        if self._consumer is not None:
            try:
                self._consumer.stop()
            except Exception:  # noqa: BLE001
                logger.debug("关闭消费者时出错", exc_info=True)
            self._consumer_snapshot = {
                "records": self._consumer.record_count,
                "buffers": self._consumer.buffer_count,
                "errors": self._consumer.error_count,
                "process_rc": self._consumer.process_rc,
            }
            self._consumer = None

        self._running.clear()
        if self._worker is not None:
            self._worker.join(timeout=5)
            self._worker = None

        if self._session is not None:
            try:
                self._session.stop()
            except Exception:  # noqa: BLE001
                logger.debug("关闭会话时出错", exc_info=True)
            self._session = None
        logger.info("ETW 采集器已停止")

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.stop()
        return False

    # -- 内部 -------------------------------------------------------------

    def _decode_loop(self):
        # 停止信号只是不再接收新事件；队列里已有的必须处理完，
        # 否则每次停止都会丢掉尾部的一批事件。
        while True:
            running = self._running.is_set()
            raw = self.bus.get(timeout=0.2)
            if raw is None:
                if not running:
                    break
                continue
            try:
                event = to_event(raw)
            except Exception:  # noqa: BLE001
                self.decode_errors += 1
                continue
            self.handled += 1
            if self._on_event is not None:
                try:
                    self._on_event(event)
                except Exception:  # noqa: BLE001
                    logger.debug("事件处理回调出错", exc_info=True)

    def stats(self):
        result = {
            "session": self.session_name,
            "providers": [spec.name for spec in self.provider_specs],
            "bus": self.bus.stats(),
            "handled": self.handled,
            "decode_errors": self.decode_errors,
        }
        if self._consumer is not None:
            result["consumer"] = {
                "records": self._consumer.record_count,
                "buffers": self._consumer.buffer_count,
                "errors": self._consumer.error_count,
                "process_rc": self._consumer.process_rc,
            }
        elif self._consumer_snapshot is not None:
            result["consumer"] = self._consumer_snapshot
        if self._session is not None:
            result["session_info"] = self._session.query()
        return result
