#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ETW 会话管理：创建、启用提供者、查询、停止。"""

import ctypes

from . import api, etwtypes as types


class EtwSessionError(RuntimeError):
    pass


class EtwSession:
    """一个 ETW 跟踪会话。

    用法:
        with EtwSession("WinMonitor") as session:
            session.enable(KERNEL_PROCESS)
            ...
    """

    def __init__(
        self,
        name,
        buffer_size_kb=64,
        min_buffers=4,
        max_buffers=32,
        log_file_path=None,
        real_time=True,
    ):
        self.name = name
        self._buffer_holder = None
        self._properties = None
        self._handle = types.TRACEHANDLE(0)
        self._started = False
        self._config = {
            "buffer_size_kb": buffer_size_kb,
            "min_buffers": min_buffers,
            "max_buffers": max_buffers,
            "log_file_path": log_file_path,
            "real_time": real_time,
        }

    # -- 生命周期 ---------------------------------------------------------

    def start(self):
        if self._started:
            return
        buffer, properties = api.build_properties(self.name, **self._config)
        self._buffer_holder = buffer
        self._properties = properties

        rc = api.StartTraceW(ctypes.byref(self._handle), self.name, properties)
        if rc == types.ERROR_ALREADY_EXISTS:
            # 残留会话先停掉再重建
            api.ControlTraceW(
                types.TRACEHANDLE(0), self.name, properties, types.EVENT_TRACE_CONTROL_STOP
            )
            rc = api.StartTraceW(ctypes.byref(self._handle), self.name, properties)
        if rc != types.ERROR_SUCCESS:
            raise EtwSessionError(
                f"StartTraceW 失败: {rc} ({ctypes.FormatError(rc).strip()})"
            )
        self._started = True

    def enable(self, provider):
        if not self._started:
            raise EtwSessionError("会话尚未启动")
        guid = types.guid_from_string(provider.guid)
        rc = api.EnableTraceEx2(
            self._handle,
            ctypes.byref(guid),
            types.EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            provider.level,
            provider.keywords,
            0,
            0,
            None,
        )
        if rc != types.ERROR_SUCCESS:
            raise EtwSessionError(
                f"EnableTraceEx2 失败 ({provider.name}): {rc} "
                f"({ctypes.FormatError(rc).strip()})"
            )

    def query(self):
        """查询会话当前属性，失败时返回空字典。"""
        if not self._started:
            return {}
        buffer, properties = api.build_properties(self.name, **self._config)
        rc = api.ControlTraceW(
            types.TRACEHANDLE(0), self.name, properties, types.EVENT_TRACE_CONTROL_QUERY
        )
        if rc != types.ERROR_SUCCESS:
            del buffer
            return {}
        result = {
            "log_file_mode": properties.contents.LogFileMode,
            "buffers_written": properties.contents.BuffersWritten,
            "events_lost": properties.contents.EventsLost,
            "number_of_buffers": properties.contents.NumberOfBuffers,
            "free_buffers": properties.contents.FreeBuffers,
            "real_time_buffers_lost": properties.contents.RealTimeBuffersLost,
        }
        del buffer
        return result

    def stop(self):
        if not self._started or self._properties is None:
            return
        api.ControlTraceW(
            types.TRACEHANDLE(0), self.name, self._properties, types.EVENT_TRACE_CONTROL_STOP
        )
        self._started = False
        self._properties = None
        self._buffer_holder = None

    # -- 上下文管理 -------------------------------------------------------

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.stop()
        return False
