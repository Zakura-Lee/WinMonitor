#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ETW 实时消费者。

设计约束:
    OpenTraceW 注册的回调运行在 ProcessTrace 的消费线程上，
    回调里只做「拷贝」不做「解析」，解析放到业务线程，
    这样高频事件下不会因为 Python 处理慢而丢缓冲。
"""

import ctypes
import threading

from ..model import FILETIME_EPOCH_DELTA, RawEvent
from . import api, etwtypes as types
from . import providers as provider_specs
from . import tdh
from .tdh import LayoutCache

# 只对这些事件做精确字段解码：每次解码都是一次 TDH API 往返，
# 高频事件（ImageLoad/ThreadStart）不应走这条路径。
# 值是要取的字段名（None 表示全部），用于高频事件做裁剪。
_KERNEL_GUID = provider_specs.guid_bytes(provider_specs.KERNEL_PROCESS.guid)
_SYSMON_GUID = provider_specs.guid_bytes(provider_specs.SYSMON.guid)

# 文件事件只取这几个字段：Sysmon 的 FileCreate/FileDelete 字段不多，
# 但两者都出现在高频路径上，裁剪后能省掉一半以上的 API 往返。
_FILE_FIELDS = ("UtcTime", "ProcessGuid", "ProcessId", "Image", "TargetFilename", "User")

_DECODE_EVENTS = {
    (_KERNEL_GUID, provider_specs.EVENT_PROCESS_START): None,
    (_KERNEL_GUID, provider_specs.EVENT_PROCESS_STOP): None,
    (_SYSMON_GUID, 1): None,
    (_SYSMON_GUID, 3): None,
    (_SYSMON_GUID, 5): None,
    (_SYSMON_GUID, 11): _FILE_FIELDS,   # FileCreate
    (_SYSMON_GUID, 23): _FILE_FIELDS,   # FileDelete
}

# 区分「没登记解码」与「登记了解码全部字段（值为 None）」
_NOT_DECODED = object()


class EtwConsumerError(RuntimeError):
    pass


class EtwConsumer:
    def __init__(self, session_name, sink, legacy=False):
        self.session_name = session_name
        self._sink = sink
        self._legacy = legacy

        self._logfile = None
        self._handle = types.TRACEHANDLE(0)
        self._thread = None
        self._started = False

        self._record_callback = types.EVENT_RECORD_CALLBACK(self._on_event)
        self._buffer_callback = types.EVENT_TRACE_BUFFER_CALLBACKW(self._on_buffer)
        self._layouts = LayoutCache()

        self.record_count = 0
        self.buffer_count = 0
        self.error_count = 0
        self.process_rc = None

    # -- 生命周期 ---------------------------------------------------------

    def start(self):
        if self._started:
            return

        logfile = types.EVENT_TRACE_LOGFILEW()
        logfile.LoggerName = self.session_name
        if self._legacy:
            logfile.ProcessTraceMode = types.PROCESS_TRACE_MODE_REAL_TIME
            logfile.EventRecordCallback = types.EVENT_RECORD_CALLBACK(
                ctypes.cast(self._record_callback, ctypes.c_void_p).value
            )
        else:
            logfile.ProcessTraceMode = (
                types.PROCESS_TRACE_MODE_REAL_TIME | types.PROCESS_TRACE_MODE_EVENT_RECORD
            )
            logfile.EventRecordCallback = self._record_callback
        logfile.BufferCallback = self._buffer_callback
        logfile.Context = None

        self._logfile = logfile
        handle = api.OpenTraceW(ctypes.pointer(logfile))
        if handle == types.INVALID_PROCESSTRACE_HANDLE:
            error = api.last_error()
            raise EtwConsumerError(
                f"OpenTraceW 失败: {error} ({ctypes.FormatError(error).strip()})"
            )

        self._handle = types.TRACEHANDLE(handle)
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._started = True

    def stop(self, timeout=5.0):
        if not self._started:
            return
        api.CloseTrace(self._handle)
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        self._started = False
        self._thread = None
        self._logfile = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.stop()
        return False

    # -- 内部 -------------------------------------------------------------

    def _run(self):
        self.process_rc = api.ProcessTrace(ctypes.byref(self._handle), 1, None, None)

    def _on_buffer(self, logfile_pointer):
        self.buffer_count += 1
        return 1

    def _on_event(self, record_pointer):
        try:
            record = record_pointer.contents
            header = record.EventHeader
            descriptor = header.EventDescriptor
            payload = b""
            if record.UserData and record.UserDataLength:
                payload = ctypes.string_at(record.UserData, record.UserDataLength)

            provider_id = bytes(header.ProviderId)
            # 布局按事件类型缓存，只有首次会真正调用 TDH
            event_name, properties = self._layouts.get(
                record, provider_id, descriptor.Id, descriptor.Version
            )

            decoded = {}
            wanted = _DECODE_EVENTS.get((provider_id, descriptor.Id), _NOT_DECODED)
            if wanted is not _NOT_DECODED and properties:
                try:
                    decoded = tdh.decode_fields(record, properties, wanted)
                except Exception:  # noqa: BLE001
                    decoded = {}

            raw = RawEvent(
                ts_ns=(header.TimeStamp - FILETIME_EPOCH_DELTA) * 100,
                provider_id=provider_id,
                event_id=descriptor.Id,
                level=descriptor.Level,
                keyword=descriptor.Keyword,
                pid=header.ProcessId,
                tid=header.ThreadId,
                payload=payload,
                version=descriptor.Version,
                event_name=event_name,
                properties=properties,
                decoded=decoded,
            )
            self.record_count += 1
            self._sink(raw)
        except Exception:  # noqa: BLE001 - 回调里抛异常会污染 ETW 运行时
            self.error_count += 1
        return None
