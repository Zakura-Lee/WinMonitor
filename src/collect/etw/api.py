"""ETW 相关 Win32 API 的 ctypes 绑定。

只封装本课题用到的函数，参数类型全部显式声明，
避免 64 位指针被截断成 32 位。
"""

import ctypes
from ctypes import wintypes

# 模块名为 etwtypes 而不是 types，避免与标准库 types 同名（脚本方式运行时会被遮蔽）
from . import etwtypes as types

advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
tdh = ctypes.WinDLL("tdh", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

PHANDLE = ctypes.POINTER(types.TRACEHANDLE)
PEVENT_TRACE_PROPERTIES = ctypes.POINTER(types.EVENT_TRACE_PROPERTIES)

# --- 会话管理 ---------------------------------------------------------------

StartTraceW = advapi32.StartTraceW
StartTraceW.argtypes = [PHANDLE, wintypes.LPCWSTR, PEVENT_TRACE_PROPERTIES]
StartTraceW.restype = wintypes.ULONG

ControlTraceW = advapi32.ControlTraceW
ControlTraceW.argtypes = [types.TRACEHANDLE, wintypes.LPCWSTR, PEVENT_TRACE_PROPERTIES, wintypes.ULONG]
ControlTraceW.restype = wintypes.ULONG

EnableTraceEx2 = advapi32.EnableTraceEx2
EnableTraceEx2.argtypes = [
    types.TRACEHANDLE,
    ctypes.POINTER(types.GUID),
    wintypes.ULONG,
    ctypes.c_ubyte,
    ctypes.c_ulonglong,
    ctypes.c_ulonglong,
    wintypes.ULONG,
    ctypes.c_void_p,
]
EnableTraceEx2.restype = wintypes.ULONG

# --- 消费 -------------------------------------------------------------------

OpenTraceW = advapi32.OpenTraceW
OpenTraceW.argtypes = [ctypes.POINTER(types.EVENT_TRACE_LOGFILEW)]
OpenTraceW.restype = types.TRACEHANDLE

ProcessTrace = advapi32.ProcessTrace
ProcessTrace.argtypes = [PHANDLE, wintypes.ULONG, ctypes.c_void_p, ctypes.c_void_p]
ProcessTrace.restype = wintypes.ULONG

CloseTrace = advapi32.CloseTrace
CloseTrace.argtypes = [types.TRACEHANDLE]
CloseTrace.restype = wintypes.ULONG

# --- 解码 -------------------------------------------------------------------

TdhGetEventInformation = tdh.TdhGetEventInformation
TdhGetEventInformation.argtypes = [
    ctypes.POINTER(types.EVENT_RECORD),
    wintypes.ULONG,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.POINTER(wintypes.ULONG),
]
TdhGetEventInformation.restype = wintypes.ULONG

# --- 杂项 -------------------------------------------------------------------

IsUserAnAdmin = ctypes.WinDLL("shell32", use_last_error=True).IsUserAnAdmin
IsUserAnAdmin.argtypes = []
IsUserAnAdmin.restype = wintypes.BOOL


def last_error():
    return ctypes.get_last_error()


def build_properties(session_name, buffer_size_kb=64, minimum_buffers=4, maximum_buffers=32):
    """构造 EVENT_TRACE_PROPERTIES 缓冲区（含会话名）。

    返回 (buffer, properties_pointer)。缓冲区必须保持存活直到会话结束，
    否则 StartTraceW 会读到已释放的内存。
    """
    name_bytes = (session_name + "\0").encode("utf-16-le")
    struct_size = ctypes.sizeof(types.EVENT_TRACE_PROPERTIES)
    total = struct_size + len(name_bytes)

    buffer = ctypes.create_string_buffer(total)
    properties = ctypes.cast(buffer, PEVENT_TRACE_PROPERTIES)

    properties.contents.Wnode.BufferSize = total
    properties.contents.Wnode.Flags = types.WNODE_FLAG_TRACED_GUID
    properties.contents.BufferSize = buffer_size_kb
    properties.contents.MinimumBuffers = minimum_buffers
    properties.contents.MaximumBuffers = maximum_buffers
    properties.contents.LogFileMode = types.EVENT_TRACE_REAL_TIME_MODE
    properties.contents.FlushTimer = 1
    properties.contents.LoggerNameOffset = struct_size
    properties.contents.LogFileNameOffset = 0

    ctypes.memmove(ctypes.addressof(buffer) + struct_size, name_bytes, len(name_bytes))
    return buffer, properties
