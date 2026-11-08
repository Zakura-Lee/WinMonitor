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


# 与参考实现保持一致：缓冲区按最大字符串长度预留，避免 ETW 回写名字时越界
MAX_STR_LEN = 1024


def build_properties(
    session_name,
    buffer_size_kb=64,
    minimum_buffers=4,
    maximum_buffers=32,
    log_file_path=None,
    real_time=True,
):
    """构造 EVENT_TRACE_PROPERTIES 缓冲区。

    返回 (buffer, properties_pointer)。缓冲区必须保持存活直到会话结束，
    否则 StartTraceW 会读到已释放的内存。

    注意: 会话名通过 StartTraceW 的 InstanceName 参数传入，
    这里不再把名字写进缓冲区，只把 Wnode.BufferSize 设成整块大小，
    与 pywintrace 等成熟实现保持一致。
    """
    struct_size = ctypes.sizeof(types.EVENT_TRACE_PROPERTIES)
    total = struct_size + 2 * ctypes.sizeof(ctypes.c_wchar) * MAX_STR_LEN

    buffer = ctypes.create_string_buffer(total)
    properties = ctypes.cast(buffer, PEVENT_TRACE_PROPERTIES)

    properties.contents.BufferSize = buffer_size_kb
    if minimum_buffers:
        properties.contents.MinimumBuffers = minimum_buffers
    if maximum_buffers:
        properties.contents.MaximumBuffers = maximum_buffers
    properties.contents.Wnode.Flags = types.WNODE_FLAG_TRACED_GUID
    properties.contents.LogFileMode = (
        types.EVENT_TRACE_REAL_TIME_MODE if real_time else types.EVENT_TRACE_FILE_MODE_SEQUENTIAL
    )
    properties.contents.Wnode.BufferSize = total
    properties.contents.LoggerNameOffset = struct_size

    if log_file_path:
        name_bytes = (session_name + "\0").encode("utf-16-le")
        path_bytes = (log_file_path + "\0").encode("utf-16-le")
        ctypes.memmove(ctypes.addressof(buffer) + struct_size, name_bytes, len(name_bytes))
        path_offset = struct_size + len(name_bytes)
        properties.contents.LogFileNameOffset = path_offset
        ctypes.memmove(ctypes.addressof(buffer) + path_offset, path_bytes, len(path_bytes))
    else:
        properties.contents.LogFileNameOffset = 0

    return buffer, properties
