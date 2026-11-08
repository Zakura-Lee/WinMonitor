"""ETW 基础类型与常量定义。

对齐方式、字段顺序与 Windows SDK 中的 evntrace.h / evntcons.h 保持一致，
结构体大小由 tests/test_etw_structs.py 断言，避免后续改动悄悄破坏布局。
"""

import ctypes
from ctypes import wintypes

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

WNODE_FLAG_TRACED_GUID = 0x00020000

EVENT_TRACE_REAL_TIME_MODE = 0x00000100
EVENT_TRACE_FILE_MODE_SEQUENTIAL = 0x00000001
PROCESS_TRACE_MODE_REAL_TIME = 0x00000100
PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000
PROCESS_TRACE_MODE_RAW_TIMESTAMP = 0x00001000

EVENT_CONTROL_CODE_DISABLE_PROVIDER = 0
EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1

EVENT_TRACE_CONTROL_STOP = 1
EVENT_TRACE_CONTROL_QUERY = 0

TRACE_LEVEL_INFORMATION = 4
TRACE_LEVEL_VERBOSE = 5

ERROR_SUCCESS = 0
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_ALREADY_EXISTS = 183
ERROR_ACCESS_DENIED = 5

INVALID_PROCESSTRACE_HANDLE = 0xFFFFFFFFFFFFFFFF

# Kernel-Process 的关键字位：进程 / 线程 / 映像加载
WINEVENT_KEYWORD_PROCESS = 0x10
WINEVENT_KEYWORD_THREAD = 0x20
WINEVENT_KEYWORD_IMAGE = 0x40

# 事件 ID
EVENT_ID_PROCESS_START = 1
EVENT_ID_PROCESS_STOP = 2
EVENT_ID_IMAGE_LOAD = 5


# ---------------------------------------------------------------------------
# 基础结构
# ---------------------------------------------------------------------------

class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]

    def __str__(self):
        tail = "".join(f"{b:02x}" for b in self.Data4)
        return "{%08X-%04X-%04X-%s-%s}" % (
            self.Data1, self.Data2, self.Data3, tail[:4], tail[4:]
        )


def guid_from_string(text):
    """把 '{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}' 或 '22fb2cd6-...' 解析成 GUID。"""
    cleaned = text.strip().strip("{}").replace("-", "")
    if len(cleaned) != 32:
        raise ValueError(f"非法 GUID: {text!r}")
    try:
        parts = [int(cleaned[i: i + 2], 16) for i in range(0, 32, 2)]
    except ValueError as exc:
        raise ValueError(f"非法 GUID: {text!r}") from exc
    return GUID(
        int(cleaned[0:8], 16),
        int(cleaned[8:12], 16),
        int(cleaned[12:16], 16),
        (ctypes.c_ubyte * 8)(*parts[8:16]),
    )


TRACEHANDLE = ctypes.c_ulonglong


class WNODE_HEADER(ctypes.Structure):
    """联合体按最长成员展开，保证偏移正确。"""

    _fields_ = [
        ("BufferSize", wintypes.ULONG),
        ("ProviderId", wintypes.ULONG),
        ("HistoricalContext", ctypes.c_ulonglong),
        ("TimeStamp", ctypes.c_longlong),
        ("Guid", GUID),
        ("ClientContext", wintypes.ULONG),
        ("Flags", wintypes.ULONG),
    ]


class EVENT_TRACE_PROPERTIES(ctypes.Structure):
    _fields_ = [
        ("Wnode", WNODE_HEADER),
        ("BufferSize", wintypes.ULONG),
        ("MinimumBuffers", wintypes.ULONG),
        ("MaximumBuffers", wintypes.ULONG),
        ("MaximumFileSize", wintypes.ULONG),
        ("LogFileMode", wintypes.ULONG),
        ("FlushTimer", wintypes.ULONG),
        ("EnableFlags", wintypes.ULONG),
        ("AgeLimit", wintypes.LONG),
        ("NumberOfBuffers", wintypes.ULONG),
        ("FreeBuffers", wintypes.ULONG),
        ("EventsLost", wintypes.ULONG),
        ("BuffersWritten", wintypes.ULONG),
        ("LogBuffersLost", wintypes.ULONG),
        ("RealTimeBuffersLost", wintypes.ULONG),
        ("LoggerThreadId", wintypes.HANDLE),
        ("LogFileNameOffset", wintypes.ULONG),
        ("LoggerNameOffset", wintypes.ULONG),
    ]


class EVENT_TRACE_HEADER(ctypes.Structure):
    """EVENT_TRACE_HEADER，大小 48 字节。

    末尾是一个 8 字节联合体，三个候选成员共用同一块空间：
        struct { ULONG KernelTime; ULONG UserTime; }
        ULONG64 ProcessorTime
        struct { ULONG ClientContext; ULONG Flags; }
    这里按其中任一成员展开即可，切勿拆成两个独立字段（会多出 8 字节）。
    """

    _fields_ = [
        ("Size", wintypes.USHORT),
        ("FieldTypeFlags", wintypes.USHORT),
        ("Version", wintypes.ULONG),
        ("ThreadId", wintypes.ULONG),
        ("ProcessId", wintypes.ULONG),
        ("TimeStamp", ctypes.c_longlong),
        ("Guid", GUID),
        ("ProcessorTime", ctypes.c_ulonglong),
    ]


class EVENT_DESCRIPTOR(ctypes.Structure):
    _fields_ = [
        ("Id", wintypes.USHORT),
        ("Version", ctypes.c_ubyte),
        ("Channel", ctypes.c_ubyte),
        ("Level", ctypes.c_ubyte),
        ("Opcode", ctypes.c_ubyte),
        ("Task", wintypes.USHORT),
        ("Keyword", ctypes.c_ulonglong),
    ]


class EVENT_HEADER(ctypes.Structure):
    _fields_ = [
        ("Size", wintypes.USHORT),
        ("HeaderType", wintypes.USHORT),
        ("Flags", wintypes.USHORT),
        ("EventProperty", wintypes.USHORT),
        ("ThreadId", wintypes.ULONG),
        ("ProcessId", wintypes.ULONG),
        ("TimeStamp", ctypes.c_longlong),
        ("ProviderId", GUID),
        ("EventDescriptor", EVENT_DESCRIPTOR),
        ("ProcessorTime", ctypes.c_ulonglong),
        ("ActivityId", GUID),
    ]


class ETW_BUFFER_CONTEXT(ctypes.Structure):
    _fields_ = [
        ("ProcessorNumber", ctypes.c_ubyte),
        ("Alignment", ctypes.c_ubyte),
        ("LoggerId", wintypes.USHORT),
    ]


class EVENT_RECORD(ctypes.Structure):
    _fields_ = [
        ("EventHeader", EVENT_HEADER),
        ("BufferContext", ETW_BUFFER_CONTEXT),
        ("ExtendedDataCount", wintypes.USHORT),
        ("UserDataLength", wintypes.USHORT),
        ("ExtendedData", ctypes.c_void_p),
        ("UserData", ctypes.c_void_p),
        ("UserContext", ctypes.c_void_p),
    ]


class SYSTEMTIME(ctypes.Structure):
    _fields_ = [
        ("wYear", wintypes.WORD),
        ("wMonth", wintypes.WORD),
        ("wDayOfWeek", wintypes.WORD),
        ("wDay", wintypes.WORD),
        ("wHour", wintypes.WORD),
        ("wMinute", wintypes.WORD),
        ("wSecond", wintypes.WORD),
        ("wMilliseconds", wintypes.WORD),
    ]


class TIME_ZONE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Bias", wintypes.LONG),
        ("StandardName", wintypes.WCHAR * 32),
        ("StandardDate", SYSTEMTIME),
        ("StandardBias", wintypes.LONG),
        ("DaylightName", wintypes.WCHAR * 32),
        ("DaylightDate", SYSTEMTIME),
        ("DaylightBias", wintypes.LONG),
    ]


class _VersionDetail(ctypes.Structure):
    _fields_ = [
        ("MajorVersion", ctypes.c_ubyte),
        ("MinorVersion", ctypes.c_ubyte),
        ("SubVersion", ctypes.c_ubyte),
        ("SubMinorVersion", ctypes.c_ubyte),
    ]


class _VersionUnion(ctypes.Union):
    _fields_ = [("Version", wintypes.ULONG), ("Detail", _VersionDetail)]


class _InstanceParts(ctypes.Structure):
    _fields_ = [
        ("StartBuffers", wintypes.ULONG),
        ("PointerSize", wintypes.ULONG),
        ("EventsLost", wintypes.ULONG),
        ("CpuSpeedInMHz", wintypes.ULONG),
    ]


class _InstanceUnion(ctypes.Union):
    _fields_ = [("LogInstanceGuid", GUID), ("Parts", _InstanceParts)]


class TRACE_LOGFILE_HEADER(ctypes.Structure):
    _fields_ = [
        ("BufferSize", wintypes.ULONG),
        ("VersionUnion", _VersionUnion),
        ("ProviderVersion", wintypes.ULONG),
        ("NumberOfProcessors", wintypes.ULONG),
        ("EndTime", ctypes.c_longlong),
        ("TimerResolution", wintypes.ULONG),
        ("MaximumFileSize", wintypes.ULONG),
        ("LogFileMode", wintypes.ULONG),
        ("BuffersWritten", wintypes.ULONG),
        ("InstanceUnion", _InstanceUnion),
        ("LoggerName", ctypes.c_wchar_p),
        ("LogFileName", ctypes.c_wchar_p),
        ("TimeZone", TIME_ZONE_INFORMATION),
        ("BootTime", ctypes.c_longlong),
        ("PerfFreq", ctypes.c_longlong),
        ("StartTime", ctypes.c_longlong),
        ("ReservedFlags", wintypes.ULONG),
        ("BuffersLost", wintypes.ULONG),
    ]


class EVENT_TRACE(ctypes.Structure):
    _fields_ = [
        ("Header", EVENT_TRACE_HEADER),
        ("InstanceId", wintypes.ULONG),
        ("ParentInstanceId", wintypes.ULONG),
        ("ParentGuid", GUID),
        ("MofData", ctypes.c_void_p),
        ("MofLength", wintypes.ULONG),
        ("ClientContext", wintypes.ULONG),
    ]


# 回调类型需要引用 EVENT_TRACE_LOGFILEW，先做前向声明再填字段
class EVENT_TRACE_LOGFILEW(ctypes.Structure):
    pass


# 事件回调返回 void（SDK: VOID (WINAPI*)(PEVENT_RECORD)）
# 缓冲区回调返回 ULONG，非 0 表示继续处理
EVENT_RECORD_CALLBACK = ctypes.WINFUNCTYPE(None, ctypes.POINTER(EVENT_RECORD))
EVENT_TRACE_BUFFER_CALLBACKW = ctypes.WINFUNCTYPE(
    wintypes.ULONG, ctypes.POINTER(EVENT_TRACE_LOGFILEW)
)

EVENT_TRACE_LOGFILEW._fields_ = [
    ("LogFileName", ctypes.c_wchar_p),
    ("LoggerName", ctypes.c_wchar_p),
    ("CurrentTime", ctypes.c_longlong),
    ("BuffersRead", wintypes.ULONG),
    ("ProcessTraceMode", wintypes.ULONG),
    ("CurrentEvent", EVENT_TRACE),
    ("LogfileHeader", TRACE_LOGFILE_HEADER),
    ("BufferCallback", EVENT_TRACE_BUFFER_CALLBACKW),
    ("BufferSize", wintypes.ULONG),
    ("Filled", wintypes.ULONG),
    ("EventsLost", wintypes.ULONG),
    ("EventRecordCallback", EVENT_RECORD_CALLBACK),
    ("IsKernelTrace", wintypes.ULONG),
    ("Context", ctypes.c_void_p),
]
