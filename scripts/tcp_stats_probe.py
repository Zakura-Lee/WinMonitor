#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TCP 连接统计探针

背景：Kernel-Network 事件的方向与字节数难以稳定解读，
改用 GetExtendedTcpTable + GetPerTcpConnectionEStats：
    前者列出当前所有 TCP 连接（含 5 元组与所属 PID）
    后者对单个连接读取精确的收发字节数与包数

这两个 API 提供的数据正是 UNSW-NB15 里 sbytes/dbytes/spkts/dpkts 的含义。

用法:
    python scripts/tcp_stats_probe.py
"""

import ctypes
import os
import socket
import struct
import sys
import threading
import time
from ctypes import wintypes

_iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)

AF_INET = 2
TCP_TABLE_OWNER_PID_ALL = 5
TcpConnectionEstatsData = 1
NO_ERROR = 0
ERROR_INSUFFICIENT_BUFFER = 122


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", wintypes.DWORD),
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwRemoteAddr", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]


class MIB_TCPTABLE_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwNumEntries", wintypes.DWORD),
        ("table", MIB_TCPROW_OWNER_PID * 1),
    ]


class TCP_ESTATS_DATA_ROD_v0(ctypes.Structure):
    _fields_ = [
        ("DataBytesOut", ctypes.c_ulonglong),
        ("DataSegsOut", ctypes.c_ulonglong),
        ("DataBytesIn", ctypes.c_ulonglong),
        ("DataSegsIn", ctypes.c_ulonglong),
        ("SegsOut", ctypes.c_ulonglong),
        ("SegsIn", ctypes.c_ulonglong),
        ("SoftErrors", wintypes.ULONG),
        ("SoftErrorReason", wintypes.ULONG),
        ("SndUna", wintypes.ULONG),
        ("SndNxt", wintypes.ULONG),
        ("SndMax", wintypes.ULONG),
        ("ThruBytesAcked", ctypes.c_ulonglong),
        ("RcvNxt", wintypes.ULONG),
        ("ThruBytesReceived", ctypes.c_ulonglong),
    ]


class MIB_TCPROW(ctypes.Structure):
    _fields_ = [
        ("dwState", wintypes.DWORD),
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwRemoteAddr", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
    ]


def _addr_to_int(text):
    return struct.unpack("<I", socket.inet_aton(text))[0]


def _port_to_int(port):
    # 端口在网络结构中按网络字节序存放，这里换算成 DWORD 的低 16 位
    return ((port & 0xFF) << 8) | ((port >> 8) & 0xFF)


def list_tcp_connections():
    """返回 [(local_ip, local_port, remote_ip, remote_port, pid, state)]。"""
    size = wintypes.DWORD(0)
    result = _iphlpapi.GetExtendedTcpTable(
        None, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0
    )
    buffer = ctypes.create_string_buffer(size.value)
    result = _iphlpapi.GetExtendedTcpTable(
        buffer, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0
    )
    if result != NO_ERROR:
        raise OSError(f"GetExtendedTcpTable 失败: {result}")

    table = ctypes.cast(buffer, ctypes.POINTER(MIB_TCPTABLE_OWNER_PID)).contents
    count = int(table.dwNumEntries)
    # 结构里 table 声明为长度 1 的数组，超过下标 1 会越界，
    # 因此从 dwNumEntries 之后的偏移重新按行指针遍历
    rows = ctypes.cast(
        ctypes.byref(buffer, ctypes.sizeof(wintypes.DWORD)),
        ctypes.POINTER(MIB_TCPROW_OWNER_PID),
    )
    entries = []
    for index in range(count):
        row = rows[index]
        entries.append(
            (
                socket.inet_ntoa(struct.pack("<I", row.dwLocalAddr)),
                socket.ntohs(row.dwLocalPort & 0xFFFF),
                socket.inet_ntoa(struct.pack("<I", row.dwRemoteAddr)),
                socket.ntohs(row.dwRemotePort & 0xFFFF),
                row.dwOwningPid,
                row.dwState,
            )
        )
    return entries


class TCP_ESTATS_DATA_RW_v0(ctypes.Structure):
    _fields_ = [("EnableCollection", ctypes.c_ubyte)]


def enable_data_stats(local_ip, local_port, remote_ip, remote_port):
    """EStats 需要先逐连接启用采集，否则读出来的 ROD 是未初始化内存。"""
    row = MIB_TCPROW()
    row.dwState = 5
    row.dwLocalAddr = _addr_to_int(local_ip)
    row.dwLocalPort = _port_to_int(local_port)
    row.dwRemoteAddr = _addr_to_int(remote_ip)
    row.dwRemotePort = _port_to_int(remote_port)

    rw = TCP_ESTATS_DATA_RW_v0(1)
    result = _iphlpapi.SetPerTcpConnectionEStats(
        ctypes.byref(row),
        TcpConnectionEstatsData,
        ctypes.byref(rw), 0, ctypes.sizeof(rw),
        None, 0, 0,
        None, 0, 0,
    )
    return result


def read_data_stats(local_ip, local_port, remote_ip, remote_port):
    """读取单个连接的收发统计，返回 (dict, 返回码)。"""
    row = MIB_TCPROW()
    row.dwState = 5  # MIB_TCP_STATE_ESTAB
    row.dwLocalAddr = _addr_to_int(local_ip)
    row.dwLocalPort = _port_to_int(local_port)
    row.dwRemoteAddr = _addr_to_int(remote_ip)
    row.dwRemotePort = _port_to_int(remote_port)

    data = TCP_ESTATS_DATA_ROD_v0()
    result = _iphlpapi.GetPerTcpConnectionEStats(
        ctypes.byref(row),
        TcpConnectionEstatsData,
        None, 0, 0,          # Rw（启用开关）
        None, 0, 0,          # Ros（只读静态）
        ctypes.byref(data), 0, ctypes.sizeof(data),  # Rod（只读动态）
    )
    if result != NO_ERROR:
        return None, result
    return (
        {
            "bytes_out": data.DataBytesOut,
            "bytes_in": data.DataBytesIn,
            "segs_out": data.DataSegsOut,
            "segs_in": data.DataSegsIn,
            "thru_acked": data.ThruBytesAcked,
            "thru_received": data.ThruBytesReceived,
        },
        result,
    )


def main():
    is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    print(f"[INFO] 进程 PID = {os.getpid()}")
    print(f"[INFO] 管理员权限 = {is_admin}")
    if not is_admin:
        print()
        print("[STOP] 这个探针必须在管理员窗口里运行。")
        print("       EStats 的启用接口 SetPerTcpConnectionEStats 需要管理员，")
        print("       非提权下会返回 5（拒绝访问）。")
        return 3

    # 回环连接在很多 Windows 版本上不支持 EStats 采集，
    # 因此用一条真实外网连接来验证。
    target = ("223.5.5.5", 443)
    try:
        client = socket.create_connection(target, timeout=5)
    except OSError as exc:
        print(f"[STOP] 无法连接 {target}: {exc}")
        return 4

    local_ip, local_port = client.getsockname()[:2]
    remote_ip, remote_port = client.getpeername()[:2]
    print(f"[INFO] 已建立连接 {local_ip}:{local_port} -> {remote_ip}:{remote_port}")

    try:
        entries = [
            e for e in list_tcp_connections()
            if e[1] == local_port and e[3] == remote_port
        ]
        print(f"[INFO] 表里匹配到的行: {entries}")
        if not entries:
            print("[STOP] GetExtendedTcpTable 没有列出这条连接")
            return 5

        # 先启用采集，再发数据，否则统计只从启用那一刻开始计
        rc = enable_data_stats(local_ip, local_port, remote_ip, remote_port)
        print(f"[INFO] 启用采集返回码 = {rc}"
              f"{'（0=成功）' if rc == 0 else '（5=拒绝访问，其它见 Win32 错误码）'}")

        payload = b"Z" * 4096
        sent = 0
        try:
            for _ in range(8):
                sent += client.send(payload)
        except OSError as exc:
            print(f"[INFO] 发送中断: {exc}")
        print(f"[INFO] 已发送 {sent} 字节")

        stats = None
        last_rc = None
        for attempt in range(4):
            time.sleep(0.4)
            stats, last_rc = read_data_stats(local_ip, local_port, remote_ip, remote_port)
            print(f"[INFO] 第 {attempt + 1} 次读取: 返回码={last_rc}  统计={stats}")
            if stats is not None:
                break

        if stats is None:
            print()
            print(f"[STOP] 读取失败，返回码 {last_rc}")
            print("       常见返回码: 87=参数错误  122=缓冲区不足  50=不支持")
            return 6

        print()
        print(f"[INFO] 实际发送 {sent} 字节，统计报告发送 {stats['bytes_out']} 字节")
        if stats["bytes_out"] > 0:
            print()
            print("结论: EStats 可用，可作为精确计数源。")
            return 0
        print()
        print("结论: 接口通了但计数为 0，可能需在连接建立时就启用。")
        return 7
    finally:
        try:
            client.close()
        except OSError:
            pass


if __name__ == "__main__":
    sys.exit(main())
