#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
配置文件: config.py
功能: 存储 WinMonitor 的配置常量
"""

import win32con

# 日志配置
LOG_FILE = "winmonitor.log"
LOG_MAX_BYTES = 5 * 1024 * 1024
LOG_BACKUP_COUNT = 3
LOG_LEVEL = "INFO"

# 进程监控配置
SUS_PATH = [
    r"c:\\users\\admin\\appdata\\local\\temp\\",
    r"c:\\users\\admin\\desktop\\",
    r"c:\\users\\admin\\downloads\\",
    r"c:\\windows\\temp\\",
]

SUS_CMD = [
    "-enc",
    "-encoded",
    "-encodedcommand",
    "-w hidden",
    "-windowstyle hidden",
    "-nop",
    "-nologo",
    "certutil",
    "bitsadmin",
    "regsvr32",
    "rundll32",
    "whoami",
    "setuid",
    "meterpreter",
    "reverse_shell",
]

SUS_PARENT = [
    "notepad.exe",
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
]

SUS_STATUS = ["zombie", "parked", "stopped"]
SUS_CPU = 70
SUS_MEM = 300  # MB
CRITICAL_CPU = 85
CRITICAL_MEM = 500

# 系统进程白名单
SYS_PROCESS_WHITELIST = {
    "lockapp.exe",
    "systemsettings.exe",
    "backgroundtaskhost.exe",
    "searchhost.exe",
    "shellexperiencehost.exe",
    "textinputhost.exe",
    "winlogon.exe",
    "storedesktopextension.exe",
    "wsappx.exe",
    "apphost.exe",
    "appinstaller.exe",
    "storebroker.exe",
    "wuauclt.exe",
    "usoclient.exe",
    "wusa.exe",
    "runtimebroker.exe",
    "svchost.exe",
    "services.exe",
    "csrss.exe",
    "smss.exe",
    "taskhostw.exe",
    "taskhost.exe",
    "dwm.exe",
    "explorer.exe",
    "calculator.exe",
    "photos.exe",
    "mail.exe",
    "calendar.exe",
    "weather.exe",
    "yourphone.exe",
    "maps.exe",
    "alarmsandclock.exe",
    "ctfmon.exe",
    "tabtip.exe",
    "mrt.exe",
    "audiodg.exe",
    "fontdrvhost.exe",
    "conhost.exe",
    "taskeng.exe",
    "lsass.exe",
    "spoolsv.exe",
    "wininit.exe",
    "trustedinstaller.exe",
}

# 完整性检查目标
INTEGRITY_TARGETS = [
    r"C:\\Windows\\System32\\cmd.exe",
    r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    r"C:\\Windows\\System32\\svchost.exe",
    r"C:\\Windows\\System32\\services.exe",
    r"C:\\Windows\\System32\\lsass.exe",
]

# 文件监控配置
IGNORE_EXTENSIONS = {
    ".tmp",
    ".swp",
    ".log",
    ".lock",
}

IGNORE_DIRECTORIES = {
    "__pycache__",
    ".git",
    "node_modules",
}

DANGEROUS_FILE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".jar",
}

FILE_MONITOR_TRUSTED_PATHS = {
    r"c:\\program files\\",
    r"c:\\program files (x86)\\",
    r"c:\\windows\\",
    r"c:\\users\\default\\",
    r"c:\\programdata\\microsoft\\windows\\store\\",
    r"c:\\programdata\\microsoft\\windows\\softwaredistribution\\",
    r"c:\\programdata\\microsoft\\windows\\updates\\",
    r"c:\\program files\\windowsapps\\",
    r"c:\\appdata\\local\\packages\\",
    r"c:\\windows\\microsoft.net\\framework64\\v4.0.30319\\",
    r"c:\\windows\\microsoft.net\\framework\\",
    r"d:\\wps office\\",
    r"c:\\program files (x86)\\microsoft office\\",
}

FILE_MONITOR_SENSITIVE_PATHS = {
    r"c:\\users\\",
    r"c:\\programdata\\",
    r"c:\\windows\\system32\\",
}

IGNORED_FILENAME_PATTERNS = {
    "tclindex",
    "bgerror.tcl",
}

FILE_MONITOR_EVENT_SCORE_THRESHOLD = 2

WHITELISTED_CACHE_PATTERNS = [
    "\\tencent\\wechat",
    "\\wechat\\",
    "\\appdata\\local\\temp",
    "\\windows\\temp",
    "\\google\\chrome\\user data",
    "\\microsoft\\edge\\user data",
    "\\mozilla\\firefox\\profiles",
    "\\cache\\",
    "\\cache2\\",
    "\\appdata\\roaming\\code\\",
    "\\appdata\\local\\programs\\microsoft vs code\\",
    "\\appdata\\roaming\\code - oss\\",
    "\\appdata\\roaming\\code\\storage\\",
]

SYSTEM_MAINTENANCE_PATTERNS = [
    "\\windows\\softwaredistribution",
    "\\windows\\winsxs",
    "\\windows\\servicing",
    "\\windows\\system32\\config",
    "\\programdata\\microsoft\\windows\\updates",
    "\\programdata\\microsoft\\windows\\store",
    "\\programdata\\microsoft\\windows\\softwaredistribution\\download",
    "\\programdata\\microsoft\\windows\\softwaredistribution\\datastore",
    "\\program files\\windowsapps\\",
    "\\appdata\\local\\packages\\",
    "\\windows\\microsoft.net\\framework64\\v4.0.30319\\",
    "\\windows\\microsoft.net\\framework\\",
    "\\wps office\\",
    "\\microsoft office\\",
]

WINDOWS_SYSTEM_PATTERNS = [
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\windows\\system\\",
]

# 网络监控配置
HIGH_RISK_REMOTE_PORTS = {4444, 1337, 3389, 445}
SQL_REMOTE_PORTS = {1433, 3306, 5432, 1521, 1434, 33060}
ATTACK_STATUSES = {"SYN_SENT", "SYN_RECV"}
SAFE_PUBLIC_PORTS = {80, 443, 53, 123, 25, 587, 110, 995, 993, 143, 7680}
PRIVATE_PREFIXES = ("10.", "172.", "192.168.", "127.")
NETWORK_TRUSTED_PROCESS_NAMES = {
    "chrome.exe",
    "firefox.exe",
    "msedge.exe",
    "explorer.exe",
    "code.exe",
    "onedrive.exe",
    "wsappx.exe",
    "appinstaller.exe",
    "storebroker.exe",
    "wuauclt.exe",
    "usoclient.exe",
    "wusa.exe",
    "svchost.exe",
    "system",
    "taskhost.exe",
    "taskeng.exe",
    "sihost.exe",
    "runtimebroker.exe",
    "searchui.exe",
    "shellexperiencehost.exe",
    "tiworker.exe",
    "ngentask.exe",
    "trustedinstaller.exe",
}
NETWORK_TRUSTED_PROCESS_PATHS = {
    r"c:\\windows\\system32\\",
    r"c:\\program files\\",
    r"c:\\program files (x86)\\",
    r"c:\\program files\\windowsapps\\",
    r"c:\\programdata\\microsoft\\windows\\store\\",
    r"c:\\programdata\\microsoft\\windows\\softwaredistribution\\",
}
PROCESS_TRUSTED_PARENT_NAMES = {
    "svchost.exe",
    "tiworker.exe",
    "ngentask.exe",
    "wuauclt.exe",
    "trustedinstaller.exe",
    "wps.exe",
    "et.exe",
    "wpp.exe",
}
NETWORK_TRUSTED_REMOTE_HOST_PATTERNS = [
    "github.com",
    "githubusercontent.com",
    "githubassets.com",
    "tencentcloud.com",
    "qcloud.com",
    "tencent.com",
    "qq.com",
    "cloud.tencent.com",
    "windowsupdate.com",
    "microsoft.com",
    "update.microsoft.com",
    "download.windowsupdate.com",
    "delivery.mp.microsoft.com",
    "windowsupdate.microsoft.com",
    "officecdn.microsoft.com",
    "microsoftonline.com",
    "microsoftstore.com",
    "microsoft.com.cn",
    "tencentcloud.com",
    "qcloud.com",
    "tencent.com",
    "qq.com",
    "cloud.tencent.com",
]
NETWORK_SUSPICION_SCORE_THRESHOLD = 2
NETWORK_HIGH_RISK_SCORE = 2
NETWORK_STATUS_SCORE = 1
NETWORK_PROCESS_SCORE = 1
NETWORK_REMOTE_SCORE = 1
TEMP_PATH_PATTERNS = ("\\temp\\", "\\appdata\\local\\temp", "\\windows\\temp")
SUSPICIOUS_PARENT_NAMES = {
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "wmic.exe",
    "mshta.exe",
    "svchost.exe",
}

PROCESS_TRUSTED_PATHS = {
    "c:\\windows\\system32\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
}

PROCESS_SUSPICION_SCORE_THRESHOLD = 2
PROCESS_CRITICAL_SCORE = 4
PROCESS_RESOURCE_SCORE = 1
PROCESS_HASH_SCORE = 3
PROCESS_CMDLINE_SCORE = 1
PROCESS_PARENT_SCORE = 1
PROCESS_PATH_SCORE = 1
PROCESS_STATUS_SCORE = 1
PROCESS_SUMMARY_INTERVAL = 60

# 注册表监控配置
MONITORED_REGISTRY = [
    (win32con.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (win32con.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (win32con.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services"),
]

SUSPICIOUS_REGISTRY_PATTERNS = [
    "powershell",
    "cmd.exe",
    "rundll32",
    "regsvr32",
    "wmic",
    "schtasks",
    "bcdedit",
    "vssadmin",
    "netsh",
]

REGISTRY_SAFE_PATTERNS = [
    "microsoft\\windows\\currentversion\\runonce",
    "microsoft\\windows\\currentversion\\runservice",
    "microsoft\\windows\\task scheduler",
]

# 审计日志配置
SUSPICIOUS_EVENT_IDS = {
    4688: "可疑进程创建",
    4625: "登录失败",
    4720: "新用户创建",
    7045: "可疑服务安装",
    1102: "审计日志被清除",
    4648: "显式凭证使用",
}

MONITORED_LOGS = ["Security", "System", "Application"]

# 监控间隔（秒）
PROCESS_MON_INTERVAL = 1
FILE_MON_INTERVAL = 0.5
REGISTRY_MON_INTERVAL = 3
AUDIT_MON_INTERVAL = 8
ASSET_MON_INTERVAL = 60

# 其他配置
MAX_ALERT_QUEUE_SIZE = 1000
THREAD_JOIN_TIMEOUT = 5