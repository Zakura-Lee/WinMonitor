#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
配置文件: config.py
功能: 存储 WinMonitor 的配置常量
"""

import json
import os
import secrets

import win32con

# 日志配置
LOG_FILE = "winmonitor.log"
LOG_MAX_BYTES = 5 * 1024 * 1024
LOG_BACKUP_COUNT = 3
LOG_LEVEL = "INFO"

# 进程监控配置
# 可疑执行路径按运行环境动态解析，避免写死某个用户名
_SYSTEM_ROOT = os.environ.get("SystemRoot", r"C:\Windows")
_USER_PROFILE = os.environ.get("USERPROFILE", "")

_TEMP_DIRS = [
    os.environ.get("TEMP", ""),
    os.environ.get("TMP", ""),
    os.path.join(_SYSTEM_ROOT, "Temp"),
]
_USER_DIRS = [os.path.join(_USER_PROFILE, name) for name in ("Desktop", "Downloads")]

SUS_PATH = [path for path in _TEMP_DIRS + _USER_DIRS if path]

SUS_PATH_WHITELIST = (
    [os.path.join(_USER_PROFILE, "Downloads", name) for name in ("setup.exe", "install.exe")]
    if _USER_PROFILE
    else []
)

SUS_CMD = [
    "-enc",
    "-encoded",
    "-encodedcommand",
    "-w hidden",
    "-windowstyle hidden",
    "-nop",
    "-nologo",
    "bitsadmin",
    "meterpreter",
    "reverse_shell",
]

SUS_PARENT = [
    "notepad.exe",
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
    os.path.join(_SYSTEM_ROOT, "System32", "cmd.exe"),
    os.path.join(_SYSTEM_ROOT, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
    os.path.join(_SYSTEM_ROOT, "System32", "svchost.exe"),
    os.path.join(_SYSTEM_ROOT, "System32", "services.exe"),
    os.path.join(_SYSTEM_ROOT, "System32", "lsass.exe"),
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
    "c:\\program files\\",
    "c:\\program files (x86)\\",
    "c:\\windows\\",
    "c:\\users\\default\\",
    "c:\\programdata\\microsoft\\windows\\store\\",
    "c:\\programdata\\microsoft\\windows\\softwaredistribution\\",
    "c:\\programdata\\microsoft\\windows\\updates\\",
    "c:\\program files\\windowsapps\\",
    "c:\\appdata\\local\\packages\\",
    "c:\\windows\\microsoft.net\\framework64\\v4.0.30319\\",
    "c:\\windows\\microsoft.net\\framework\\",
    "d:\\wps office\\",
    "c:\\program files (x86)\\microsoft office\\",
}

FILE_MONITOR_SENSITIVE_PATHS = {
    "c:\\users\\",
    "c:\\programdata\\",
    "c:\\windows\\system32\\",
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
HIGH_RISK_REMOTE_PORTS = {4444, 1337, 3389}
SQL_REMOTE_PORTS = {}
ATTACK_STATUSES = {"SYN_SENT"}
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
    "c:\\windows\\system32\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
    "c:\\program files\\windowsapps\\",
    "c:\\programdata\\microsoft\\windows\\store\\",
    "c:\\programdata\\microsoft\\windows\\softwaredistribution\\",
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

# 后端服务配置
SERVICE_HOST = "0.0.0.0"
SERVICE_PORT = 5000

# 应用密钥：优先取环境变量，其次读本地文件，都没有则生成并落盘
# 落盘位置位于 data/ 下，已在 .gitignore 中排除，不会进入版本库
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECRET_FILE = os.path.join(_PROJECT_ROOT, "data", "secrets.json")


def _load_secrets():
    """获取 JWT 与 Flask 会话密钥，保证跨重启稳定且不写死在源码里。"""
    env_jwt = os.environ.get("WINMON_JWT_SECRET", "").strip()
    env_app = os.environ.get("WINMON_APP_SECRET", "").strip()

    stored = {}
    try:
        with open(SECRET_FILE, "r", encoding="utf-8") as handler:
            stored = json.load(handler) or {}
    except (OSError, ValueError):
        stored = {}

    jwt_secret = env_jwt or str(stored.get("jwt_secret", "")).strip()
    app_secret = env_app or str(stored.get("app_secret", "")).strip()

    generated = False
    if not jwt_secret:
        jwt_secret = secrets.token_urlsafe(48)
        generated = True
    if not app_secret:
        app_secret = secrets.token_urlsafe(48)
        generated = True

    if generated:
        stored["jwt_secret"] = jwt_secret
        stored["app_secret"] = app_secret
        try:
            os.makedirs(os.path.dirname(SECRET_FILE), exist_ok=True)
            with open(SECRET_FILE, "w", encoding="utf-8") as handler:
                json.dump(stored, handler, indent=2)
            os.chmod(SECRET_FILE, 0o600)
        except OSError:
            # 落盘失败时密钥仅在本次进程内有效，不影响启动
            pass

    return jwt_secret, app_secret


JWT_SECRET, APP_SECRET_KEY = _load_secrets()

# MySQL 数据库配置
DB_HOST = "127.0.0.1"
DB_PORT = 3306
DB_USER = "root"
DB_PASSWORD = "123456"
DB_NAME = "winmonitor"

# 默认管理员账号（首次初始化时可手动修改）
ADMIN_DEFAULT_USERNAME = "admin"
ADMIN_DEFAULT_PASSWORD = "123456"

# 其他配置
MAX_ALERT_QUEUE_SIZE = 1000
THREAD_JOIN_TIMEOUT = 5