import json
from pathlib import Path
from datetime import datetime
from db.connection import get_connection

LOG_BACKUP_DIR = Path(__file__).resolve().parents[2] / "logs"
LOG_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
LOG_BACKUP_FILE = LOG_BACKUP_DIR / "backup.log"

# 日志类型中文映射
CATEGORY_CN_MAP = {
    "file": "文件监控",
    "process": "进程监控",
    "network": "网络监控",
    "registry": "注册表监控",
    "audit": "审计日志",
    "asset": "资产清点",
    "user": "用户变更",
    "admin_action": "管理员操作",
    "monitor": "监控事件",
}

# 监控日志类型列表（用于区分监控日志和用户变更日志）
MONITOR_CATEGORIES = {"file", "process", "network", "registry", "audit", "asset", "monitor"}


def get_category_cn(category):
    """获取日志类型的中文名称"""
    return CATEGORY_CN_MAP.get(category, category)


def add_category_cn_to_logs(logs):
    """为日志列表添加中文类型名称"""
    for log in logs:
        log["category_cn"] = get_category_cn(log.get("category", ""))
    return logs


def insert_log(username, category, title, message, severity, source="system"):
    query = "INSERT INTO logs (username, category, title, message, severity, source) VALUES (%s, %s, %s, %s, %s, %s)"
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(query, (username, category, title, message, severity, source))
        conn.commit()
    finally:
        cursor.close()
        conn.close()

    try:
        entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "username": username,
            "category": category,
            "title": title,
            "message": message,
            "severity": severity,
            "source": source,
        }
        with LOG_BACKUP_FILE.open("a", encoding="utf-8") as backup:
            backup.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass


def get_logs_for_user(username, is_admin=False, limit=500):
    if is_admin:
        query = "SELECT id, username, category, title, message, severity, source, created_at FROM logs ORDER BY created_at DESC LIMIT %s"
        params = (limit,)
    else:
        query = (
            "SELECT id, username, category, title, message, severity, source, created_at "
            "FROM logs WHERE username=%s "
            "ORDER BY created_at DESC LIMIT %s"
        )
        params = (username, limit)
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(query, params)
        return cursor.fetchall()
    finally:
        cursor.close()
        conn.close()


def get_recent_summary(username, is_admin=False):
    if is_admin:
        query = "SELECT COUNT(*) AS total FROM logs WHERE created_at >= NOW() - INTERVAL 1 MINUTE"
        params = ()
    else:
        query = (
            "SELECT COUNT(*) AS total FROM logs "
            "WHERE username=%s "
            "AND created_at >= NOW() - INTERVAL 1 MINUTE"
        )
        params = (username,)
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(query, params)
        result = cursor.fetchone()
        return result["total"] if result else 0
    finally:
        cursor.close()
        conn.close()
