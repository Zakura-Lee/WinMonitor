from pathlib import Path
import config

try:
    import pymysql
except ImportError as exc:
    raise ImportError(
        "Missing dependency PyMySQL. Please install it with `python -m pip install PyMySQL`."
    ) from exc


def init_db():
    db_config = {
        "host": config.DB_HOST,
        "port": config.DB_PORT,
        "user": config.DB_USER,
        "password": config.DB_PASSWORD,
        "charset": "utf8mb4",
        "cursorclass": pymysql.cursors.DictCursor,
    }
    conn = pymysql.connect(**db_config)
    conn.autocommit(True)
    cursor = conn.cursor()
    try:
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{config.DB_NAME}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
        cursor.execute(f"USE `{config.DB_NAME}`")
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(64) NOT NULL UNIQUE,
                password_hash VARCHAR(256) NOT NULL,
                salt VARCHAR(64) NOT NULL,
                is_admin TINYINT(1) NOT NULL DEFAULT 0,
                last_seen TIMESTAMP NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """
        )
        # MySQL versions before 8.0 do not support "IF NOT EXISTS" on ADD COLUMN.
        # Check information_schema for the column first and only alter when missing.
        cursor.execute(
            "SELECT COUNT(1) as cnt FROM information_schema.COLUMNS "
            "WHERE TABLE_SCHEMA=%s AND TABLE_NAME='users' AND COLUMN_NAME='last_seen'",
            (config.DB_NAME,)
        )
        row = cursor.fetchone()
        if not row or row.get("cnt", 0) == 0:
            cursor.execute("ALTER TABLE users ADD COLUMN last_seen TIMESTAMP NULL")
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS logs (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(64) NOT NULL,
                category VARCHAR(64) NOT NULL,
                title VARCHAR(128) NOT NULL,
                message TEXT NOT NULL,
                severity VARCHAR(32) NOT NULL,
                source VARCHAR(64) DEFAULT 'system',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS user_requests (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(64) NOT NULL,
                request_type VARCHAR(64) NOT NULL,
                details TEXT,
                requested_password_hash VARCHAR(256),
                requested_salt VARCHAR(64),
                status VARCHAR(32) NOT NULL DEFAULT 'pending',
                reviewed_by VARCHAR(64),
                submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reviewed_at TIMESTAMP NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """
        )
    finally:
        cursor.close()
        conn.close()
