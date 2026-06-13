try:
    import pymysql
    from pymysql.err import MySQLError as Error
except ImportError as exc:
    raise ImportError(
        "Missing dependency PyMySQL. Please install it with `python -m pip install PyMySQL`."
    ) from exc
import config


def get_connection():
    conn = pymysql.connect(
        host=config.DB_HOST,
        port=config.DB_PORT,
        user=config.DB_USER,
        password=config.DB_PASSWORD,
        database=config.DB_NAME,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
    )
    conn.autocommit(True)
    return conn


def execute_query(query, params=None):
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(query, params or ())
        rows = cursor.fetchall()
        return rows
    finally:
        if cursor is not None:
            cursor.close()
        if conn is not None:
            conn.close()
