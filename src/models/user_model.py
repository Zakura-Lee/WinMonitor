from db.connection import get_connection
from utils.security import hash_password, verify_password


def create_user(username, password, is_admin=False):
    salt, password_hash = hash_password(password)
    query = "INSERT INTO users (username, password_hash, salt, is_admin) VALUES (%s, %s, %s, %s)"
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(query, (username, password_hash, salt, int(is_admin)))
        conn.commit()
        return True
    except Exception:
        return False
    finally:
        cursor.close()
        conn.close()


def get_user_by_username(username):
    query = "SELECT id, username, password_hash, salt, is_admin FROM users WHERE username=%s"
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(query, (username,))
        return cursor.fetchone()
    finally:
        cursor.close()
        conn.close()


def authenticate_user(username, password):
    user = get_user_by_username(username)
    if not user:
        return None
    if verify_password(password, user["salt"], user["password_hash"]):
        return {
            "id": user["id"],
            "username": user["username"],
            "is_admin": bool(user["is_admin"]),
        }
    return None


def verify_user_password(username, password):
    user = get_user_by_username(username)
    if not user:
        return False
    return verify_password(password, user["salt"], user["password_hash"])


def update_username(old_username, new_username):
    query = "UPDATE users SET username=%s WHERE username=%s"
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(query, (new_username, old_username))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        cursor.close()
        conn.close()


def get_admin_user():
    query = "SELECT id, username, is_admin FROM users WHERE is_admin=1 LIMIT 1"
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(query)
        return cursor.fetchone()
    finally:
        cursor.close()
        conn.close()


def get_users(limit=200):
    query = "SELECT id, username, is_admin, last_seen, created_at FROM users ORDER BY created_at DESC LIMIT %s"
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(query, (limit,))
        return cursor.fetchall()
    finally:
        cursor.close()
        conn.close()


def update_user_password(username, new_password=None, password_hash=None, salt=None):
    if new_password is not None:
        salt, password_hash = hash_password(new_password)
    if not password_hash or not salt:
        return False
    query = "UPDATE users SET password_hash=%s, salt=%s WHERE username=%s"
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(query, (password_hash, salt, username))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        cursor.close()
        conn.close()


def update_last_seen(username):
    if not username:
        return False
    query = "UPDATE users SET last_seen=NOW() WHERE username=%s"
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(query, (username,))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        cursor.close()
        conn.close()


def delete_user(username):
    query = "DELETE FROM users WHERE username=%s"
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(query, (username,))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        cursor.close()
        conn.close()


def ensure_admin_user(default_username, default_password):
    query = "SELECT id FROM users WHERE is_admin=1 LIMIT 1"
    conn = get_connection()
    cursor = None
    try:
        cursor = conn.cursor()
        cursor.execute(query)
        admin_exists = cursor.fetchone() is not None
    finally:
        if cursor is not None:
            cursor.close()
        conn.close()

    if not admin_exists:
        return create_user(default_username, default_password, is_admin=True)
    return True
