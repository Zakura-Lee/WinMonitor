from db.connection import get_connection
from models.user_model import update_user_password, delete_user


def create_request(username, request_type, details=None, requested_password_hash=None, requested_salt=None):
    query = """
        INSERT INTO user_requests
        (username, request_type, details, requested_password_hash, requested_salt, status)
        VALUES (%s, %s, %s, %s, %s, 'pending')
    """
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(query, (username, request_type, details, requested_password_hash, requested_salt))
        conn.commit()
        return cursor.lastrowid
    finally:
        cursor.close()
        conn.close()


def get_pending_requests():
    query = "SELECT id, username, request_type, details, status, submitted_at FROM user_requests WHERE status='pending' ORDER BY submitted_at DESC"
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(query)
        return cursor.fetchall()
    finally:
        cursor.close()
        conn.close()


def get_requests_for_user(username):
    query = "SELECT id, username, request_type, details, status, submitted_at, reviewed_by, reviewed_at FROM user_requests WHERE username=%s ORDER BY submitted_at DESC"
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(query, (username,))
        return cursor.fetchall()
    finally:
        cursor.close()
        conn.close()


def get_request_by_id(request_id):
    query = "SELECT * FROM user_requests WHERE id=%s"
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(query, (request_id,))
        return cursor.fetchone()
    finally:
        cursor.close()
        conn.close()


def review_request(request_id, approve, reviewer):
    request_row = get_request_by_id(request_id)
    if not request_row or request_row["status"] != "pending":
        return False

    conn = get_connection()
    try:
        cursor = conn.cursor()
        if approve:
            if request_row["request_type"] in {"password_change", "forgot_password"}:
                if request_row["requested_password_hash"] and request_row["requested_salt"]:
                    updated = update_user_password(
                        request_row["username"],
                        None,
                        request_row["requested_password_hash"],
                        request_row["requested_salt"],
                    )
                    if not updated:
                        return False
                else:
                    return False
            elif request_row["request_type"] == "delete_account":
                deleted = delete_user(request_row["username"])
                if not deleted:
                    return False

            cursor.execute(
                "UPDATE user_requests SET status=%s, reviewed_by=%s, reviewed_at=NOW() WHERE id=%s",
                ("approved", reviewer, request_id),
            )
        else:
            cursor.execute(
                "UPDATE user_requests SET status=%s, reviewed_by=%s, reviewed_at=NOW() WHERE id=%s",
                ("denied", reviewer, request_id),
            )
        conn.commit()
        return True
    finally:
        cursor.close()
        conn.close()
