from functools import wraps
from flask import request, jsonify
from utils.security import verify_token
from models.user_model import update_last_seen


def auth_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"success": False, "message": "缺少认证令牌。"}), 401
        token = auth_header.split(" ", 1)[1].strip()
        payload = verify_token(token)
        if not payload:
            return jsonify({"success": False, "message": "无效或已过期的令牌。"}), 401
        request.user = payload
        try:
            update_last_seen(payload.get("username"))
        except Exception:
            pass
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"success": False, "message": "缺少认证令牌。"}), 401
        token = auth_header.split(" ", 1)[1].strip()
        payload = verify_token(token)
        if not payload:
            return jsonify({"success": False, "message": "无效或已过期的令牌。"}), 401
        if not payload.get("is_admin"):
            return jsonify({"success": False, "message": "管理员权限不足。"}), 403
        request.user = payload
        try:
            update_last_seen(payload.get("username"))
        except Exception:
            pass
        return fn(*args, **kwargs)
    return wrapper
