from flask import Blueprint, request, jsonify
from routes.auth_utils import admin_required
from models.user_model import get_users, delete_user
from models.log_model import get_logs_for_user
from models.user_request_model import get_pending_requests, review_request
from models.log_model import insert_log

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/admin/users", methods=["GET"])
@admin_required
def list_users():
    users = get_users(limit=500)
    now = __import__("datetime").datetime.now()
    for user in users:
        last_seen = user.get("last_seen")
        if last_seen:
            try:
                delta = now - last_seen
                user["online"] = delta.total_seconds() <= 300
                user["last_seen"] = last_seen.strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                user["online"] = False
                user["last_seen"] = str(last_seen)
        else:
            user["online"] = False
            user["last_seen"] = None
    return jsonify({"success": True, "users": users})


@admin_bp.route("/admin/requests", methods=["GET"])
@admin_required
def list_requests():
    requests_data = get_pending_requests()
    return jsonify({"success": True, "requests": requests_data})


@admin_bp.route("/admin/requests/<int:request_id>/review", methods=["POST"])
@admin_required
def review_user_request(request_id):
    payload = request.get_json(silent=True) or {}
    action = payload.get("action", "").strip().lower()
    if action not in {"approve", "deny"}:
        return jsonify({"success": False, "message": "审批动作必须为 approve 或 deny。"}), 400

    approved = action == "approve"
    admin_user = request.user["username"]
    success = review_request(request_id, approved, admin_user)
    if not success:
        return jsonify({"success": False, "message": "审批失败或请求不存在。"}), 400

    insert_log(
        "system",
        "admin_action",
        "用户请求审批",
        f"管理员 {admin_user} 已 {'批准' if approved else '拒绝'} 请求 {request_id}。",
        "info",
        source="admin",
    )
    return jsonify({"success": True, "message": "审批已处理。"})


@admin_bp.route("/admin/logs", methods=["GET"])
@admin_required
def admin_logs():
    logs = get_logs_for_user("system", is_admin=True, limit=1000)
    grouped = {}
    for log in logs:
        user = log["username"]
        category = log.get("category", "unknown")
        grouped.setdefault(user, {}).setdefault(category, []).append(log)
    return jsonify({"success": True, "logs_by_user": grouped})


@admin_bp.route("/admin/users/<string:username>/delete", methods=["POST"])
@admin_required
def admin_delete_user(username):
    current = request.user["username"]
    if username == current:
        return jsonify({"success": False, "message": "管理员不能删除自己的账号。"}), 400
    deleted = delete_user(username)
    if not deleted:
        return jsonify({"success": False, "message": "用户删除失败或用户不存在。"}), 400
    insert_log(
        "system",
        "admin_action",
        "用户注销",
        f"管理员 {current} 删除用户 {username}。",
        "info",
        source="admin",
    )
    return jsonify({"success": True, "message": "用户已删除。"})
