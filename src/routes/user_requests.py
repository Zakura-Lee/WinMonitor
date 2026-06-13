from flask import Blueprint, request, jsonify
from routes.auth_utils import auth_required
from models.user_request_model import create_request, get_requests_for_user
from models.log_model import insert_log
from utils.security import hash_password

requests_bp = Blueprint("user_requests", __name__)


@requests_bp.route("/requests", methods=["POST"])
@auth_required
def submit_request():
    data = request.get_json(silent=True) or {}
    user = request.user
    request_type = data.get("request_type", "").strip()
    details = data.get("details", "").strip()
    new_password = data.get("new_password", "")

    if request_type not in {"password_change", "forgot_password", "delete_account"}:
        return jsonify({"success": False, "message": "请求类型不合法。"}), 400

    requested_password_hash = None
    requested_salt = None
    if request_type in {"password_change", "forgot_password"}:
        if not new_password:
            return jsonify({"success": False, "message": "需要提供新密码。"}), 400
        requested_salt, requested_password_hash = hash_password(new_password)

    request_id = create_request(
        user["username"],
        request_type,
        details,
        requested_password_hash=requested_password_hash,
        requested_salt=requested_salt,
    )
    insert_log(
        "system",
        "admin_notification",
        "用户请求审批",
        f"用户 {user['username']} 提交 {request_type} 请求。",
        "info",
        source="user_request",
    )
    return jsonify({"success": True, "message": "请求已提交，管理员会尽快处理。", "request_id": request_id})


@requests_bp.route("/requests/mine", methods=["GET"])
@auth_required
def my_requests():
    user = request.user
    requests = get_requests_for_user(user["username"])
    return jsonify({"success": True, "requests": requests})
