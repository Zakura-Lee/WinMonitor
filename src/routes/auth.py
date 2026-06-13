import re

from flask import Blueprint, request, jsonify
from models.user_model import (
    create_user,
    authenticate_user,
    get_user_by_username,
    update_last_seen,
    verify_user_password,
    update_username,
    update_user_password,
    delete_user,
)
from models.log_model import insert_log
from models.user_request_model import create_request
from routes.auth_utils import auth_required
from utils.security import generate_token, hash_password

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    confirm_password = data.get("confirm_password", "")
    if not username or not password:
        return jsonify({"success": False, "message": "用户名和密码不能为空。"}), 400
    if not is_username_valid(username):
        return jsonify({"success": False, "message": "用户名长度 3-32 位，仅支持字母、数字、下划线、点和短划线。"}), 400
    if password != confirm_password:
        return jsonify({"success": False, "message": "两次密码输入不一致。"}), 400
    if get_user_by_username(username):
        return jsonify({"success": False, "message": "用户名已存在。"}), 409

    user_type = data.get("user_type", "normal")
    is_admin = False
    if user_type == "admin":
        # 只有当当前系统中还没有管理员时，才能创建管理员账号
        from models.user_model import get_admin_user

        if get_admin_user():
            return jsonify({"success": False, "message": "管理员账号已存在，无法创建新的管理员。"}), 403
        is_admin = True

    created = create_user(username, password, is_admin=is_admin)
    if not created:
        return jsonify({"success": False, "message": "用户创建失败，请检查数据库配置。"}), 500

    insert_log(
        "system",
        "user",
        "用户注册",
        f"用户 {username} 已完成注册。",
        "info",
        source="system",
    )

    return jsonify({"success": True, "message": "注册成功，请登录。"})


def is_username_valid(username):
    return bool(re.match(r"^[A-Za-z0-9_.-]{3,32}$", username))


def is_password_strong(password):
    return len(password) >= 8 and bool(re.search(r"[A-Za-z]", password)) and bool(re.search(r"\d", password))


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"success": False, "message": "用户名和密码不能为空。"}), 400

    user = authenticate_user(username, password)
    if not user:
        return jsonify({"success": False, "message": "用户名或密码错误。"}), 401

    user_type = data.get("user_type", "normal")
    if user_type == "admin" and not user["is_admin"]:
        return jsonify({"success": False, "message": "该账号不是管理员，请选择普通用户。"}), 403
    if user_type == "normal" and user["is_admin"]:
        return jsonify({"success": False, "message": "该账号是管理员，请选择管理员登录。"}), 403

    update_last_seen(user["username"])
    token = generate_token(user["username"], user["is_admin"])
    
    from models.user_request_model import get_requests_for_user
    recent_requests = get_requests_for_user(user["username"])
    password_reset_approved = any(req["request_type"] == "forgot_password" and req["status"] == "approved" for req in recent_requests)

    return jsonify({
        "success": True,
        "token": token,
        "username": user["username"],
        "is_admin": user["is_admin"],
        "password_reset": password_reset_approved,
    })


@auth_bp.route("/forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()

    if not username:
        return jsonify({"success": False, "message": "请输入用户名。"}), 400

    user = get_user_by_username(username)
    if not user:
        return jsonify({"success": False, "message": "该用户名不存在。"}), 404

    if user.get("is_admin"):
        return jsonify({"success": False, "message": "管理员账号不支持忘记密码功能。"}), 403

    reset_password = "123456"
    salt, password_hash = hash_password(reset_password)

    request_id = create_request(username, "forgot_password", details="申请重置密码为初始密码", requested_password_hash=password_hash, requested_salt=salt)
    if request_id:
        insert_log(username, "user", "密码重置申请", f"用户 {username} 提交了密码重置申请", "info", "auth")
        return jsonify({"success": True, "message": "密码重置申请已提交，请等待管理员审核。"})
    return jsonify({"success": False, "message": "申请提交失败，请稍后重试。"}), 500


@auth_bp.route("/user/me", methods=["GET"])
@auth_required
def current_user():
    user = request.user
    return jsonify({"success": True, "username": user.get("username"), "is_admin": user.get("is_admin", False)})


@auth_bp.route("/user/change-username", methods=["POST"])
@auth_required
def change_username():
    data = request.get_json(silent=True) or {}
    new_username = data.get("new_username", "").strip()
    current_password = data.get("current_password", "")
    if not new_username or not current_password:
        return jsonify({"success": False, "message": "新用户名和当前密码不能为空。"}), 400
    current_username = request.user.get("username")
    if not is_username_valid(new_username):
        return jsonify({"success": False, "message": "用户名长度 3-32 位，仅支持字母、数字、下划线、点和短划线。"}), 400
    if new_username != current_username and get_user_by_username(new_username):
        return jsonify({"success": False, "message": "新用户名已被占用，请选择其它用户名。"}), 409
    if not verify_user_password(current_username, current_password):
        return jsonify({"success": False, "message": "当前密码错误，无法修改用户名。"}), 401
    if update_username(current_username, new_username):
        token = generate_token(new_username, request.user.get("is_admin", False))
        return jsonify({"success": True, "message": "用户名修改成功。", "token": token})
    return jsonify({"success": False, "message": "用户名修改失败，请稍后重试。"}), 500


@auth_bp.route("/user/change-password", methods=["POST"])
@auth_required
def change_password():
    data = request.get_json(silent=True) or {}
    current_password = data.get("current_password", "")
    new_password = data.get("new_password", "")
    if not current_password or not new_password:
        return jsonify({"success": False, "message": "请输入当前密码和新密码。"}), 400
    if new_password == current_password:
        return jsonify({"success": False, "message": "新密码不能与当前密码相同。"}), 400
    if not is_password_strong(new_password):
        return jsonify({"success": False, "message": "密码至少 8 位，必须包含字母和数字。"}), 400
    username = request.user.get("username")
    if not verify_user_password(username, current_password):
        return jsonify({"success": False, "message": "当前密码错误，无法修改密码。"}), 401
    if update_user_password(username, new_password=new_password):
        return jsonify({"success": True, "message": "密码修改成功。"})
    return jsonify({"success": False, "message": "密码修改失败，请稍后重试。"}), 500


@auth_bp.route("/user/delete-account", methods=["POST"])
@auth_required
def delete_account():
    username = request.user.get("username")
    if not username:
        return jsonify({"success": False, "message": "无法识别当前用户。"}), 401
    deleted = delete_user(username)
    if not deleted:
        return jsonify({"success": False, "message": "账户删除失败或用户不存在。"}), 400

    insert_log(
        "system",
        "user",
        "用户注销",
        f"用户 {username} 已注销账号。",
        "info",
        source="system",
    )
    return jsonify({"success": True, "message": "账号已注销。"})
