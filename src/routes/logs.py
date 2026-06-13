from flask import Blueprint, request, jsonify
from routes.auth_utils import auth_required
from models.log_model import get_logs_for_user, get_recent_summary, add_category_cn_to_logs, MONITOR_CATEGORIES

logs_bp = Blueprint("logs", __name__)


@logs_bp.route("/logs", methods=["GET"])
@auth_required
def user_logs():
    user = request.user
    logs = get_logs_for_user(user["username"], is_admin=user.get("is_admin", False), limit=200)
    logs = add_category_cn_to_logs(logs)
    return jsonify({"success": True, "logs": logs})


@logs_bp.route("/summary", methods=["GET"])
@auth_required
def summary():
    user = request.user
    total = get_recent_summary(user["username"], is_admin=user.get("is_admin", False))
    return jsonify({"success": True, "summary": {"recent_count": total}})
