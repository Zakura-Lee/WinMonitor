import os
import threading
import time
from flask import Blueprint, jsonify, request
from core.monitor import monitor_service

system_bp = Blueprint("system", __name__)


@system_bp.route("/system/exit", methods=["POST"])
def exit_system():
    # 先停止监控服务，再尝试关闭 Flask 开发服务器进程
    monitor_service.stop()
    shutdown_func = request.environ.get("werkzeug.server.shutdown")

    def _shutdown():
        time.sleep(0.5)
        if shutdown_func:
            shutdown_func()
        else:
            os._exit(0)

    threading.Thread(target=_shutdown, daemon=True).start()
    return jsonify({"success": True, "message": "系统已停止，请关闭此页面。"})
