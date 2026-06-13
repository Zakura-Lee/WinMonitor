from flask import Blueprint, jsonify, request, Response
from routes.auth_utils import auth_required, admin_required
from core.monitor import monitor_service
from modules import process_mon
from models.log_model import get_category_cn
import json
import queue

monitor_bp = Blueprint("monitor", __name__)


@monitor_bp.route("/monitor/start", methods=["POST"])
@auth_required
def start_monitor():
    user = request.user
    username = user.get("username", "system")
    monitor_service.start(username=username)
    return jsonify({"success": True, "message": "监控已启动。", "status": monitor_service.status()})


@monitor_bp.route("/monitor/pause", methods=["POST"])
@auth_required
def pause_monitor():
    monitor_service.pause()
    return jsonify({"success": True, "message": "监控已暂停。", "status": monitor_service.status()})


@monitor_bp.route("/monitor/stop", methods=["POST"])
@auth_required
def stop_monitor():
    monitor_service.stop()
    return jsonify({"success": True, "message": "监控已退出。", "status": monitor_service.status()})


@monitor_bp.route("/monitor/status", methods=["GET"])
@auth_required
def monitor_status():
    return jsonify({"success": True, "status": monitor_service.status()})


@monitor_bp.route("/monitor/processes", methods=["GET"])
@auth_required
def monitor_processes():
    current = process_mon.collect_current_processes(limit=200)
    changes = monitor_service.get_process_changes()
    return jsonify({
        "success": True,
        "status": monitor_service.status(),
        "current_processes": current,
        "process_changes": changes,
    })


@monitor_bp.route("/monitor/critical-alerts", methods=["GET"])
@auth_required
def get_critical_alerts():
    user = request.user
    username = user.get("username")
    is_admin = user.get("is_admin", False)
    if is_admin:
        alerts = monitor_service.get_critical_alerts(limit=20)
    else:
        alerts = monitor_service.get_critical_alerts(username=username, limit=20)
    for alert in alerts:
        alert["category_cn"] = get_category_cn(alert.get("category", ""))
    return jsonify({"success": True, "critical_alerts": alerts})


@monitor_bp.route("/monitor/stream-alerts", methods=["GET"])
def stream_alerts():
    token = request.headers.get("Authorization") or request.args.get("token")
    if not token:
        return jsonify({"success": False, "message": "未授权"}), 401
    
    if token.startswith("Bearer "):
        token = token[7:]
    
    from routes.auth_utils import verify_token
    payload = verify_token(token)
    if not payload:
        return jsonify({"success": False, "message": "无效令牌"}), 401
    
    username = payload.get("username")
    is_admin = payload.get("is_admin", False)
    
    def generate():
        sid = monitor_service.subscribe_alerts()
        monitor_service.set_subscriber_user(sid, username)
        
        try:
            with monitor_service._subscriber_lock:
                sub = monitor_service.alert_subscribers.get(sid)
                if not sub:
                    return
                q = sub["queue"]
            
            while True:
                try:
                    alert = q.get(timeout=30)
                    
                    if not is_admin and alert.get("username") != username:
                        continue
                    
                    alert["category_cn"] = get_category_cn(alert.get("category", ""))
                    data = json.dumps({"type": "alert", "alert": alert}, ensure_ascii=False)
                    yield f"data: {data}\n\n"
                    
                except queue.Empty:
                    yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
                    
        except GeneratorExit:
            pass
        finally:
            monitor_service.unsubscribe_alerts(sid)
    
    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
