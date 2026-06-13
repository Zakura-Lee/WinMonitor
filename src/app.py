from pathlib import Path
import logging
import sys
from flask import Flask, send_from_directory, jsonify, Response
from flask_cors import CORS

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / "src"))

import config
from db.setup import init_db
from models.user_model import ensure_admin_user
from routes.auth import auth_bp
from routes.logs import logs_bp
from routes.user_requests import requests_bp
from routes.admin import admin_bp
from routes.monitor import monitor_bp
from routes.system import system_bp
from core.monitor import monitor_service

BASE_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = BASE_DIR / "web"

app = Flask(
    __name__,
    static_folder=None,
    static_url_path=None,
    template_folder=str(WEB_DIR),
)
app.config["SECRET_KEY"] = config.APP_SECRET_KEY
CORS(app, supports_credentials=True)

app.register_blueprint(auth_bp, url_prefix="/api")
app.register_blueprint(logs_bp, url_prefix="/api")
app.register_blueprint(requests_bp, url_prefix="/api")
app.register_blueprint(admin_bp, url_prefix="/api")
app.register_blueprint(monitor_bp, url_prefix="/api")
app.register_blueprint(system_bp, url_prefix="/api")


def create_app():
    init_db()
    ensure_admin_user(config.ADMIN_DEFAULT_USERNAME, config.ADMIN_DEFAULT_PASSWORD)
    return app


@app.route("/")
def index():
    return send_from_directory(str(WEB_DIR), "login.html")


@app.route("/login")
def login_page():
    return send_from_directory(str(WEB_DIR), "login.html")


@app.route("/register")
def register_page():
    return send_from_directory(str(WEB_DIR), "register.html")


@app.route("/dashboard")
def dashboard_page():
    return send_from_directory(str(WEB_DIR), "dashboard.html")


@app.route("/menu")
def menu_page():
    return send_from_directory(str(WEB_DIR), "menu.html")


@app.route("/profile")
def profile_page():
    return send_from_directory(str(WEB_DIR), "profile.html")


@app.route("/admin")
def admin_page():
    return send_from_directory(str(WEB_DIR), "admin.html")


@app.route("/favicon.ico")
def favicon():
    return Response(status=204)


@app.route("/hybridaction/<path:path>")
def ignore_hybridaction(path):
    return Response(status=204)


@app.route("/<path:path>")
def static_files(path):
    return send_from_directory(str(WEB_DIR), path)


@app.errorhandler(404)
def page_not_found(error):
    return jsonify({"success": False, "message": "页面未找到"}), 404


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    create_app()
    app.run(host=config.SERVICE_HOST, port=config.SERVICE_PORT)
