#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
B3 回归测试: 敏感接口的鉴权边界

只验证 401 / 403 分支，不触发管理员成功路径，
因为 /api/system/exit 成功后会真的结束进程。
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from app import app
from utils.security import generate_token

CONTROL_PATHS = ("/api/monitor/start", "/api/monitor/pause", "/api/monitor/stop")


def _normal_user_headers():
    token = generate_token("normal-user", False)
    return {"Authorization": f"Bearer {token}"}


def test_exit_requires_login():
    response = app.test_client().post("/api/system/exit")
    assert response.status_code == 401, response.status_code


def test_exit_rejects_normal_user():
    response = app.test_client().post("/api/system/exit", headers=_normal_user_headers())
    assert response.status_code == 403, response.status_code


def test_monitor_control_requires_login():
    client = app.test_client()
    for path in CONTROL_PATHS:
        response = client.post(path)
        assert response.status_code == 401, (path, response.status_code)


def test_monitor_control_rejects_normal_user():
    client = app.test_client()
    for path in CONTROL_PATHS:
        response = client.post(path, headers=_normal_user_headers())
        assert response.status_code == 403, (path, response.status_code)


def test_status_still_requires_login():
    response = app.test_client().get("/api/monitor/status")
    assert response.status_code == 401, response.status_code


if __name__ == "__main__":
    failures = 0
    for name in sorted(n for n in dir() if n.startswith("test_")):
        fn = globals()[name]
        try:
            fn()
            print(f"PASS  {name}")
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print(f"FAIL  {name}: {type(exc).__name__}: {exc}")
    print()
    print("全部通过" if failures == 0 else f"{failures} 个测试失败")
    sys.exit(1 if failures else 0)
