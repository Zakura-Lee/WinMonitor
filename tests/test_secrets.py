#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
B2 回归测试: 应用密钥不再写死在源码里，且旧占位符签出的令牌会被拒绝
"""

import base64
import hashlib
import hmac
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from utils.security import verify_token


def test_secrets_not_placeholder():
    import config

    assert len(config.JWT_SECRET) >= 32, "JWT 密钥太短"
    assert len(config.APP_SECRET_KEY) >= 32, "会话密钥太短"
    assert "replace-with" not in config.JWT_SECRET.lower(), "仍在使用占位符"
    assert "replace-with" not in config.APP_SECRET_KEY.lower(), "仍在使用占位符"
    assert config.JWT_SECRET != config.APP_SECRET_KEY, "两个密钥不应相同"


def test_secrets_persisted():
    import config

    if os.environ.get("WINMON_JWT_SECRET"):
        return  # 走环境变量时不落盘，跳过
    assert os.path.isfile(config.SECRET_FILE), f"密钥文件不存在: {config.SECRET_FILE}"
    with open(config.SECRET_FILE, encoding="utf-8") as handler:
        stored = json.load(handler)
    assert stored["jwt_secret"] == config.JWT_SECRET
    assert stored["app_secret"] == config.APP_SECRET_KEY


def test_forged_token_with_old_secret_rejected():
    """用旧的公开占位符伪造管理员令牌，必须校验失败。"""
    payload = {"username": "admin", "is_admin": True, "exp": int(time.time()) + 3600}
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    body = base64.urlsafe_b64encode(raw).decode("utf-8")
    signature = hmac.new(
        b"replace-with-a-secure-jwt-secret", body.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    assert verify_token(f"{body}.{signature}") is None


def test_valid_token_roundtrip():
    from utils.security import generate_token

    token = generate_token("someone", True)
    payload = verify_token(token)
    assert payload is not None
    assert payload["username"] == "someone"
    assert payload["is_admin"] is True


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
