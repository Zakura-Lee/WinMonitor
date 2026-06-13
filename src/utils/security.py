import hashlib
import hmac
import json
import base64
import secrets
import time
import config


def hash_password(password: str) -> tuple[str, str]:
    salt = secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        120000,
    ).hex()
    return salt, password_hash


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    candidate = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        120000,
    ).hex()
    return hmac.compare_digest(candidate, expected_hash)


def generate_token(username: str, is_admin: bool) -> str:
    payload = {
        "username": username,
        "is_admin": is_admin,
        "exp": int(time.time()) + 86400,
    }
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    token_payload = base64.urlsafe_b64encode(payload_bytes).decode("utf-8")
    signature = hmac.new(config.JWT_SECRET.encode("utf-8"), token_payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{token_payload}.{signature}"


def verify_token(token: str) -> dict | None:
    try:
        payload_token, signature = token.rsplit(".", 1)
        expected = hmac.new(config.JWT_SECRET.encode("utf-8"), payload_token.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None
        payload_bytes = base64.urlsafe_b64decode(payload_token.encode("utf-8"))
        payload = json.loads(payload_bytes)
        if payload.get("exp", 0) < int(time.time()):
            return None
        return payload
    except Exception:
        return None
