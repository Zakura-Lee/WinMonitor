#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LLM 复核层客户端

设计约束（来自前期讨论）:
    1. LLM 只产出「意见 + 理由」，不参与「是否告警」的最终判定；
    2. 无密钥、超时、限流、返回格式错误时一律降级为不可用，不影响规则检测；
    3. 日志内容是攻击者可控制的输入，必须当纯数据处理，输出只做 schema 校验；
    4. 敏感字段发出前脱敏。

只依赖标准库，跑在 Python 3.15 的应用环境里也没问题。
"""

import hashlib
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request

# 脱敏规则：把用户名、内网地址、SID 换掉，避免把本机身份信息发出去。
# 注意：re.sub 的替换串里反斜杠仍是转义字符，路径必须写成 \\\\ 才是单个反斜杠。
_REDACTIONS = (
    (re.compile(r"C:\\Users\\[^\\\s\"']+", re.IGNORECASE), "C:\\\\Users\\\\<user>"),
    (re.compile(r"\bS-1-5-\d+(?:-\d+){1,4}\b"), "<sid>"),
    (re.compile(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "<lan-ip>"),
    (re.compile(r"\b192\.168\.\d{1,3}\.\d{1,3}\b"), "<lan-ip>"),
    (re.compile(r"\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b"), "<lan-ip>"),
)

# 事件内容里可能夹杂提示词注入，这里做最基础的削弱
_INJECTION_PATTERNS = (
    re.compile(r"(?i)ignore (all )?(previous|above) instructions"),
    re.compile(r"(?i)disregard (all )?(previous|above)"),
    re.compile(r"(?i)system prompt"),
)


def redact(text, limit=1200):
    """脱敏并裁剪长度。"""
    if not text:
        return ""
    result = str(text)
    for pattern, replacement in _REDACTIONS:
        result = pattern.sub(replacement, result)
    for pattern in _INJECTION_PATTERNS:
        result = pattern.sub("[redacted-instruction]", result)
    if len(result) > limit:
        result = result[:limit] + "…"
    return result


def make_key(text):
    return hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()[:32]


class LLMUnavailable(RuntimeError):
    """LLM 不可用（无密钥、被熔断、持续失败）。"""


class LLMClient:
    def __init__(
        self,
        api_key=None,
        base_url="https://api.deepseek.com",
        model="deepseek-chat",
        timeout=20,
        max_tokens=800,
        cache_ttl=3600,
        failure_limit=3,
    ):
        self.api_key = api_key if api_key is not None else os.environ.get("WINMON_LLM_API_KEY", "")
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.max_tokens = max_tokens
        self.cache_ttl = cache_ttl
        self.failure_limit = failure_limit

        self._cache = {}
        self._lock = threading.Lock()
        self._failures = 0
        self._open_until = 0.0
        self.calls = 0
        self.hits = 0
        self.failures = 0

    # -- 状态 -------------------------------------------------------------

    @property
    def available(self):
        if not self.api_key:
            return False
        return time.monotonic() >= self._open_until

    def stats(self):
        return {
            "available": self.available,
            "has_key": bool(self.api_key),
            "calls": self.calls,
            "cache_hits": self.hits,
            "failures": self.failures,
            "circuit_open": time.monotonic() < self._open_until,
            "model": self.model,
        }

    # -- 缓存 -------------------------------------------------------------

    def _cache_get(self, key):
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            value, expires = entry
            if expires < time.time():
                self._cache.pop(key, None)
                return None
            self.hits += 1
            return value

    def _cache_put(self, key, value):
        with self._lock:
            if len(self._cache) > 512:
                self._cache.clear()
            self._cache[key] = (value, time.time() + self.cache_ttl)

    # -- 调用 -------------------------------------------------------------

    def _post(self, messages):
        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": self.max_tokens,
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
        }
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            body = response.read().decode("utf-8", "ignore")
        parsed = json.loads(body)
        return parsed["choices"][0]["message"]["content"]

    def _record_failure(self):
        with self._lock:
            self.failures += 1
            self._failures += 1
            if self._failures >= self.failure_limit:
                # 熔断 60 秒，避免持续打爆接口
                self._open_until = time.monotonic() + 60

    def _record_success(self):
        with self._lock:
            self._failures = 0

    def ask_json(self, system_prompt, user_prompt, cache_key=None):
        """请求一个 JSON 对象；任何异常都转成 LLMUnavailable。"""
        if not self.api_key:
            raise LLMUnavailable("未配置 WINMON_LLM_API_KEY")
        if not self.available:
            raise LLMUnavailable("熔断中")

        key = cache_key or make_key(system_prompt + "\x00" + user_prompt)
        cached = self._cache_get(key)
        if cached is not None:
            return cached

        self.calls += 1
        try:
            content = self._post(
                [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ]
            )
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError) as exc:
            self._record_failure()
            raise LLMUnavailable(f"请求失败: {exc}") from exc

        self._record_success()
        result = parse_json_content(content)
        if result is None:
            self._record_failure()
            raise LLMUnavailable("返回内容不是合法 JSON")

        self._cache_put(key, result)
        return result


def parse_json_content(content):
    """从模型输出里抠出 JSON 对象，容忍 ```json 包裹。"""
    if not content:
        return None
    text = content.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
        text = text.strip()
    try:
        value = json.loads(text)
    except (ValueError, TypeError):
        return None
    return value if isinstance(value, dict) else None


_default_client = None


def get_client(config=None):
    """按配置拿全局客户端。"""
    global _default_client
    if _default_client is not None:
        return _default_client

    if config is None:
        try:
            import config as config_module
        except ImportError:
            from .. import config as config_module
        config = config_module

    _default_client = LLMClient(
        base_url=getattr(config, "LLM_BASE_URL", "https://api.deepseek.com"),
        model=getattr(config, "LLM_MODEL", "deepseek-chat"),
        timeout=getattr(config, "LLM_TIMEOUT", 20),
        max_tokens=getattr(config, "LLM_MAX_TOKENS", 800),
    )
    return _default_client
