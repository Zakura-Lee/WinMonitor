#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
导入冒烟测试: 确认所有模块在改动后仍可正常加载（不启动线程、不连数据库）
"""

import importlib
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

MODULES = [
    "config",
    "utils.paths",
    "modules.process_mon",
    "modules.file_mon",
    "modules.network_mon",
    "modules.registry_mon",
    "modules.audit_mon",
    "modules.asset_mon",
    "db.connection",
    "models.user_model",
    "models.log_model",
    "models.user_request_model",
    "core.monitor",
    "collect.model",
    "collect.bus",
    "collect.normalize",
    "collect.collector",
    "collect.proctree",
    "collect.asset",
    "collect.detect",
    "collect.etw.providers",
    "collect.etw.session",
    "collect.etw.consumer",
    "routes.auth",
    "routes.logs",
    "routes.admin",
    "routes.monitor",
    "routes.system",
    "routes.user_requests",
    "app",
]


def test_all_modules_import():
    failed = []
    for name in MODULES:
        try:
            importlib.import_module(name)
        except Exception as exc:  # noqa: BLE001
            failed.append(f"{name}: {type(exc).__name__}: {exc}")
    assert not failed, "以下模块导入失败:\n" + "\n".join(failed)


if __name__ == "__main__":
    try:
        test_all_modules_import()
        print(f"全部 {len(MODULES)} 个模块导入正常")
    except AssertionError as exc:
        print(exc)
        sys.exit(1)
