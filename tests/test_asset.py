#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P8 资产清点测试：验证不再依赖 WMI，且关键字段可用。"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from collect import asset


def test_inventory_shape():
    inventory = asset.collect_asset_inventory()
    for key in (
        "computer_name",
        "os_version",
        "architecture",
        "cpu_count",
        "physical_memory_gb",
        "manufacturer",
        "model",
        "logical_drives",
        "network_adapters",
    ):
        assert key in inventory, f"缺少字段 {key}"
    assert inventory["computer_name"]
    assert inventory["cpu_count"] >= 1


def test_memory_is_positive():
    memory = asset.collect_memory_gb()
    assert isinstance(memory, (int, float)), memory
    assert memory > 0


def test_disks_have_capacity():
    drives = asset.collect_disks()
    assert drives, "未枚举到任何磁盘"
    for drive in drives:
        assert drive["device_id"]
        assert drive["size_gb"] > 0
        assert 0 <= drive["free_space_gb"] <= drive["size_gb"] + 0.01


def test_adapters_shape():
    adapters = asset.collect_adapters()
    # 虚拟机可能没有网卡，允许为空，但每条记录必须字段完整
    for adapter in adapters:
        assert "description" in adapter
        assert "mac_address" in adapter
        assert isinstance(adapter["ip_addresses"], list)


def test_no_wmi_dependency():
    """模块不应再导入 win32com / pythoncom。"""
    import ast

    path = os.path.join(ROOT, "src", "modules", "asset_mon.py")
    with open(path, encoding="utf-8") as handle:
        tree = ast.parse(handle.read())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    assert "win32com.client" not in imported
    assert "pythoncom" not in imported


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
