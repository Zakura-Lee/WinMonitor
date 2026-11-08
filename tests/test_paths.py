#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
B1 回归测试: 路径归一化与前缀匹配

用法:
    python tests/test_paths.py          # 直接运行
    pytest tests/test_paths.py          # 也可被 pytest 收集
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "src", "modules"))

from utils.paths import contains_any, matches_prefix, normalize

SYSTEM_ROOT = os.environ.get("SystemRoot", r"C:\Windows")
SYSTEM32_SVCHOST = os.path.join(SYSTEM_ROOT, "System32", "svchost.exe")


def test_normalize():
    assert normalize(r"C:\Windows\System32\cmd.exe") == "c:/windows/system32/cmd.exe"
    assert normalize("c:/windows/") == "c:/windows"
    assert normalize("C:\\\\Windows") == "c:/windows"
    assert normalize("") == ""
    assert normalize(None) == ""


def test_matches_prefix_boundary():
    assert matches_prefix(r"C:\Windows\System32\svchost.exe", [r"c:\windows"])
    assert matches_prefix(r"C:\Windows", [r"c:\windows"])
    assert not matches_prefix(r"C:\WindowsOld\x.exe", [r"c:\windows"])
    assert not matches_prefix("", [r"c:\windows"])


def test_contains_any():
    assert contains_any(r"C:\Users\a\AppData\Local\Temp\x.txt", ["\\temp\\"])
    assert not contains_any(r"C:\Users\a\doc.txt", ["\\temp\\"])


def test_config_path_lists_have_no_doubled_backslash():
    import config

    names = (
        "SUS_PATH",
        "FILE_MONITOR_TRUSTED_PATHS",
        "FILE_MONITOR_SENSITIVE_PATHS",
        "NETWORK_TRUSTED_PROCESS_PATHS",
        "INTEGRITY_TARGETS",
        "PROCESS_TRUSTED_PATHS",
    )
    for name in names:
        entries = getattr(config, name)
        assert entries, f"{name} 不应为空"
        for entry in entries:
            assert "\\\\" not in entry, f"{name} 含双反斜杠: {entry!r}"


def test_file_mon_path_predicates():
    import file_mon

    assert file_mon.is_trusted_path(SYSTEM32_SVCHOST)
    assert file_mon.is_sensitive_path(SYSTEM32_SVCHOST)
    assert file_mon.is_windows_system_path(SYSTEM32_SVCHOST)
    assert file_mon._is_system32_core_dll(os.path.join(SYSTEM_ROOT, "System32", "urlmon.dll"))
    assert not file_mon._is_system32_core_dll(os.path.join(SYSTEM_ROOT, "System32", "drivers", "x.sys"))
    assert file_mon._is_dotnet_framework_path(
        os.path.join(SYSTEM_ROOT, "Microsoft.NET", "Framework64", "v4.0.30319", "ngen.exe")
    )


def test_process_mon_trusted_path():
    import process_mon

    assert process_mon.is_trusted_path(SYSTEM32_SVCHOST)


def test_integrity_targets_point_to_existing_files():
    import config

    existing = [path for path in config.INTEGRITY_TARGETS if os.path.isfile(path)]
    assert existing, "完整性目标没有一个存在，路径解析可能有问题"


def test_sus_path_resolved_from_environment():
    import config

    temp = os.environ.get("TEMP", "")
    assert temp, "环境变量 TEMP 缺失，无法验证"
    assert any(os.path.normcase(path) == os.path.normcase(temp) for path in config.SUS_PATH), config.SUS_PATH


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
