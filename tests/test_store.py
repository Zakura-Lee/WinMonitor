#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P9a 事件持久化测试"""

import json
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from collect.model import Event
from collect.store import EventStore, event_to_record


def _event(**kwargs):
    base = {"ts_ns": 1_700_000_000_000_000_000, "provider": "Microsoft-Windows-Sysmon", "event_id": 1}
    base.update(kwargs)
    return Event(**base)


def test_record_is_compact():
    event = _event(pid=1234, image=r"C:\Windows\System32\cmd.exe", cmdline="", user="")
    record = event_to_record(event)
    assert record["pid"] == 1234
    assert "image" in record
    # 空字段不落盘
    assert "cmdline" not in record
    assert "user" not in record
    assert "extra" not in record


def test_store_writes_lines():
    directory = tempfile.mkdtemp(prefix="wm_store_")
    try:
        store = EventStore(directory, retain_days=2)
        for index in range(3):
            assert store.write(_event(pid=100 + index)) is True
        store.flush()

        files = []
        for dirpath, _, names in os.walk(directory):
            files.extend(os.path.join(dirpath, name) for name in names if name.endswith(".jsonl"))
        assert len(files) == 1, files

        with open(files[0], encoding="utf-8") as handle:
            lines = [json.loads(line) for line in handle if line.strip()]
        assert len(lines) == 3
        assert [line["pid"] for line in lines] == [100, 101, 102]
        assert store.stats()["written"] == 3
        store.close()
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def test_store_sampling_cap():
    directory = tempfile.mkdtemp(prefix="wm_store_cap_")
    try:
        store = EventStore(directory, max_per_hour=2)
        assert store.write(_event(pid=1)) is True
        assert store.write(_event(pid=2)) is True
        assert store.write(_event(pid=3)) is False
        assert store.stats()["dropped"] == 1
        store.close()
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def test_store_disabled():
    directory = tempfile.mkdtemp(prefix="wm_store_off_")
    try:
        store = EventStore(directory, enabled=False)
        assert store.write(_event(pid=9)) is False
        assert store.stats()["enabled"] is False
        assert not os.listdir(directory)
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def test_store_filters_noise_events():
    directory = tempfile.mkdtemp(prefix="wm_store_filter_")
    try:
        store = EventStore(directory)
        thread_event = _event(
            provider="Microsoft-Windows-Kernel-Process", event_id=3, pid=4
        )
        assert store.write(thread_event) is False
        assert store.stats()["filtered"] == 1

        net_event = _event(provider="Microsoft-Windows-Kernel-Network", event_id=10)
        assert store.write(net_event) is True

        process_event = _event(provider="Microsoft-Windows-Sysmon", event_id=1)
        assert store.write(process_event) is True
        assert store.stats()["written"] == 2
        store.close()
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def test_store_prunes_old_days():
    directory = tempfile.mkdtemp(prefix="wm_store_prune_")
    try:
        stale = os.path.join(directory, "20200101")
        os.makedirs(stale)
        with open(os.path.join(stale, "00.jsonl"), "w", encoding="utf-8") as handle:
            handle.write("{}\n")

        store = EventStore(directory, retain_days=1)
        store.close()
        assert not os.path.exists(stale), "过期目录应被清理"
    finally:
        shutil.rmtree(directory, ignore_errors=True)


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
