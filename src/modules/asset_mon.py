#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模块名: asset_mon.py
功能: Windows 系统资产清点

实现已迁到 `collect.asset`（原生 API + 注册表，不依赖 WMI）。
本模块只保留采集线程的外壳，保持原有调用签名不变。
"""

import logging
import time

import config
from collect.asset import collect_asset_inventory

__all__ = ["asset_mon", "collect_asset_inventory"]


def asset_mon(stop_event, results, alert_queue=None, refresh_interval=config.ASSET_MON_INTERVAL):
    logging.info("资产清点已启动")
    try:
        while not stop_event.is_set():
            inventory = collect_asset_inventory()
            if isinstance(results, dict):
                results["asset_inventory"] = inventory
            logging.info("资产清点完成: %s", inventory.get("computer_name", "unknown"))
            for _ in range(refresh_interval):
                if stop_event.is_set():
                    break
                time.sleep(1)
    finally:
        logging.info("资产清点已停止")
