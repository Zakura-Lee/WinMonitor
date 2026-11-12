import logging
import os
import queue
import threading
import time
from models.log_model import insert_log
import config
from modules import process_mon, file_mon, network_mon, registry_mon, audit_mon, asset_mon

# ETW 后端已经覆盖的采集类别：这些模块不再启动 legacy 版本，
# 否则等于两套采集并行，开销翻倍且会产生重复告警。
ETW_COVERED = ("process", "file", "network", "registry")

# Sysmon 覆盖不到、任何后端下都需要的采集器
ALWAYS_ON = ("audit", "asset")


def plan_collectors(backend, process_started):
    """决定本次启动要装配哪些采集器。

    backend 为 etw 且 ETW 成功启动时，只保留审计与资产；
    否则退回全套 legacy 采集器。
    """
    if backend == "etw" and process_started:
        return list(ALWAYS_ON)
    return ["process", "file", "network", "registry"] + list(ALWAYS_ON)


class MonitorService:
    def __init__(self):
        self.alert_queue = queue.Queue(maxsize=config.MAX_ALERT_QUEUE_SIZE)
        self.monitor_threads = []
        self.consumer_thread = None
        self.stop_event = threading.Event()
        self.running = False
        self.start_time = None
        self.process_data = {"process_changes": []}
        self.network_events = []
        self.file_events = []
        self.registry_events = []
        self.current_user = None
        self.critical_alerts = []
        self.max_critical_alerts = 50
        self.alert_subscribers = {}
        self.subscriber_id = 0
        self._subscriber_lock = threading.Lock()
        # 采集后端
        self.backend = getattr(config, "MONITOR_BACKEND", "legacy")
        self.etw_collector = None
        self.etw_primary = None
        self.etw_fallback_reason = None
        self.active_collectors = []
        # 活跃进程表：用 GUID / 进程序号做键，供父链查询与终止事件补全
        try:
            from collect.proctree import ProcessTable

            self.process_table = ProcessTable()
        except Exception:  # noqa: BLE001
            self.process_table = None

    # -- 进程采集后端 -----------------------------------------------------

    def _start_etw_backend(self, process_data, alert_queue):
        """启动 ETW 进程采集。失败时返回 False，由调用方回退到 legacy。"""
        try:
            from collect.collector import EtwCollector
            from collect.etw import providers as etw_providers
            from collect.proctree import ProcessTable
        except Exception as exc:  # noqa: BLE001
            self.etw_fallback_reason = f"导入采集层失败: {exc}"
            return False

        self.process_table = ProcessTable()

        collector = EtwCollector(
            session_name="WinMonitorMonitor",
            on_event=self._on_etw_event,
        )
        try:
            collector.start()
        except Exception as exc:  # noqa: BLE001
            self.etw_fallback_reason = f"启动失败: {exc}"
            try:
                collector.stop()
            except Exception:  # noqa: BLE001
                pass
            return False

        # Sysmon 可用时以它为准（带命令行），否则退回内核进程事件
        disabled = set(collector.disabled_providers)
        if etw_providers.SYSMON.name not in disabled:
            self.etw_primary = etw_providers.SYSMON.name
        else:
            self.etw_primary = etw_providers.KERNEL_PROCESS.name

        self.etw_collector = collector
        self.etw_fallback_reason = None
        return True

    def _on_etw_event(self, event):
        """把采集层的 Event 分派到进程、网络或文件处理。"""
        is_sysmon = event.provider == "Microsoft-Windows-Sysmon"

        if is_sysmon:
            if event.event_id == 1 or event.event_id == 5:
                # 进程事件受主提供者开关约束，避免与内核事件重复计数
                if self.etw_primary != "Microsoft-Windows-Sysmon":
                    return
                action = "started" if event.event_id == 1 else "stopped"
                self._handle_process_event(event, action)
            elif event.event_id == 3:
                self._handle_network_event(event)
            elif event.event_id == 11:
                self._handle_file_event(event, "created")
            elif event.event_id == 23:
                self._handle_file_event(event, "deleted")
            elif event.event_id in (12, 13, 14):
                self._handle_registry_event(event)
            return

        if self.etw_primary == "Microsoft-Windows-Sysmon":
            return  # Sysmon 已经报告过同一个进程
        if event.event_id == 1:
            self._handle_process_event(event, "started")
        elif event.event_id == 2:
            self._handle_process_event(event, "stopped")

    def _handle_process_event(self, event, action):
        if action == "started":
            record = self.process_table.add_start(event)
        else:
            # 终止事件本身不带父进程信息，靠进程表补全
            record = self.process_table.mark_stop(event)

        if record is not None:
            pid = record.pid
            image = record.image
            ppid = record.ppid
            cmdline = record.cmdline
            parent_key = record.parent_key
        else:
            pid = event.pid
            image = event.image
            ppid = event.ppid
            cmdline = event.cmdline
            parent_key = f"guid:{event.parent_guid}" if event.parent_guid else ""

        parent = self.process_table.get(parent_key) if parent_key else None
        pname = os.path.basename(parent.image).lower() if parent and parent.image else ""

        changes = self.process_data.setdefault("process_changes", [])
        changes.insert(
            0,
            {
                "time": time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.localtime(event.timestamp_seconds())
                ),
                "type": action,
                "pid": pid,
                "name": os.path.basename(image).lower() if image else "",
                "exe_path": image,
                "ppid": ppid,
                "pname": pname,
                "cpu": 0.0,
                "mem": 0.0,
                "cmdline": cmdline,
            },
        )
        del changes[200:]

    def _handle_network_event(self, event):
        from collect.detect import classify_network, format_endpoint

        kind, reason, severity = classify_network(event)
        parent = self.process_table.latest_by_pid(event.ppid) if event.ppid else None

        record = {
            "time": time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(event.timestamp_seconds())
            ),
            "pid": event.pid,
            "local": format_endpoint(event.saddr, event.sport),
            "remote": format_endpoint(event.daddr, event.dport),
            "status": event.proto or "connect",
            "type": kind,
            "reason": reason,
            "process_name": os.path.basename(event.image).lower() if event.image else "",
            "process_exe": event.image,
            "parent_name": os.path.basename(parent.image).lower() if parent and parent.image else "",
            "blocked": False,
        }
        self.network_events.insert(0, record)
        del self.network_events[500:]

        if kind in ("abnormal", "attack") and severity:
            try:
                self.alert_queue.put_nowait(
                    {
                        "category": "network",
                        "title": "网络攻击警报" if kind == "attack" else "网络异常连接",
                        "message": f"{record['local']} -> {record['remote']} ({reason})",
                        "severity": severity,
                    }
                )
            except queue.Full:
                logging.debug("告警队列已满，丢弃网络告警")

    def _handle_file_event(self, event, action):
        from collect.detect import classify_file

        kind, reason, severity = classify_file(event, action)
        parent = self.process_table.latest_by_pid(event.ppid) if event.ppid else None

        record = {
            "time": time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(event.timestamp_seconds())
            ),
            "action": action,
            "path": event.path,
            "type": kind,
            "reason": reason,
            "pid": event.pid,
            "process_name": os.path.basename(event.image).lower() if event.image else "",
            "process_exe": event.image,
            "parent_name": os.path.basename(parent.image).lower() if parent and parent.image else "",
        }
        self.file_events.insert(0, record)
        del self.file_events[500:]

        if kind == "danger" and severity:
            try:
                self.alert_queue.put_nowait(
                    {
                        "category": "file",
                        "title": "文件安全警告",
                        "message": f"{action} {event.path} ({reason})",
                        "severity": severity,
                    }
                )
            except queue.Full:
                logging.debug("告警队列已满，丢弃文件告警")

    def _handle_registry_event(self, event):
        from collect.detect import classify_registry

        kind, reason, severity = classify_registry(event)
        parent = self.process_table.latest_by_pid(event.ppid) if event.ppid else None

        record = {
            "time": time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(event.timestamp_seconds())
            ),
            "key": event.key,
            "value": event.value,
            "action": (event.extra or {}).get("registry_action", ""),
            "type": kind,
            "reason": reason,
            "pid": event.pid,
            "process_name": os.path.basename(event.image).lower() if event.image else "",
            "process_exe": event.image,
            "parent_name": os.path.basename(parent.image).lower() if parent and parent.image else "",
        }
        self.registry_events.insert(0, record)
        del self.registry_events[500:]

        if kind in ("abnormal", "danger") and severity:
            try:
                self.alert_queue.put_nowait(
                    {
                        "category": "registry",
                        "title": "注册表可疑写入" if kind == "danger" else "自启动项变更",
                        "message": f"{event.key} = {event.value} ({reason})",
                        "severity": severity,
                    }
                )
            except queue.Full:
                logging.debug("告警队列已满，丢弃注册表告警")

    def _stop_etw_backend(self):
        if self.etw_collector is None:
            return
        try:
            self.etw_collector.stop()
        except Exception:  # noqa: BLE001
            logging.debug("停止 ETW 采集器时出错", exc_info=True)
        self.etw_collector = None
        self.etw_primary = None

    # -- 生命周期 ---------------------------------------------------------

    def start(self, username=None):
        if self.running:
            return
        self.stop_event = threading.Event()
        self.current_user = username or "system"
        if self.start_time is None:
            self.start_time = time.time()
            self.process_data = {"process_changes": []}
            self.network_events = []
            self.file_events = []
            self.registry_events = []
        self.consumer_thread = threading.Thread(target=self._consume_alerts, daemon=True)
        self.consumer_thread.start()

        self.monitor_threads = []
        self.backend = getattr(config, "MONITOR_BACKEND", "legacy")

        process_started = False
        if self.backend == "etw":
            process_started = self._start_etw_backend(self.process_data, self.alert_queue)
            if not process_started:
                logging.warning(
                    "ETW 后端不可用，回退到 legacy 进程采集: %s", self.etw_fallback_reason
                )
                self.backend = "legacy"

        collectors = plan_collectors(self.backend, process_started)
        self.active_collectors = list(collectors)

        factories = {
            "process": lambda: threading.Thread(
                target=process_mon.p_mon,
                args=(self.stop_event, self.process_data, self.alert_queue),
                daemon=True,
            ),
            "file": lambda: threading.Thread(
                target=file_mon.f_mon, args=(self.stop_event, {}, self.alert_queue), daemon=True
            ),
            "network": lambda: threading.Thread(
                target=network_mon.n_mon, args=(self.stop_event, {}, self.alert_queue), daemon=True
            ),
            "registry": lambda: threading.Thread(
                target=registry_mon.r_mon, args=(self.stop_event, {}, self.alert_queue), daemon=True
            ),
            "audit": lambda: threading.Thread(
                target=audit_mon.audit_mon, args=(self.stop_event, {}, self.alert_queue), daemon=True
            ),
            "asset": lambda: threading.Thread(
                target=asset_mon.asset_mon, args=(self.stop_event, {}, self.alert_queue), daemon=True
            ),
        }

        for name in collectors:
            self.monitor_threads.append(factories[name]())

        for thread in self.monitor_threads:
            thread.start()

        self.running = True
        logging.info(
            "MonitorService 已启动 (后端=%s, 进程采集=%s, 采集器=%s)",
            self.backend,
            "etw" if process_started else "legacy",
            ",".join(collectors),
        )

    def _shutdown(self, reset_start_time, message):
        self.stop_event.set()
        self._stop_etw_backend()
        for thread in self.monitor_threads:
            try:
                thread.join(timeout=2)
            except Exception:
                pass
        if self.consumer_thread is not None:
            try:
                self.consumer_thread.join(timeout=2)
            except Exception:
                pass
        self.running = False
        self.monitor_threads = []
        self.consumer_thread = None
        self.current_user = None
        if reset_start_time:
            self.start_time = None
            self.process_data = {"process_changes": []}
        logging.info(message)

    def stop(self):
        if not self.running:
            return
        self._shutdown(True, "MonitorService 已退出")

    def pause(self):
        if not self.running:
            return
        self._shutdown(False, "MonitorService 已暂停")

    def status(self):
        active_threads = sum(1 for thread in self.monitor_threads if thread.is_alive())
        result = {
            "running": self.running,
            "active_threads": active_threads,
            "started_at": self.start_time,
            "backend": self.backend,
            "etw_primary": self.etw_primary,
            "etw_fallback_reason": self.etw_fallback_reason,
            "active_collectors": list(self.active_collectors),
        }
        if self.etw_collector is not None:
            try:
                stats = self.etw_collector.stats()
                result["etw"] = {
                    "handled": stats.get("handled"),
                    "bus": stats.get("bus"),
                }
            except Exception:  # noqa: BLE001
                pass
        if self.process_table is not None:
            result["process_table"] = self.process_table.stats()
        return result

    def get_process_changes(self):
        return self.process_data.get("process_changes", []) if isinstance(self.process_data, dict) else []

    def get_critical_alerts(self, username=None, limit=20):
        if username:
            alerts = [a for a in self.critical_alerts if a.get("username") == username]
        else:
            alerts = self.critical_alerts
        return alerts[:limit]

    def subscribe_alerts(self):
        with self._subscriber_lock:
            self.subscriber_id += 1
            sid = self.subscriber_id
            self.alert_subscribers[sid] = {
                "queue": queue.Queue(maxsize=100),
                "username": None,
                "last_id": 0,
            }
            return sid

    def unsubscribe_alerts(self, sid):
        with self._subscriber_lock:
            if sid in self.alert_subscribers:
                del self.alert_subscribers[sid]

    def set_subscriber_user(self, sid, username):
        with self._subscriber_lock:
            if sid in self.alert_subscribers:
                self.alert_subscribers[sid]["username"] = username

    def _broadcast_alert(self, alert):
        with self._subscriber_lock:
            for sid, sub in list(self.alert_subscribers.items()):
                try:
                    sub["queue"].put_nowait(alert)
                except queue.Full:
                    pass

    def _consume_alerts(self):
        while not self.stop_event.is_set():
            try:
                event = self.alert_queue.get(timeout=1)
                if not isinstance(event, dict):
                    continue
                username = event.get("username") or self.current_user or "system"
                category = event.get("category", "monitor")
                title = event.get("title", "事件")
                message = event.get("message", "")
                severity = event.get("severity", "info")
                source = event.get("source", category)
                insert_log(username, category, title, message, severity, source)
                
                if severity == "critical":
                    alert_record = {
                        "username": username,
                        "category": category,
                        "title": title,
                        "message": message,
                        "severity": severity,
                        "source": source,
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    }
                    self.critical_alerts.insert(0, alert_record)
                    if len(self.critical_alerts) > self.max_critical_alerts:
                        self.critical_alerts = self.critical_alerts[:self.max_critical_alerts]
                    
                    self._broadcast_alert(alert_record)
                
                self.alert_queue.task_done()
            except queue.Empty:
                continue
            except Exception as exc:
                logging.debug("Alert consumer 出错: %s", exc)


monitor_service = MonitorService()
