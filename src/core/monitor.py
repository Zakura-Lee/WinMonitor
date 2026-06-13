import logging
import queue
import threading
import time
from models.log_model import insert_log
import config
from modules import process_mon, file_mon, network_mon, registry_mon, audit_mon, asset_mon


class MonitorService:
    def __init__(self):
        self.alert_queue = queue.Queue(maxsize=config.MAX_ALERT_QUEUE_SIZE)
        self.monitor_threads = []
        self.consumer_thread = None
        self.stop_event = threading.Event()
        self.running = False
        self.start_time = None
        self.process_data = {"process_changes": []}
        self.current_user = None
        self.critical_alerts = []
        self.max_critical_alerts = 50
        self.alert_subscribers = {}
        self.subscriber_id = 0
        self._subscriber_lock = threading.Lock()

    def start(self, username=None):
        if self.running:
            return
        self.stop_event = threading.Event()
        self.current_user = username or "system"
        if self.start_time is None:
            self.start_time = time.time()
            self.process_data = {"process_changes": []}
        self.consumer_thread = threading.Thread(target=self._consume_alerts, daemon=True)
        self.consumer_thread.start()

        self.monitor_threads = [
            threading.Thread(target=process_mon.p_mon, args=(self.stop_event, self.process_data, self.alert_queue), daemon=True),
            threading.Thread(target=file_mon.f_mon, args=(self.stop_event, {}, self.alert_queue), daemon=True),
            threading.Thread(target=network_mon.n_mon, args=(self.stop_event, {}, self.alert_queue), daemon=True),
            threading.Thread(target=registry_mon.r_mon, args=(self.stop_event, {}, self.alert_queue), daemon=True),
            threading.Thread(target=audit_mon.audit_mon, args=(self.stop_event, {}, self.alert_queue), daemon=True),
            threading.Thread(target=asset_mon.asset_mon, args=(self.stop_event, {}, self.alert_queue), daemon=True),
        ]

        for thread in self.monitor_threads:
            thread.start()

        self.running = True
        logging.info("MonitorService 已启动")

    def stop(self):
        if not self.running:
            return
        self.stop_event.set()
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
        self.start_time = None
        self.process_data = {"process_changes": []}
        self.current_user = None
        logging.info("MonitorService 已退出")

    def pause(self):
        if not self.running:
            return
        self.stop_event.set()
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
        logging.info("MonitorService 已暂停")

    def status(self):
        active_threads = sum(1 for thread in self.monitor_threads if thread.is_alive())
        return {
            "running": self.running,
            "active_threads": active_threads,
            "started_at": self.start_time,
        }

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
