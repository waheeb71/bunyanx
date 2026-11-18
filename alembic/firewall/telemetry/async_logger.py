"""
Firewall Telemetry — Async Non-Blocking JSON Logger
======================================================
Moved to 'telemetry/' package to avoid shadowing Python's built-in 'logging' module.
This file is the canonical source. The old path 'logging/async_logger.py' is kept
as a thin compatibility shim.
"""

import logging
import json
import queue
from logging.handlers import QueueHandler, QueueListener
import threading
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger_name": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "telemetry"):
            log_entry["telemetry"] = record.telemetry
        return json.dumps(log_entry)


class AsyncFirewallLogger:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if not cls._instance:
                cls._instance = super(AsyncFirewallLogger, cls).__new__(cls)
                cls._instance._init()
            return cls._instance

    def _init(self):
        # 100K capacity queue ensures high throughput bursting capability
        self.log_queue = queue.Queue(maxsize=100000)

        # Destination Handler (Stdout for now, could be passed to Loki/File)
        self.target_handler = logging.StreamHandler()
        self.target_handler.setFormatter(JSONFormatter())

        # Async Queue Handler
        self.queue_handler = QueueHandler(self.log_queue)

        # The listener spins up a dedicated background C-thread
        self.listener = QueueListener(self.log_queue, self.target_handler, respect_handler_level=True)
        self.listener.start()

        self.logger = logging.getLogger("firewall_fast_logger")
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False

        if not self.logger.handlers:
            self.logger.addHandler(self.queue_handler)

    def log_verdict(self, context_dict: dict, action: str, reason: str, rule: str):
        """Asynchronously log a firewall verdict in JSON structure."""
        telemetry = {
            "flow_id": context_dict.get("flow_id"),          # M8: flow correlation
            "src_ip": context_dict.get("src_ip"),
            "dst_ip": context_dict.get("dst_ip"),
            "src_port": context_dict.get("src_port"),
            "dst_port": context_dict.get("dst_port"),
            "protocol": context_dict.get("protocol"),
            "country_code": context_dict.get("country_code"),  # M7: GeoIP enrichment
            "action": action,
            "reason": reason,
            "rule": rule
        }
        self.logger.log(logging.INFO, "Firewall Evaluation Verdict", extra={"telemetry": telemetry})

    def stop(self):
        self.listener.stop()


# Global singleton
firewall_telemetry = AsyncFirewallLogger()
