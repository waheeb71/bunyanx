import json
import hashlib
import logging
import threading
import queue
from typing import Dict
from sqlalchemy.orm import Session
from system.core.framework import InspectionContext, InspectionFinding, InspectionResult, InspectionAction
from modules.http_inspection.models import HTTPInspectionLog

class EventLogger:
    def __init__(self, logger: logging.Logger, num_workers: int = 8):
        self.logger = logger
        self.ai_logger = logging.getLogger("bunyanx.http.ai_events")
        
        self.log_queue = queue.Queue(maxsize=1000)
        self.workers = []
        for i in range(num_workers):
            t = threading.Thread(target=self._worker_loop, name=f"http_log_{i}", daemon=True)
            t.start()
            self.workers.append(t)

    def stop(self, timeout: float = 1.0) -> None:
        """Gracefully stop background logging worker threads."""
        for _ in self.workers:
            try:
                self.log_queue.put_nowait(None)
            except queue.Full:
                pass
        for t in self.workers:
            if t.is_alive():
                t.join(timeout=timeout)

    def _worker_loop(self):
        while True:
            try:
                task = self.log_queue.get()
                if task is None:
                    break
                task()
            except Exception as e:
                self.logger.error(f"Log worker error: {e}")
            finally:
                self.log_queue.task_done()

    def log_attack_async(self, get_db_session, http_data: Dict, finding: InspectionFinding, context: InspectionContext, mode: str):
        url = http_data.get('url', '')
        host = http_data.get('headers', {}).get('host', '')
        method = http_data.get('method', '')
        headers = http_data.get('headers', {})

        ua_raw = headers.get('user-agent', '')
        ua_hash = hashlib.sha256(ua_raw.encode()).hexdigest() if ua_raw else None

        def worker():
            db: Session = get_db_session()
            try:
                log_entry = HTTPInspectionLog(
                    source_ip=context.src_ip,
                    target_host=host or context.dst_ip,
                    url_path=url[:1024] if url else '',
                    request_method=method[:10] if method else None,
                    user_agent_hash=ua_hash,
                    user_agent_raw=ua_raw[:512] if ua_raw else None,
                    flow_id=context.flow_id[:64] if context.flow_id else None,
                    pattern_matched=finding.description[:255],
                    severity=finding.severity,
                    action="BLOCK" if mode == "enforce" else "LOG_ONLY (MONITOR)",
                    details=str(finding.evidence)[:1024]
                )
                db.add(log_entry)
                db.commit()
            except Exception as e:
                self.logger.error(f"Failed to write async HTTP attack log: {e}")
            finally:
                db.close()

        try:
            self.log_queue.put(worker, block=False)
        except queue.Full:
            self.logger.warning("Log queue is full! Dropping log entry to prevent OOM.")

    def emit_ai_event(self, http_data: Dict, result: InspectionResult, context: InspectionContext) -> None:
        if result.action not in (InspectionAction.BLOCK, InspectionAction.LOG_ONLY):
            return

        try:
            event = {
                "event_type": "http_inspection_alert",
                "timestamp": context.timestamp,
                "flow_id": context.flow_id,
                "src_ip": context.src_ip,
                "dst_ip": context.dst_ip,
                "dst_port": context.dst_port,
                "method": http_data.get("method"),
                "url": http_data.get("url", "")[:256],
                "action": result.action.name,
                "findings_count": len(result.findings),
                "top_severity": result.findings[0].severity if result.findings else None,
                "top_category": result.findings[0].category if result.findings else None,
                "confidence": result.findings[0].confidence if result.findings else None,
            }
            self.ai_logger.info(json.dumps(event))

            if result.action == InspectionAction.BLOCK:
                try:
                    from system.events.bus import EventBus
                    from system.events.topics import Topics
                    EventBus.publish_from_thread(Topics.THREAT_DETECTED, {
                        "src_ip": context.src_ip,
                        "dst_ip": context.dst_ip,
                        "reason": f"HTTP Threat Blocked: {event.get('top_category', 'HTTP_ATTACK')}",
                        "module": "http_inspection",
                    })
                except Exception as exc:
                    self.logger.debug(f"Failed to publish HTTP threat to EventBus: {exc}")
        except Exception as e:
            self.logger.debug(f"AI event emission failed (non-critical): {e}")
