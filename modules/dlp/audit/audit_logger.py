"""
bunyanx NGFW — DLP Audit Logger
====================================
Provides a structured, tamper-evident audit trail for all DLP events.

Design
------
* Every DLP detection (regex match, BEFP alert, or user feedback action) is
  emitted as a structured JSON audit record via Python's standard logging
  module using a dedicated logger ("dlp.audit").
* The audit logger also bridges to the SIEM subsystem (siem_connector.py)
  when a connector is registered.
* Records are written to a separate rotating file: dlp_audit.jsonl
  (independent of the application log so it can be shipped to a SIEM
   independently without filtering).

Tamper-evidence
---------------
Each audit record includes a chained SHA-256 HMAC over
(record_json || prev_record_hash) so that any modification or deletion
of a record in the middle of the log can be detected during forensic review.
The HMAC key is derived from NGFW_SECRET_KEY at startup.

Usage
-----
    from modules.dlp.audit.audit_logger import DLPAuditLogger

    audit = DLPAuditLogger.get_instance()
    audit.log_detection(event_id, src_ip, decision, findings, ers, explanation)
    audit.log_admin_action(admin_user, action, target, details)
    audit.log_feedback(event_id, label, submitted_by)
"""

import os
import json
import time
import hashlib
import hmac
import logging
import logging.handlers
import threading
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from system.siem.siem_connector import SIEMEvent, SIEMConnector

_logger = logging.getLogger(__name__)

# ─── Paths ────────────────────────────────────────────────────────────────────
_DATA_DIR_ENV = os.getenv("NGFW_DATA_DIR", "")
if _DATA_DIR_ENV:
    _AUDIT_LOG_PATH = Path(_DATA_DIR_ENV) / "dlp_audit.jsonl"
else:
    _AUDIT_LOG_PATH = Path(__file__).parent.parent / "data" / "dlp_audit.jsonl"
_AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

# Rotation: 100 MB per file, keep 10 rotated files
_AUDIT_MAX_BYTES    = int(os.getenv("DLP_AUDIT_MAX_BYTES", str(100 * 1024 * 1024)))
_AUDIT_BACKUP_COUNT = int(os.getenv("DLP_AUDIT_BACKUP_COUNT", "10"))

# ─── HMAC chain key ───────────────────────────────────────────────────────────
# Derived from NGFW_SECRET_KEY so audit chain is instance-specific.
# SECURITY FIX (CRITICAL): Must have a non-empty secret key to prevent audit forgery.
_raw_secret = os.getenv("NGFW_SECRET_KEY", "")
if not _raw_secret:
    raise EnvironmentError(
        "[DLP][AUDIT] NGFW_SECRET_KEY must be set. "
        "HMAC chain is compromised without a proper secret. "
        "Set NGFW_SECRET_KEY environment variable before starting the application."
    )
_HMAC_KEY = hashlib.sha256((_raw_secret + ":dlp-audit").encode()).digest()


def _compute_hmac(record_json: str, prev_hash: str) -> str:
    """Compute HMAC-SHA256 over (record_json || prev_hash)."""
    h = hmac.new(_HMAC_KEY, digestmod=hashlib.sha256)
    h.update(record_json.encode("utf-8"))
    h.update(prev_hash.encode("utf-8"))
    return h.hexdigest()


def _read_last_lines(file_path: Path, limit: int) -> List[str]:
    """Read the last N lines from a file by seeking backwards in chunks."""
    if not file_path.exists():
        return []
    
    lines: List[str] = []
    chunk_size = 8192
    with open(file_path, "rb") as f:
        try:
            f.seek(0, 2)
            file_size = f.tell()
            pointer = file_size
            buffer = b""
            
            while pointer > 0 and len(lines) < limit:
                read_amt = min(chunk_size, pointer)
                pointer -= read_amt
                f.seek(pointer)
                buffer = f.read(read_amt) + buffer
                
                # Split buffer into lines
                split_lines = buffer.split(b"\n")
                if pointer > 0:
                    buffer = split_lines[0]
                    lines_to_add = split_lines[1:]
                else:
                    buffer = b""
                    lines_to_add = split_lines
                
                for l in reversed(lines_to_add):
                    l_str = l.decode("utf-8", errors="ignore").strip()
                    if l_str:
                        lines.append(l_str)
                        if len(lines) >= limit:
                            break
            # Add final piece
            if buffer and len(lines) < limit:
                l_str = buffer.decode("utf-8", errors="ignore").strip()
                if l_str:
                    lines.append(l_str)
        except OSError:
            with open(file_path, "r", encoding="utf-8") as f_txt:
                all_lines = f_txt.readlines()
                return [l.strip() for l in reversed(all_lines[-limit:])]
    return lines


# ─── DLPAuditLogger ───────────────────────────────────────────────────────────

class DLPAuditLogger:
    """
    Thread-safe, chained audit logger for DLP events.

    Singleton — obtain via DLPAuditLogger.get_instance().
    Register a SIEM connector with register_siem_connector() to forward
    high-severity events to the SIEM in real time.
    """

    _instance: Optional["DLPAuditLogger"] = None
    _init_lock = threading.Lock()

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._siem: Optional[SIEMConnector] = None

        # Set up rotating file handler for the audit trail
        self._file_handler = logging.handlers.RotatingFileHandler(
            filename=str(_AUDIT_LOG_PATH),
            maxBytes=_AUDIT_MAX_BYTES,
            backupCount=_AUDIT_BACKUP_COUNT,
            encoding="utf-8",
        )
        self._file_handler.setFormatter(logging.Formatter("%(message)s"))

        self._audit_logger = logging.getLogger("dlp.audit")
        self._audit_logger.setLevel(logging.INFO)
        self._audit_logger.addHandler(self._file_handler)
        self._audit_logger.propagate = False  # Don't pollute the root logger

        # Seek the last line of the existing audit file to recover prev_hash (cross-restart chaining)
        self._prev_hash: str = "0" * 64
        if _AUDIT_LOG_PATH.exists():
            try:
                last_lines = _read_last_lines(_AUDIT_LOG_PATH, 5)
                for line in last_lines:
                    try:
                        record = json.loads(line)
                        if "_chain_hmac" in record:
                            self._prev_hash = record["_chain_hmac"]
                            _logger.info("[DLP][AUDIT] Recovered prev_hash from last log entry: %s", self._prev_hash[:16])
                            break
                    except json.JSONDecodeError:
                        continue
            except Exception as e:
                _logger.warning("[DLP][AUDIT] Failed to recover prev_hash from existing log: %s", e)

        _logger.info(
            "[DLP][AUDIT] Audit logger initialised. Path=%s max=%dMB backups=%d",
            _AUDIT_LOG_PATH,
            _AUDIT_MAX_BYTES // (1024 * 1024),
            _AUDIT_BACKUP_COUNT,
        )

    @classmethod
    def get_instance(cls) -> "DLPAuditLogger":
        """Return singleton instance (thread-safe)."""
        if cls._instance is None:
            with cls._init_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def register_siem_connector(self, connector: SIEMConnector) -> None:
        """Attach a SIEM connector to receive high-severity DLP detections."""
        with self._lock:
            self._siem = connector
        _logger.info("[DLP][AUDIT] SIEM connector registered: %s", type(connector).__name__)

    # ─── Core record writer ─────────────────────────────────────────────────

    def _write(self, record: Dict[str, Any]) -> None:
        """
        Serialize record to JSONL, compute HMAC chain, and write to audit log.
        Thread-safe.
        """
        with self._lock:
            record["record_id"] = str(uuid.uuid4())
            record["ts_utc"]    = time.time()
            record.setdefault("source", "dlp")

            # Compute chained HMAC (integrity chain)
            record_json = json.dumps(record, separators=(",", ":"), sort_keys=True)
            chain_hmac  = _compute_hmac(record_json, self._prev_hash)
            record["_chain_hmac"] = chain_hmac
            self._prev_hash = chain_hmac

            # Write final record (with HMAC field included)
            final_json = json.dumps(record, separators=(",", ":"), sort_keys=True)
            self._audit_logger.info(final_json)

    # ─── Public API ─────────────────────────────────────────────────────────

    def log_detection(
        self,
        event_id: str,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        decision: str,
        findings: List[Dict],
        ers: float,
        ai_score: float,
        final_score: float,
        explanation: List[str],
        action_taken: str = "MONITOR",
        dst_port: int = 0,
    ) -> None:
        """
        Log a DLP detection event.

        Called for every non-NORMAL DLP decision (SUSPICIOUS, HIGH_RISK, EXFILTRATION)
        and also for NORMAL decisions when regex matches were found.

        REM-12 FIX: Content matches (CC, SSN, etc.) are now explicitly logged.
        """
        severity = {
            "NORMAL":       "info",
            "SUSPICIOUS":   "warning",
            "HIGH_RISK":    "critical",
            "EXFILTRATION": "critical",
        }.get(decision, "warning")

        record = {
            "event_type":   "DLP_DETECTION",
            "event_id":     event_id,
            "severity":     severity,
            "src_ip":       src_ip,
            "dst_ip":       dst_ip,
            "dst_port":     dst_port,
            "protocol":     protocol,
            "decision":     decision,
            "action_taken": action_taken,
            "ers":          round(ers, 4),
            "ai_score":     round(ai_score, 4),
            "final_score":  round(final_score, 4),
            "match_count":  len(findings),
            "match_types":  list({f.get("type", "UNKNOWN") for f in findings}),
            "explanation":  explanation,
        }
        self._write(record)

        # Forward SUSPICIOUS+ to SIEM
        if severity in ("warning", "critical") and self._siem:
            siem_event = SIEMEvent(
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                severity=severity,
                event_type="DLP_DETECTION",
                source_ip=src_ip,
                destination_ip=dst_ip,
                source_port=0,
                destination_port=dst_port,
                protocol=protocol,
                action=action_taken,
                description=(
                    f"DLP {decision}: ERS={ers:.3f} AI={ai_score:.3f} "
                    f"matches={len(findings)} types={record['match_types']}"
                ),
                metadata={
                    "event_id": event_id,
                    "ers": ers,
                    "final_score": final_score,
                    "match_types": record["match_types"],
                    "explanation": explanation,
                },
            )
            # SIEM connector is async; submit as fire-and-forget to avoid blocking
            import asyncio
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    if not hasattr(self, "_siem_tasks"):
                        self._siem_tasks = set()
                    
                    # Clean up finished tasks
                    self._siem_tasks = {t for t in self._siem_tasks if not t.done()}
                    
                    if len(self._siem_tasks) >= 500:
                        _logger.warning("[DLP][AUDIT] SIEM task queue full (%d). Dropping SIEM event to prevent memory exhaustion.", len(self._siem_tasks))
                    else:
                        task = loop.create_task(self._siem.send(siem_event))
                        self._siem_tasks.add(task)
                else:
                    loop.run_until_complete(self._siem.send(siem_event))
            except Exception as exc:
                _logger.warning("[DLP][AUDIT] SIEM send failed: %s", exc)

    def log_admin_action(
        self,
        admin_user: str,
        action: str,
        target: str,
        details: Optional[Dict] = None,
        ip_address: str = "",
    ) -> None:
        """
        Log an administrative action (rule change, feedback review, config update).
        These are the most critical records for forensic investigation.
        """
        record = {
            "event_type":  "DLP_ADMIN_ACTION",
            "severity":    "info",
            "admin_user":  admin_user,
            "action":      action,
            "target":      target,
            "ip_address":  ip_address,
            "details":     details or {},
            "description": f"Admin performed {action} on {target}",
        }
        self._write(record)
        _logger.info(
            "[DLP][AUDIT] Admin action: user=%s action=%s target=%s",
            admin_user, action, target,
        )

    def log_feedback(
        self,
        event_id: str,
        label: str,
        submitted_by: str,
        review_action: Optional[str] = None,
        reviewed_by: Optional[str] = None,
    ) -> None:
        """Log analyst feedback submission and admin review decisions."""
        if review_action:
            admin_user = reviewed_by or "admin"
            action = f"FEEDBACK_{review_action.upper()}"
            description = f"Reviewed feedback for event {event_id}: {review_action}"
        else:
            admin_user = submitted_by or "analyst"
            action = f"FEEDBACK_SUBMIT_{label.upper()}"
            description = f"Submitted feedback for event {event_id} as {label}"

        record = {
            "event_type":   "DLP_FEEDBACK",
            "severity":     "info",
            "event_id":     event_id,
            "label":        label,
            "submitted_by": submitted_by,
            "review_action": review_action,
            "reviewed_by":   reviewed_by,
            "admin_user":    admin_user,
            "action":        action,
            "target":        f"event_id={event_id}",
            "description":   description,
        }
        self._write(record)

    def log_config_change(
        self,
        admin_user: str,
        field: str,
        old_value: Any,
        new_value: Any,
        ip_address: str = "",
    ) -> None:
        """Log any DLP configuration change for compliance."""
        record = {
            "event_type":  "DLP_CONFIG_CHANGE",
            "severity":    "warning",
            "admin_user":  admin_user,
            "field":       field,
            "old_value":   str(old_value),
            "new_value":   str(new_value),
            "ip_address":  ip_address,
            "action":      "CONFIG_CHANGE",
            "target":      field,
            "description": f"Changed config field '{field}' from '{old_value}' to '{new_value}'",
        }
        self._write(record)
        _logger.warning(
            "[DLP][AUDIT] Config change: user=%s field=%s old=%s new=%s",
            admin_user, field, old_value, new_value,
        )

    def get_recent_detections(self, limit: int = 100) -> List[Dict]:
        """
        Return the most recent audit records from the audit log.
        Used by the dashboard /api/dlp/audit endpoint.
        Note: reads from the active (not rotated) log file only.
        """
        records = []
        if not _AUDIT_LOG_PATH.exists():
            return records
        try:
            # Read lines from the end to satisfy the limit
            lines = _read_last_lines(_AUDIT_LOG_PATH, limit * 4)
            for line in lines:
                try:
                    rec = json.loads(line)
                    # Support all relevant DLP event types in the audit log view
                    if rec.get("event_type") in ("DLP_DETECTION", "DLP_ADMIN_ACTION", "DLP_CONFIG_CHANGE", "DLP_FEEDBACK"):
                        records.append(rec)
                        if len(records) >= limit:
                            break
                except json.JSONDecodeError:
                    continue
        except Exception as e:
            _logger.error("[DLP][AUDIT] Failed to read audit log: %s", e)
        return records

    def audit_log_path(self) -> str:
        """Return the absolute path to the active audit log file."""
        return str(_AUDIT_LOG_PATH)
