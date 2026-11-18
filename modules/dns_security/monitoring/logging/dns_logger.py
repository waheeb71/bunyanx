"""
DNS Security — Structured Logger
=================================
Emits machine-readable JSON events to the named logger `dns_security.events`.

Events feed into Loki via Promtail/Alloy with the stream label:
  {module="dns_security", env="production"}

Event catalogue:
  dns.query        — every inspected DNS query (sample rate configurable)
  dns.block        — every blocked domain (always logged)
  dns.dart.decision — every DART engine decision with full XAI evidence
  dns.error        — any engine error (always logged)
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional


# ─── Named logger — feed this into Loki via Promtail JSON handler ─────────────
_BASE_LOGGER = logging.getLogger("dns_security.events")


# ─── Event schemas ─────────────────────────────────────────────────────────────

@dataclass
class QueryEvent:
    event: str = "dns.query"
    domain: str = ""
    src_ip: str = ""
    qtype: str = "A"
    action: str = "ALLOW"
    latency_ms: float = 0.0
    ts: float = 0.0

    def __post_init__(self):
        if not self.ts:
            self.ts = time.time()


@dataclass
class BlockEvent:
    event: str = "dns.block"
    domain: str = ""
    src_ip: str = ""
    category: str = ""
    severity: str = "HIGH"
    confidence: float = 0.0
    rule: Optional[str] = None
    ts: float = 0.0

    def __post_init__(self):
        if not self.ts:
            self.ts = time.time()


@dataclass
class DARTDecisionEvent:
    event: str = "dns.dart.decision"
    domain: str = ""
    src_ip: str = ""
    verdict: str = ""           # "MALICIOUS" | "CLEAN"
    resonance_score: float = 0.0
    layers_triggered: int = 0
    s1_score: float = 0.0
    s2_score: float = 0.0
    s3_score: float = 0.0
    evidence: Optional[Dict[str, Any]] = None
    ts: float = 0.0

    def __post_init__(self):
        if not self.ts:
            self.ts = time.time()


# ─── Logger singleton ──────────────────────────────────────────────────────────

class DNSLogger:
    """
    Thread-safe structured logger for the DNS security module.

    Emits JSON lines. Wire this logger's handler to ship to Loki:

        handler = logging.handlers.RotatingFileHandler("/var/log/ngfw/dns_events.jsonl")
        DNSLogger.get()._logger.addHandler(handler)
    """

    _instance: Optional["DNSLogger"] = None

    def __init__(self) -> None:
        self._logger = _BASE_LOGGER
        # Sample rate for dns.query events (1.0 = 100%, 0.1 = 10%)
        self.query_sample_rate: float = 1.0

    # ── Factory ────────────────────────────────────────────────────────────────

    @classmethod
    def get(cls) -> "DNSLogger":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    # ── Internal ───────────────────────────────────────────────────────────────

    def _emit(self, event_dict: dict, level: int = logging.INFO) -> None:
        """Serialize event to a single JSON line."""
        try:
            self._logger.log(level, json.dumps(event_dict, default=str))
        except Exception:
            pass  # Never crash the inspection pipeline due to logging

    # ── Public API ─────────────────────────────────────────────────────────────

    def log_query(
        self,
        domain: str,
        src_ip: str,
        qtype: str = "A",
        action: str = "ALLOW",
        latency_ms: float = 0.0,
    ) -> None:
        """
        Log every DNS query. Respects sample_rate to keep log volume manageable.
        Always logs BLOCK decisions regardless of sample rate.
        """
        import random
        if action == "ALLOW" and random.random() > self.query_sample_rate:
            return
        ev = QueryEvent(
            domain=domain, src_ip=src_ip,
            qtype=qtype, action=action, latency_ms=round(latency_ms, 4),
        )
        self._emit(asdict(ev))

    def log_block(
        self,
        domain: str,
        src_ip: str,
        category: str,
        severity: str = "HIGH",
        confidence: float = 1.0,
        rule: Optional[str] = None,
    ) -> None:
        """Always log block events at WARNING level for SOC pipelines."""
        ev = BlockEvent(
            domain=domain, src_ip=src_ip,
            category=category, severity=severity,
            confidence=round(confidence, 4), rule=rule,
        )
        self._emit(asdict(ev), level=logging.WARNING)

    def log_dart_decision(
        self,
        domain: str,
        src_ip: str,
        dart_decision,          # DARTDecision dataclass from dart_fusion
        s1_score: float = 0.0,
        s2_score: float = 0.0,
        s3_score: float = 0.0,
    ) -> None:
        """
        Log a full DART decision with XAI evidence.
        Malicious decisions are logged at WARNING, clean at DEBUG.
        """
        verdict = "MALICIOUS" if dart_decision.is_malicious else "CLEAN"
        ev = DARTDecisionEvent(
            domain=domain,
            src_ip=src_ip,
            verdict=verdict,
            resonance_score=round(dart_decision.resonance_score, 4),
            layers_triggered=dart_decision.layers_triggered,
            s1_score=round(s1_score, 4),
            s2_score=round(s2_score, 4),
            s3_score=round(s3_score, 4),
            evidence=dart_decision.evidence,
        )
        level = logging.WARNING if dart_decision.is_malicious else logging.DEBUG
        self._emit(asdict(ev), level=level)

    def log_error(self, domain: str, src_ip: str, error: str) -> None:
        """Log engine errors without crashing the packet path."""
        self._emit(
            {
                "event": "dns.error",
                "domain": domain,
                "src_ip": src_ip,
                "error": error,
                "ts": time.time(),
            },
            level=logging.ERROR,
        )
