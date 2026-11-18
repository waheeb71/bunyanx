"""
PHANTOM IDS/IPS — Structured Logger (Loki-compatible)
=======================================================
Emits structured JSON log lines that Promtail can scrape into Loki.

Every PHANTOM event carries a fixed set of labels so Grafana dashboards
can filter by:
    module="ids_ips"  layer="sbe|ctgb|hgtc|ocl|fusion"
    threat_class="encrypted_c2|..."  action="BLOCK|ALLOW"

Usage:
    from modules.ids_ips.logging.phantom_logger import PhantomLogger
    log = PhantomLogger()
    log.threat(src_ip, dst_ip, threat_class, confidence, action)
    log.drift(error_rate, window_size)
    log.ocl_update(class_name, memory_size)
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, Optional

# Fixed labels for all PHANTOM log lines
_MODULE  = "ids_ips"
_SERVICE = "phantom"


def _now_iso() -> str:
    """ISO-8601 timestamp with millisecond precision."""
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + \
           f".{int((time.time() % 1) * 1000):03d}Z"


class PhantomLogger:
    """
    Thin wrapper around Python logging that emits JSON records.
    Each record is a single JSON object per line — ingested by Promtail/Loki
    via the system logging infrastructure.

    All methods are no-op safe and never raise.
    """

    def __init__(self, name: str = "phantom") -> None:
        self._log = logging.getLogger(f"ids_ips.{name}")

    def _emit(self, level: str, layer: str, event: str,
              data: Dict[str, Any]) -> None:
        record = {
            "timestamp": _now_iso(),
            "module":    _MODULE,
            "service":   _SERVICE,
            "layer":     layer,
            "event":     event,
            **data,
        }
        line = json.dumps(record, ensure_ascii=True, default=str)
        getattr(self._log, level, self._log.info)(line)

    # ── Layer 1: SBE ─────────────────────────────────────────────────────────

    def sbe_encoded(self, src_ip: str, payload_len: int,
                    cache_hit: bool, elapsed_ms: float) -> None:
        """Logged once per SBE encode operation."""
        self._emit("debug", "sbe", "encoded", {
            "src_ip":      src_ip,
            "payload_len": payload_len,
            "cache_hit":   cache_hit,
            "elapsed_ms":  round(elapsed_ms, 3),
        })

    # ── Layer 2: CTGB ────────────────────────────────────────────────────────

    def graph_updated(self, nodes: int, causal_edges: int,
                      causal_density: float) -> None:
        self._emit("debug", "ctgb", "graph_updated", {
            "graph_nodes":    nodes,
            "causal_edges":   causal_edges,
            "causal_density": round(causal_density, 4),
        })

    # ── Layer 3: HGTC ────────────────────────────────────────────────────────

    def inference_result(self, src_ip: str, dst_ip: str,
                         threat_class: str, confidence: float,
                         is_threat: bool, elapsed_ms: float) -> None:
        level = "warning" if is_threat else "debug"
        self._emit(level, "hgtc", "inference", {
            "src_ip":       src_ip,
            "dst_ip":       dst_ip,
            "threat_class": threat_class,
            "confidence":   round(confidence, 4),
            "is_threat":    is_threat,
            "elapsed_ms":   round(elapsed_ms, 3),
        })

    # ── Layer 4: OCL ─────────────────────────────────────────────────────────

    def drift_detected(self, error_rate: float, window_size: int,
                       total_drifts: int) -> None:
        self._emit("warning", "ocl", "drift_detected", {
            "error_rate":   round(error_rate, 4),
            "window_size":  window_size,
            "total_drifts": total_drifts,
        })

    def ocl_update(self, label: str, memory_size: int,
                   loss: Optional[float] = None) -> None:
        data: Dict[str, Any] = {"label": label, "memory_size": memory_size}
        if loss is not None:
            data["loss"] = round(loss, 6)
        self._emit("debug", "ocl", "gradient_step", data)

    # ── Layer 5: Fusion / Decision ───────────────────────────────────────────

    def threat(self, src_ip: str, dst_ip: str, threat_class: str,
               confidence: float, causal_density: float,
               action: str, latency_ms: float) -> None:
        """Primary security event — always logged at WARNING+."""
        level = "warning" if action == "ALLOW" else "error"
        self._emit(level, "fusion", "threat_event", {
            "src_ip":         src_ip,
            "dst_ip":         dst_ip,
            "threat_class":   threat_class,
            "confidence":     round(confidence, 4),
            "causal_density": round(causal_density, 4),
            "action":         action,
            "latency_ms":     round(latency_ms, 3),
        })

    def block(self, src_ip: str, dst_ip: str, threat_class: str,
              confidence: float) -> None:
        """Emitted when BLOCK decision is taken — maps to Loki alert."""
        self._emit("error", "fusion", "block_decision", {
            "src_ip":       src_ip,
            "dst_ip":       dst_ip,
            "threat_class": threat_class,
            "confidence":   round(confidence, 4),
        })

    def allow_low_conf(self, src_ip: str, threat_class: str,
                       confidence: float) -> None:
        """Emitted when threat detected but confidence below threshold."""
        self._emit("info", "fusion", "allow_low_confidence", {
            "src_ip":       src_ip,
            "threat_class": threat_class,
            "confidence":   round(confidence, 4),
        })
