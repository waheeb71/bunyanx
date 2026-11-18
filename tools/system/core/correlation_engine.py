"""
bunyanx NGFW — Correlation Engine
=======================================
Subscribes to EventBus events and correlates them into higher-order signals.

This replaces direct module-to-module calls (the "no-direct-calls" rule).
Instead of: ModuleA calls CorrelationEngine.correlate(finding)
Now:        ModuleA publishes → EventBus → CorrelationEngine subscribes

Correlation rules:
  1. Multi-source threat amplification
     3+ threat.detected events from the same IP in 60s → BLOCK
  2. AI + IDS convergence
     ai.score_generated (score ≥ 0.7) + threat.detected → upgrade to CRITICAL
  3. Scan detection
     5+ unique dst_ports from same IP in 30s → port scan → BLOCK
  4. Anomaly + Threat Intel convergence
     anomaly.scored + intel_reputation=HIGH → immediate BLOCK

Usage:
    engine = CorrelationEngine.instance()
    await engine.start()
"""

import asyncio
import logging
import time
from collections import defaultdict
from typing import Optional

logger = logging.getLogger(__name__)


def _get_AEGIS_pipeline():
    """
    Return the UnifiedDefensePipeline singleton attached to the application,
    or None if it is not yet initialised.
    Uses the same _app_instance pattern as the API router.
    """
    try:
        import system.core.engine as _eng
        inst = getattr(_eng, '_app_instance', None)
        if inst:
            return getattr(inst, 'AEGIS_engine', None)
    except Exception:
        pass
    return None


async def _AEGIS_fire(AEGIS, src_ip: str, event_type: str) -> None:
    """
    Fire-and-forget coroutine: calls AEGIS.process_event() in the background.
    Errors are logged but never propagate to the calling event handler.
    """
    try:
        await asyncio.to_thread(AEGIS.process_event, src_ip, event_type)
    except Exception as _e:
        logger.debug("AEGIS fire-and-forget error for %s/%s: %s", src_ip, event_type, _e)


# ── Event-type bridge: CorrelationEngine category → KillchainGraph node ───────────
# CorrelationEngine emits raw category strings that do not always match the
# node names used by KillchainGraph (and the AEGIS ASE).  This table maps
# them to valid Kill-Chain stage names so the Bayesian filter gets clean input.
_CORRELATION_TO_AEGIS: dict[str, str] = {
    # Network-level categories
    "ANOMALY":          "LATERAL_MOVEMENT",   # high anomaly score → lateral indicator
    "PORT_SCAN":        "SCAN",
    "PORTSCAN":         "SCAN",
    "SCAN_DETECTED":    "SCAN",
    # Threat intel / IDS categories
    "MALWARE_DETECTED": "MALWARE",
    "MALWARE_AV":       "MALWARE",
    "PHISHING":         "WAF_EXPLOIT",
    "WAF":              "WAF_EXPLOIT",
    "C2":               "DGA_C2",
    "C2_DETECTED":      "DGA_C2",
    "EXFIL":            "DLP_EXFIL",
    "DLP":              "DLP_EXFIL",
    "LATERAL":          "LATERAL_MOVEMENT",
    "PRIVESC":          "PRIVILEGE_ESCALATION",
    "PRIV_ESC":         "PRIVILEGE_ESCALATION",
    "PRIVILEGE":        "PRIVILEGE_ESCALATION",
    "RANSOMWARE_DET":   "RANSOMWARE",
    "PERSIST":          "PERSISTENCE",
    # Pass-through (already valid KillchainGraph nodes)
    "WAF_EXPLOIT":      "WAF_EXPLOIT",
    "DGA_C2":           "DGA_C2",
    "DLP_EXFIL":        "DLP_EXFIL",
    "LATERAL_MOVEMENT": "LATERAL_MOVEMENT",
    "PRIVILEGE_ESCALATION": "PRIVILEGE_ESCALATION",
    "PERSISTENCE":      "PERSISTENCE",
    "RANSOMWARE":       "RANSOMWARE",
}


def _map_event(raw_event_type: str) -> str:
    """Translate a raw CorrelationEngine category to a KillchainGraph node name."""
    upper = raw_event_type.upper()
    return _CORRELATION_TO_AEGIS.get(upper, upper)  # pass-through if unknown


class CorrelationEngine:
    """
    Event-driven correlation engine.
    Subscribes to threat events and emits compound response decisions.
    """

    _instance: Optional["CorrelationEngine"] = None

    # Sliding window parameters
    WINDOW_S = 60          # 1 minute correlation window
    THREAT_THRESHOLD = 3   # threats from same IP before auto-block
    PORT_SCAN_THRESHOLD = 5  # unique dst_ports before scan detection
    SCAN_WINDOW_S = 30     # port scan detection window

    def __init__(self):
        self._threat_counts: dict = defaultdict(list)      # ip → [timestamps]
        self._dst_ports: dict = defaultdict(dict)           # ip → {port: timestamp}
        self._ai_scores: dict = {}                          # session_id → score
        self._bus = None

    @classmethod
    def instance(cls) -> "CorrelationEngine":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    async def start(self) -> None:
        """Subscribe to all relevant event topics."""
        from system.events.bus import EventBus
        from system.events.topics import Topics

        self._bus = await EventBus.instance()

        await self._bus.subscribe(Topics.THREAT_DETECTED, self._on_threat)
        await self._bus.subscribe(Topics.AI_SCORE_GENERATED, self._on_ai_score)
        await self._bus.subscribe(Topics.ANOMALY_SCORED, self._on_anomaly)
        await self._bus.subscribe(Topics.PACKET_INSPECTED, self._on_packet)

        # Background cleanup
        asyncio.create_task(self._cleanup_loop())

        logger.info("[Correlation] Engine started — subscribing to event bus ✓")

    # ── Event Handlers ─────────────────────────────────────────────

    async def _on_threat(self, event: dict) -> None:
        """Rule 1 & 2: Multi-source threat amplification + AEGIS per-IP update."""
        src_ip = event.get("src_ip", "")
        if not src_ip or src_ip == "0.0.0.0":
            return

        # ── AEGIS: feed the confirmed threat into the adversarial pipeline ───
        AEGIS = _get_AEGIS_pipeline()
        if AEGIS:
            raw_type  = event.get("category", event.get("event_type", "UNKNOWN"))
            kcg_event = _map_event(raw_type)
            asyncio.create_task(_AEGIS_fire(AEGIS, src_ip, kcg_event))

        now = time.time()
        # Add to sliding window
        self._threat_counts[src_ip] = [
            t for t in self._threat_counts[src_ip]
            if now - t < self.WINDOW_S
        ]
        self._threat_counts[src_ip].append(now)

        count = len(self._threat_counts[src_ip])

        if count >= self.THREAT_THRESHOLD:
            logger.warning(
                f"[Correlation] Rule 1: {src_ip} triggered {count} threats "
                f"in {self.WINDOW_S}s → escalating to BLOCK"
            )
            await self._emit_block(src_ip, reason=f"Correlation: {count} threats in {self.WINDOW_S}s")
            # Publish correlation.triggered so audio system fires an alert tone
            try:
                from system.events.topics import Topics
                await self._bus.publish(Topics.CORRELATION_TRIGGERED, {
                    "src_ip":    src_ip,
                    "rule":      "rule_1_threat_threshold",
                    "count":     count,
                    "window_s":  self.WINDOW_S,
                    "action":    "BLOCK",
                })
            except Exception as _ce:
                logger.warning(f"[Correlation] Failed to publish correlation.triggered: {_ce}")

        # Rule 2: Check if AI also flagged this session
        session_id = event.get("session_id", "")
        ai_score = self._ai_scores.get(session_id, 0.0)
        if ai_score >= 0.7:
            logger.warning(
                f"[Correlation] Rule 2: AI (score={ai_score:.2f}) + "
                f"IDS convergence for {src_ip} → CRITICAL"
            )
            await self._emit_alert(
                src_ip=src_ip,
                severity="critical",
                message=f"AI + IDS convergence: score={ai_score:.2f}"
            )

    async def _on_ai_score(self, event: dict) -> None:
        """Store AI score for cross-correlation."""
        session_id = event.get("session_id", "")
        score = float(event.get("score", 0.0))
        if session_id:
            self._ai_scores[session_id] = score

    async def _on_anomaly(self, event: dict) -> None:
        """Rule 4: Anomaly + Threat Intel convergence + AEGIS update."""
        score = float(event.get("score", 0.0))
        if score < 0.5:
            return

        # ── AEGIS: anomaly with high score = lateral-movement indicator ───
        AEGIS = _get_AEGIS_pipeline()
        device_ip = event.get("device_id", "")
        if AEGIS and device_ip:
            asyncio.create_task(_AEGIS_fire(AEGIS, device_ip, _map_event("ANOMALY")))

        # Check threat intel reputation for the same IP
        try:
            from system.threat_intel.intel_manager import ThreatIntelManager
            # We'd need the IP from anomaly context — using device_id as proxy
            device_ip = event.get("device_id", "")
            if device_ip and ThreatIntelManager.instance().is_ip_blocked(device_ip):
                logger.warning(
                    f"[Correlation] Rule 4: Anomaly (score={score:.2f}) + "
                    f"Threat Intel hit for {device_ip} → immediate BLOCK"
                )
                await self._emit_block(device_ip, reason="Anomaly + Threat Intel convergence")
        except Exception:
            pass

    async def _on_packet(self, event: dict) -> None:
        """Rule 3: Port scan detection + AEGIS port-scan awareness."""
        src_ip = event.get("src_ip", "")
        dst_port = event.get("dst_port", 0)
        if not src_ip or not dst_port:
            return

        now = time.time()
        # Prune old port entries
        self._dst_ports[src_ip] = {
            port: ts for port, ts in self._dst_ports[src_ip].items()
            if now - ts < self.SCAN_WINDOW_S
        }
        self._dst_ports[src_ip][dst_port] = now

        unique_ports = len(self._dst_ports[src_ip])
        if unique_ports >= self.PORT_SCAN_THRESHOLD:
            logger.warning(
                f"[Correlation] Rule 3: Port scan from {src_ip} "
                f"({unique_ports} unique ports in {self.SCAN_WINDOW_S}s) → BLOCK"
            )
            await self._emit_block(src_ip, reason=f"Port scan: {unique_ports} ports")
            # Publish ids.port_scan so audio system fires a security alert tone
            try:
                from system.events.topics import Topics
                await self._bus.publish(Topics.IDS_PORT_SCAN, {
                    "src_ip":       src_ip,
                    "unique_ports": unique_ports,
                    "window_s":     self.SCAN_WINDOW_S,
                    "action":       "BLOCK",
                })
            except Exception as _ce:
                logger.warning(f"[Correlation] Failed to publish ids.port_scan: {_ce}")

            # ── AEGIS: confirmed port-scan → feeds RECONNAISSANCE stage ───
            AEGIS = _get_AEGIS_pipeline()
            if AEGIS:
                asyncio.create_task(_AEGIS_fire(AEGIS, src_ip, "SCAN"))

            # Clear after detection to avoid repeated firing
            self._dst_ports[src_ip].clear()

    # ── Response Emitters ──────────────────────────────────────────

    async def _emit_block(self, ip: str, reason: str) -> None:
        """Publish a response.block event — AccelerationBridge will handle it."""
        from system.events.topics import Topics
        from system.events.schemas import ResponseBlockEvent

        event = ResponseBlockEvent(
            src_ip=ip,
            reason=reason,
            duration_s=3600,
            triggered_by="correlation_engine",
        )
        await self._bus.publish(Topics.RESPONSE_BLOCK, event.to_dict())

    async def _emit_alert(self, src_ip: str, severity: str, message: str) -> None:
        from system.events.topics import Topics
        from system.events.schemas import ResponseAlertEvent

        event = ResponseAlertEvent(
            severity=severity,
            title="Correlation Engine Alert",
            message=message,
            src_ip=src_ip,
        )
        await self._bus.publish(Topics.RESPONSE_ALERT, event.to_dict())

    async def _cleanup_loop(self) -> None:
        """Remove stale sliding window entries periodically."""
        while True:
            await asyncio.sleep(60)
            now = time.time()
            # Clean threat counts
            for ip in list(self._threat_counts.keys()):
                self._threat_counts[ip] = [
                    t for t in self._threat_counts[ip]
                    if now - t < self.WINDOW_S
                ]
                if not self._threat_counts[ip]:
                    del self._threat_counts[ip]
            # Clean AI scores (older than 5 min)
            # (simplified: just clear all — sessions are short-lived)
            if len(self._ai_scores) > 10000:
                self._ai_scores.clear()
