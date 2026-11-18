"""
bunyanx NGFW — Predictive Correlation Engine
==============================================

Bridges the Unified Event Sink → AEGIS v3 pipeline.

This engine receives raw security events from CorrelationEngine,
routes them through the full AEGIS v3 inference pipeline
(KillchainGraph → AEGISEngine → DB write), and maintains
the IntentPredictor and ForecastGate state used by the API layer.

Architecture
------------
    EventSink.emit(event)
         │
         ▼
    PredictiveCorrelationEngine.process_event()
         │
         ├─► KillchainGraph.record_transition()  (Markov chain update)
         ├─► AEGISEngine.process_event()         (Full AEGIS inference)
         ├─► IntentPredictor.update()             (Intent state update)
         ├─► ForecastGate.record_decision()       (RL safety log)
         └─► DB writes (AEGISDecisionLog, AttackIntentLog, AEGISDecoyLog)
"""
from __future__ import annotations

import json
import asyncio
import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# IntentPredictor — per-IP intent state for /intent/active endpoint
# ---------------------------------------------------------------------------

_SEVERITY_MAP = {
    "RANSOMWARE":           "HIGH",
    "DLP_EXFIL":            "HIGH",
    "PRIVILEGE_ESCALATION": "HIGH",
    "PRIV_ESC":             "HIGH",
    "LATERAL_MOVEMENT":     "HIGH",
    "LATERAL":              "HIGH",
    "DGA_C2":               "MEDIUM",
    "WAF_EXPLOIT":          "MEDIUM",
    "MALWARE":              "MEDIUM",
    "PERSISTENCE":          "MEDIUM",
    "SCAN":                 "LOW",
}

_COUNTERMEASURE_MAP = {
    "MONITOR":           "مراقبة مستمرة — تعقب نشاط الـIP وتسجيل كل الاتصالات",
    "ALERT_ONLY":        "تنبيه SOC — إرسال تحذير فوري لمحلل الأمن المناوب",
    "RATE_LIMIT":        "تقييد معدل الاتصالات — تطبيق سياسة QoS صارمة على المصدر",
    "HONEYPOT_REDIRECT": "إعادة توجيه إلى مصيدة — تحويل المهاجم لخادم وهمي محكوم",
    "DECOY_TRAP":        "نشر فخ خداع — زرع ملفات/بيانات مزيفة على المسار المتوقع",
    "ISOLATE_PARTIAL":   "عزل جزئي — قطع الاتصال بالإنترنت مع الإبقاء على الشبكة الداخلية",
    "ISOLATE_FULL":      "عزل كامل — قطع جميع اتصالات المصدر فوراً",
    "KILL_SESSIONS":     "إنهاء الجلسات — قطع جميع الجلسات النشطة من هذا الـIP",
    "BLOCK_IP":          "حظر الـIP — إضافة المصدر لقائمة الحظر الدائم في جدار الحماية",
    "EMERGENCY_ISOLATE": "عزل طارئ — استجابة طارئة شاملة مع إخطار فريق الأزمات",
    "CREDENTIAL_ROTATE": "تدوير بيانات الاعتماد — إلغاء جلسات المصادقة وإجبار على إعادة المصادقة",
    "FAKE_PATCH":        "تحديث وهمي — تقديم ثغرة مزيفة لاستدراج المهاجم وكشف أسلوبه",
}

@dataclass
class IntentEntry:
    src_ip:          str
    current_stage:   str
    predicted_next:  str
    confidence:      float
    severity:        str
    countermeasure:  str
    last_seen:       float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "src_ip":         self.src_ip,
            "current_stage":  self.current_stage,
            "predicted_next": self.predicted_next,
            "confidence":     round(self.confidence, 4),
            "severity":       self.severity,
            "countermeasure": self.countermeasure,
            "last_seen":      self.last_seen,
        }


class IntentPredictor:
    """
    Maintains per-IP intent prediction state for the /intent/active endpoint.
    Updated by PredictiveCorrelationEngine on every processed event.
    """

    # IPs inactive for more than 10 minutes are removed from active intents
    INTENT_TTL_SECONDS = 600

    def __init__(self) -> None:
        self._intents: dict[str, IntentEntry] = {}
        self._history: dict[str, list[dict]] = defaultdict(list)  # src_ip → prediction history

    def update(
        self,
        src_ip: str,
        current_stage: str,
        predicted_next: str,
        confidence: float,
        action: str,
    ) -> None:
        """Update or create intent entry for a source IP."""
        severity     = _SEVERITY_MAP.get(predicted_next.upper(), "LOW")
        countermeasure = _COUNTERMEASURE_MAP.get(action, action)

        entry = IntentEntry(
            src_ip=src_ip,
            current_stage=current_stage,
            predicted_next=predicted_next,
            confidence=confidence,
            severity=severity,
            countermeasure=countermeasure,
        )
        self._intents[src_ip] = entry

        # Append to per-IP history (keep last 50)
        hist = self._history[src_ip]
        hist.append({
            "timestamp":     entry.last_seen,
            "current_stage": current_stage,
            "predicted_next": predicted_next,
            "confidence":    round(confidence, 4),
            "action":        action,
        })
        if len(hist) > 50:
            self._history[src_ip] = hist[-50:]

    def get_all_active_intents(self) -> list[dict]:
        """Return all non-expired active intent entries."""
        now = time.time()
        active = {
            ip: e for ip, e in self._intents.items()
            if (now - e.last_seen) < self.INTENT_TTL_SECONDS
        }
        # Evict expired
        self._intents = active
        return [e.to_dict() for e in sorted(
            active.values(), key=lambda x: x.confidence, reverse=True
        )]

    def get_ip_intent(self, src_ip: str) -> list[dict]:
        """Return full prediction history for a specific IP."""
        return self._history.get(src_ip, [])

    def get_accuracy_report(self) -> dict:
        """Return basic stats (full accuracy tracking is in AIS)."""
        return {
            "active_tracked_ips": len(self._intents),
            "total_history_entries": sum(len(v) for v in self._history.values()),
        }

    def resolve_ip(self, src_ip: str) -> None:
        """Mark an IP as resolved (remove from active intents)."""
        self._intents.pop(src_ip, None)


# ---------------------------------------------------------------------------
# RLSafetyLayer — RL budget + audit log for /safety/budget and /safety/audit
# ---------------------------------------------------------------------------

@dataclass
class SafetyAuditEntry:
    timestamp:      float
    target_ip:      str
    target_type:    str
    proposed:       str
    approved:       str
    constrained:    bool
    net_reward:     float
    requires_human: bool
    reason:         str

    def to_dict(self) -> dict:
        return {
            "timestamp":      self.timestamp,
            "target_ip":      self.target_ip,
            "target_type":    self.target_type,
            "proposed":       self.proposed,
            "approved":       self.approved,
            "constrained":    self.constrained,
            "net_reward":     round(self.net_reward, 4),
            "requires_human": self.requires_human,
            "reason":         self.reason,
        }


class RLSafetyLayer:
    """
    Tracks RL risk budget and maintains audit log.
    Exposed via /safety/budget and /safety/audit endpoints.
    """

    # Action cost table (mirrors router's hardcoded chip labels)
    ACTION_COST = {
        "MONITOR":           0.0,
        "ALERT_ONLY":        0.0,
        "RATE_LIMIT":        5.0,
        "HONEYPOT_REDIRECT": 8.0,
        "DECOY_TRAP":        8.0,
        "ISOLATE_PARTIAL":   15.0,
        "CREDENTIAL_ROTATE": 10.0,
        "FAKE_PATCH":        10.0,
        "KILL_SESSIONS":     20.0,
        "ISOLATE_FULL":      35.0,
        "BLOCK_IP":          20.0,
        "EMERGENCY_ISOLATE": 35.0,
    }

    # Regen rate: budget regenerates at this rate per second
    REGEN_RATE = 0.5  # units per second
    MAX_BUDGET  = 100.0
    HUMAN_REVIEW_THRESHOLD = 35.0  # actions costing this much need human review

    def __init__(self) -> None:
        self._current_budget = self.MAX_BUDGET
        self._last_regen_ts  = time.time()
        self._audit_log: deque = deque(maxlen=500)

    def _regen(self) -> None:
        """Regenerate budget based on elapsed time."""
        now = time.time()
        elapsed = now - self._last_regen_ts
        self._current_budget = min(
            self.MAX_BUDGET,
            self._current_budget + elapsed * self.REGEN_RATE
        )
        self._last_regen_ts = now

    def record_action(
        self,
        src_ip:      str,
        proposed:    str,
        approved:    str,
        target_type: str = "network_ip",
    ) -> None:
        """Record an RL safety decision and deduct from budget."""
        self._regen()
        cost = self.ACTION_COST.get(approved, 0.0)
        constrained = proposed != approved
        requires_human = cost >= self.HUMAN_REVIEW_THRESHOLD

        budget_before = self._current_budget
        self._current_budget = max(0.0, self._current_budget - cost)

        entry = SafetyAuditEntry(
            timestamp=time.time(),
            target_ip=src_ip,
            target_type=target_type,
            proposed=proposed,
            approved=approved,
            constrained=constrained,
            net_reward=-(cost),
            requires_human=requires_human,
            reason=(
                f"Budget deduction: -{cost:.1f} pts | "
                f"Before={budget_before:.1f} After={self._current_budget:.1f}"
                + (" | CONSTRAINED" if constrained else "")
                + (" | HUMAN_REVIEW_REQUIRED" if requires_human else "")
            ),
        )
        self._audit_log.append(entry)

    def get_budget_status(self) -> dict:
        self._regen()
        return {
            "current_budget":  round(self._current_budget, 2),
            "max_budget":      self.MAX_BUDGET,
            "utilization_pct": round((1.0 - self._current_budget / self.MAX_BUDGET) * 100, 1),
            "regen_rate":      f"{self.REGEN_RATE} pts/sec",
        }

    def get_audit_log(self, n: int = 20) -> list[dict]:
        entries = list(self._audit_log)
        return [e.to_dict() for e in entries[-n:]]


# ---------------------------------------------------------------------------
# ForecastGate — container object set on _app_instance for router access
# ---------------------------------------------------------------------------

class ForecastGate:
    """
    Holds the RLSafetyLayer instance.
    Set on _app_instance.forecast_gate so the router can access it.
    """
    def __init__(self) -> None:
        self.safety = RLSafetyLayer()


# ---------------------------------------------------------------------------
# PredictiveCorrelationEngine — Main event bridge
# ---------------------------------------------------------------------------

class PredictiveCorrelationEngine:
    """
    Real Predictive Correlation Engine.
    Bridges EventSink → AEGIS v3 full inference pipeline.

    Wired to _app_instance so the API router can access:
        - correlator.killchain_graph     → /killchain/graph
        - correlator.intent_predictor    → /intent/active, /intent/{ip}
        - app_instance.forecast_gate     → /safety/budget, /safety/audit
    """

    def __init__(self, orchestrator=None, logger=None) -> None:
        self._logger = logger or _log
        self._orchestrator = orchestrator

        # Sub-components accessible by router
        from modules.predictive_ai.engine.killchain_graph import KillchainGraph
        self.killchain_graph  = KillchainGraph(logger=self._logger)
        self.intent_predictor = IntentPredictor()
        # Per-IP event history for killchain scoring.
        # maxlen=10: sliding window — prevents evaluate_ip_events from growing O(n^2)
        self._ip_events: dict[str, deque] = defaultdict(lambda: deque(maxlen=10))
        # Per-IP AEGIS cooldown: don't call AEGIS more than once per 2s per IP
        # (prevents 18 AEGIS calls/second storm from a single aggressive src_ip)
        self._AEGIS_last_ts: dict[str, float] = {}
        _AEGIS_COOLDOWN_S = 2.0   # seconds
        self._AEGIS_cooldown = _AEGIS_COOLDOWN_S

        self._logger.info(
            "✅ PredictiveCorrelationEngine REAL — KillchainGraph + IntentPredictor active"
        )

        # AEGIS_engine / forecast_gate injected via set_AEGIS() after construction.
        # This avoids importing system.core.engine (reverse dependency / circular import).
        self._AEGIS_engine = None
        self._forecast_gate = None

    def set_AEGIS(self, AEGIS_engine, forecast_gate=None) -> None:
        """
        Wire AEGISEngine and ForecastGate after construction.
        Called by engine.py._init_ml_components() so this file never needs
        to import system.core.engine.
        """
        self._AEGIS_engine = AEGIS_engine
        self._forecast_gate = forecast_gate
        self._logger.info("PredictiveCorrelationEngine: AEGISEngine wired via set_AEGIS()")

    def set_oracle(self, oracle_engine, forecast_gate=None) -> None:
        """Backward compatibility alias for set_AEGIS()."""
        return self.set_AEGIS(oracle_engine, forecast_gate)

    @property
    def _oracle_engine(self):
        return self._AEGIS_engine

    @_oracle_engine.setter
    def _oracle_engine(self, value):
        self._AEGIS_engine = value

    @property
    def oracle_engine(self):
        return self._AEGIS_engine

    @oracle_engine.setter
    def oracle_engine(self, value):
        self._AEGIS_engine = value

    @staticmethod
    def _normalize_event(event) -> tuple[str, str]:
        """Extract valid src_ip and map event to canonical Killchain stage."""
        if isinstance(event, dict):
            src_ip = event.get('src_ip') or event.get('client_ip') or event.get('source_ip') or event.get('ip') or ''
            action = str(event.get('action') or event.get('result') or '').upper()
            findings = event.get('findings') or []
            raw_text = " ".join(str(v) for v in [
                event.get('ml_label', ''),
                event.get('reason', ''),
                event.get('event_type', ''),
                event.get('category', ''),
                event.get('threat_class', ''),
                event.get('detector', ''),
                event.get('module', ''),
                event.get('signature_name', ''),
                event.get('rule_name', ''),
                event.get('event', ''),
                event.get('type', ''),
            ] if v).lower()
        else:
            src_ip = getattr(event, 'src_ip', getattr(event, 'client_ip', getattr(event, 'source_ip', getattr(event, 'ip', '')))) or ''
            action = str(getattr(event, 'action', getattr(event, 'result', ''))).upper()
            findings = getattr(event, 'findings', [])
            raw_text = " ".join(str(getattr(event, attr, '')) for attr in [
                'ml_label', 'reason', 'event_type', 'category', 'threat_class', 'detector', 'module', 'name', 'event', 'type'
            ] if hasattr(event, attr)).lower()

        src_ip = str(src_ip).strip()
        if not src_ip or src_ip.lower() in ('unknown', 'none', '127.0.0.1', '::1'):
            return ('', 'UNKNOWN')

        # 1. Ignore benign, informational, or health traffic
        if any(b in raw_text for b in [
            'vip match', 'vip reverse proxy completed', 'relay closed',
            'snapshot saved', 'healthy', 'healthcheck', 'unblocked',
            'options /api', 'get /api', 'post /api/v1/auth/login 200'
        ]):
            return ('', 'UNKNOWN')

        # 2. Ignore existing blocklist enforcement checks to avoid feedback loops
        if 'is blocked in ipblocklist' in raw_text or 'pipeline:blocklist' in raw_text:
            return ('', 'UNKNOWN')

        # 3. If action is pure ALLOW and no threat findings exist, ignore
        if action in ('ALLOW', 'PASS') and not findings:
            return ('', 'UNKNOWN')

        # 4. Precise mapping to Markov Killchain stages (Only real threats)
        if any(k in raw_text for k in ['sql', 'xss', 'csrf', 'traversal', 'file_inclusion', 'rce', 'command injection', 'ssrf', 'xxe']):
            return (src_ip, 'WAF_EXPLOIT')
        elif any(k in raw_text for k in ['port_scan', 'scan', 'nmap', 'syn_flood', 'recon', 'masscan']):
            return (src_ip, 'SCAN')
        elif any(k in raw_text for k in ['yara', 'malware', 'trojan', 'virus', 'dropper', 'pe_entropy', 'av_threat']):
            return (src_ip, 'MALWARE')
        elif any(k in raw_text for k in ['dga', 'dns_tunnel', 'dart_threat', 'botnet', 'beacon', 'beacondb', 'suspicious_tld', 'dns_sinkhole']):
            return (src_ip, 'DGA_C2')
        elif any(k in raw_text for k in ['dlp', 'exfil', 'leak', 'credit_card', 'iban', 'ssn_leak', 'secret_leak']):
            return (src_ip, 'DLP_EXFIL')
        elif any(k in raw_text for k in ['lateral', 'smb_exploit', 'psexec', 'rdp_jump', 'pass_the_hash']):
            return (src_ip, 'LATERAL_MOVEMENT')
        elif any(k in raw_text for k in ['privilege_escalation', 'sudo_exploit', 'auth_brute_force', 'credential_stuffing', 'brute']):
            return (src_ip, 'PRIVILEGE_ESCALATION')
        elif any(k in raw_text for k in ['ransom', 'encrypt', 'vssadmin', 'shadow_delete']):
            return (src_ip, 'RANSOMWARE')
        elif any(k in raw_text for k in ['persistence', 'backdoor', 'cron_persist', 'registry_persist']):
            return (src_ip, 'PERSISTENCE')
        else:
            return ('', 'UNKNOWN')

    def reset_ip(self, src_ip: str) -> None:
        """Reset all killchain history and AEGIS cooldown for a given IP."""
        if src_ip in self._ip_events:
            self._ip_events[src_ip].clear()
            del self._ip_events[src_ip]
        if src_ip in self._AEGIS_last_ts:
            del self._AEGIS_last_ts[src_ip]
        if hasattr(self.intent_predictor, '_intents') and src_ip in self.intent_predictor._intents:
            del self.intent_predictor._intents[src_ip]
        self._logger.info(f"PredictiveCorrelationEngine: Cleared killchain history for {src_ip}")

    def reset_all(self) -> None:
        """Reset all in-memory IP histories."""
        self._ip_events.clear()
        self._AEGIS_last_ts.clear()
        if hasattr(self.intent_predictor, '_intents'):
            self.intent_predictor._intents.clear()
        self._logger.info("PredictiveCorrelationEngine: Cleared all IP histories")

    async def process_event(self, event) -> None:
        """
        Process a security event through the full predictive pipeline.

        event can be a dict or an object with .src_ip, .event_type attributes.
        """
        try:
            src_ip, event_type = self._normalize_event(event)
            if not src_ip or event_type == 'UNKNOWN':
                return

            event_type = str(event_type).upper()


            # ── Layer 1: KillchainGraph transition update ──────────────
            ip_history = self._ip_events[src_ip]

            # Dedup: skip if the same event_type repeats consecutively.
            # e.g. VIP_REVERSE_PROXY_COMPLETED firing 70 times in a row
            # adds no new information but multiplies evaluate_ip_events cost.
            if ip_history and list(ip_history)[-1] == event_type:
                return

            if ip_history:
                self.killchain_graph.record_transition(
                    list(ip_history)[-1], event_type
                )
            ip_history.append(event_type)

            # Evaluate kill-chain path for this IP
            self.killchain_graph.evaluate_ip_events(src_ip, list(ip_history))

            # ── Layer 2: AEGIS v3 inference ───────────────────────────
            # Injected via set_AEGIS() — no import of system.core.engine needed
            AEGIS = self._AEGIS_engine

            if AEGIS:
                import time as _time
                _now = _time.monotonic()
                _last = self._AEGIS_last_ts.get(src_ip, 0.0)
                if _now - _last < self._AEGIS_cooldown:
                    # Same IP evaluated by AEGIS too recently — skip to prevent storm
                    self._logger.debug(
                        "[AEGIS] Cooldown skip: ip=%s (%.1fs since last eval)",
                        src_ip, _now - _last,
                    )
                    return
                self._AEGIS_last_ts[src_ip] = _now
                result = await asyncio.to_thread(AEGIS.process_event, src_ip=src_ip, event_type=event_type)

                # ── Layer 3: Update IntentPredictor state ──────────────
                if result.ttp_distribution:
                    top_ttp = result.ttp_distribution[0]
                    self.intent_predictor.update(
                        src_ip=src_ip,
                        current_stage=result.belief_state.most_likely_stage,
                        predicted_next=top_ttp.ttp,
                        confidence=top_ttp.probability,
                        action=result.counter_strategy.action,
                    )

                # ── Layer 4: Record RL safety decision ─────────────────
                if self._forecast_gate:
                    self._forecast_gate.safety.record_action(
                        src_ip=src_ip,
                        proposed=result.counter_strategy.action,
                        approved=result.counter_strategy.action,
                    )

                # ── Layer 5: Async DB writes ───────────────────────────
                await asyncio.to_thread(self._write_db_async, src_ip, event_type, result)

        except Exception as exc:
            self._logger.debug("PredictiveCorrelationEngine.process_event error: %s", exc)

    def _write_db_async(self, src_ip: str, event_type: str, result) -> None:
        """Write AEGIS decision and intent prediction to DB (non-blocking)."""
        try:
            from system.database.database import SessionLocal
            from modules.predictive_ai.models import (
                AttackIntentLog,
                AEGISDecisionLog,
                AEGISDecoyLog,
            )
            import json as _json
            from datetime import datetime

            db = SessionLocal()
            try:
                from system.database.database import Base
                import modules.predictive_ai.models
                try:
                    Base.metadata.create_all(bind=db.get_bind())
                except Exception:
                    pass

                # Write AEGISDecisionLog
                decoy_deployed = result.decoy_directive is not None
                decoy_details  = None
                if result.decoy_directive:
                    decoy_details = _json.dumps(result.decoy_directive.to_dict())

                decision_log = AEGISDecisionLog(
                    src_ip=src_ip,
                    event_type=event_type,
                    belief_state=_json.dumps(result.belief_state.to_dict()),
                    predicted_ttp_dist=_json.dumps([
                        {"ttp": p.ttp, "probability": round(p.probability, 4)}
                        for p in result.ttp_distribution[:5]
                    ]),
                    counter_strategy=result.counter_strategy.action,
                    action_explanation=result.counter_strategy.explanation,
                    decoy_deployed=decoy_deployed,
                    decoy_details=decoy_details,
                )
                db.add(decision_log)

                # Write AttackIntentLog
                if result.ttp_distribution:
                    top_ttp = result.ttp_distribution[0]
                    intent_log = AttackIntentLog(
                        src_ip=src_ip,
                        predicted_ttp=top_ttp.ttp,
                        confidence=top_ttp.probability,
                        action=result.counter_strategy.action,
                    )
                    db.add(intent_log)

                # Write AEGISDecoyLog if decoy deployed
                if result.decoy_directive:
                    asset = result.decoy_directive.decoy_asset
                    decoy_log = AEGISDecoyLog(
                        decoy_id=asset.asset_id,
                        src_ip=src_ip,
                        stage=asset.stage,
                        decoy_ip=asset.decoy_ip,
                        fake_service=asset.fake_service,
                        fake_port=asset.fake_port,
                        interaction_count=asset.interaction_count,
                        is_expired=asset.is_expired,
                    )
                    db.add(decoy_log)

                db.commit()
            except Exception as _db_err:
                db.rollback()
                self._logger.debug("DB write error in PredictiveCorrelationEngine: %s", _db_err)
            finally:
                db.close()
        except Exception as _outer:
            self._logger.debug("DB session error in PredictiveCorrelationEngine: %s", _outer)
