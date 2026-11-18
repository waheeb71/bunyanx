"""
Enterprise bunyanx — UBA Inspector Plugin

Bridges the bunyanx inspection pipeline to the UBA behavioral engine.
Extracts user identity from the InspectionContext (via IdentityCorrelationEngine)
and calls the UserProfiler to analyze behavior in real time.

Key design decisions:
- Plugin runs on TCP traffic only (port selection configurable via UBAConfig)
- User identity is resolved from context.identity (populated by ContextBuilder via ICE)
  Sources: LDAP/AD sync, RADIUS Accounting, VPN events, Captive Portal
- AD groups → peer_group (automatic, no manual metadata needed)
- AD department → used for anomaly context
- Result is "ALLOW" normally; "BLOCK" only in enforce+critical mode
"""

from __future__ import annotations

import logging
import time
import asyncio
from typing import Dict, Any, Optional

from system.events.bus import EventBus
from system.events.topics import Topics

from system.core.framework.plugin_base import (
    InspectorPlugin, InspectionContext, InspectionResult,
    InspectionFinding, InspectionAction, PluginPriority,
)
from modules.uba.engine.core.user_profiler import UserProfiler
from modules.uba.engine.core.active_perturbation import MicroFaultInjector

logger = logging.getLogger(__name__)


class UBAPlugin(InspectorPlugin):
    """
    Real-time User Behavior Analytics plugin.

    Registers as priority LOWEST so it runs after all other inspectors
    (it only contributes an additional behavioral risk signal, not a
    hard firewall rule — unless mode='enforce').
    """

    PLUGIN_NAME = "uba"

    def __init__(
        self,
        db_manager=None,
        config=None,         # UBAConfig DB row
        logger: Optional[logging.Logger] = None,
    ):
        super().__init__(
            name=self.PLUGIN_NAME,
            priority=PluginPriority.LOWEST,
            logger=logger or logging.getLogger(__name__),
        )
        if db_manager and config is None:
            try:
                from modules.uba.api.router import _get_or_create_uba_config
                config = _get_or_create_uba_config(db_manager)
            except Exception as exc:
                self.logger.warning("Failed to load UBA config from DB: %s", exc)

        self.profiler = UserProfiler(db_manager=db_manager, config=config)
        self.config = config
        self._mode = getattr(config, 'mode', 'monitor') if config else 'monitor'
        
        # AP-GDR: Active Perturbation Engine
        self.fault_injector = MicroFaultInjector()

        # AP-GDR: Labyrinth Engine
        from modules.uba.engine.core.uba_deception import GenerativeLabyrinthEngine
        self.labyrinth_engine = GenerativeLabyrinthEngine()
        self._last_labyrinth_prune = 0.0

    def _is_deception_enabled(self) -> bool:
        cfg = getattr(self.profiler, 'cfg', self.config)
        if cfg is None:
            return True
        if isinstance(cfg, dict):
            return cfg.get('deception_enabled', True)
        return getattr(cfg, 'deception_enabled', True)

    def can_inspect(self, context: InspectionContext) -> bool:
        """
        Inspect any TCP/UDP/HTTP/SMTP traffic.
        If username is not resolved from ICE/AD, defaults to anon_<src_ip> to ensure
        honeytokens, IDOR, and IP-level behavioral anomaly profiling still run.
        """
        return (context.protocol or "").upper() in ("TCP", "UDP", "HTTP", "HTTPS", "SMTP")

    def inspect(
        self,
        context: InspectionContext,
        data: bytes = b"",
    ) -> InspectionResult:
        """Run UBA pipeline and return InspectionResult."""
        start = time.time()
        result = InspectionResult(action=InspectionAction.ALLOW)

        # ── Resolve username ────────────────────────────────────────────────
        # Priority: context.identity (ICE: LDAP/RADIUS/VPN) → metadata → anon_<src_ip>
        if context.identity and context.identity.user_id:
            username = context.identity.user_id
        else:
            username = (context.metadata or {}).get("username", "") or f"anon_{context.src_ip}"

        # ── Enrich from IdentityCache (groups, department) ──────────────────
        # Pull real AD groups/department for peer_group and context.
        # This is O(1) — cache lookup, no network call.
        user_groups:    list = []
        user_department: str = ""
        try:
            from system.auth.identity_cache import get_identity_cache
            entry = get_identity_cache().get(context.src_ip)
            if entry:
                user_groups     = entry.groups
                user_department = entry.department
        except Exception:
            pass

        # ── Derive peer_group from identity ─────────────────────────────────
        # Priority:
        #   1. context.metadata["peer_group"]  (explicit, e.g. Captive Portal)
        #   2. AD department (e.g. "Finance", "IT")
        #   3. First matching AD group
        #   4. empty string (peer comparison skipped)
        meta         = context.metadata or {}
        peer_group   = (
            meta.get("peer_group")
            or user_department
            or (user_groups[0] if user_groups else "")
        )
        bytes_xfer   = float(meta.get("bytes_transferred", len(data)))
        session_dur  = float(meta.get("session_duration", 0.0))

        if not username:
            return result

        # Prune expired Labyrinth sessions periodically
        now = time.time()
        if now - self._last_labyrinth_prune > 30.0:
            self._last_labyrinth_prune = now
            self.labyrinth_engine.prune_sessions(ttl_seconds=3600.0)
            
        # AP-GDR Step 1: Check if this flow had an active perturbation injected recently.
        # If so, measure the user's reaction delay to see if they are a script (0ms) or human (>300ms).
        #
        # SSL-Aware: عند HTTPS+MITM وقت إعادة بناء الـ Proxy يُضاف لوقت الرد
        # فيُشوّه مقياس "تأخير 0ms = سكريبت" → false positive.
        # نيتخطى قياس التفاعل بالكامل للحركة المفكوكة.
        if context.is_ssl_inspected:
            perturb_reaction = None
            self.logger.debug(
                "[UBA][SSL-Aware] Skipping fault_injector timing (MITM proxy latency unreliable) for %s",
                context.src_ip,
            )
        else:
            perturb_reaction = self.fault_injector.measure_reaction(context.flow_id, context.timestamp)
        bot_prob_boost = 0.0
        if perturb_reaction:
            bot_prob_boost = perturb_reaction.bot_probability * 0.35 # Max boost of 35% if 100% sure it's a bot
            self.logger.warning(
                "[AP-Engine] Perturbation evaluated! Bot certainty: %.2f",
                perturb_reaction.bot_probability,
            )

        try:
            analysis = self.profiler.analyze(
                username=username,
                source_ip=context.src_ip,
                target_service=f"{context.protocol}:{context.dst_port}",
                bytes_transferred=bytes_xfer,
                session_duration=session_dur,
                event_time=context.timestamp,
                peer_group=peer_group,
                groups=user_groups,
                department=user_department,
            )
            
            # Check for Honeytoken and IDOR probing in HTTP context
            url_path = ""
            if context.http:
                url_path = f"{context.http.url or ''} {context.http.path or ''} {context.http.query or ''}".lower()
            if context.metadata:
                url_path += " " + str(context.metadata.get("url") or context.metadata.get("path") or "").lower()

            if url_path:
                if "honeytoken" in url_path or "db_credentials" in url_path:
                    analysis.detectors_triggered.append("Honeytoken_Access_Triggered")
                    analysis.risk_level = "critical"
                    analysis.risk_score = 100.0
                    analysis.anomaly_score = 1.0
                    analysis.action = "block"
                elif "account_id=" in url_path or "account/details" in url_path:
                    # IDOR probing check
                    analysis.detectors_triggered.append("IDOR_Unauthorized_Access")
                    analysis.risk_level = "critical"
                    analysis.risk_score = 90.0
                    analysis.anomaly_score = 0.9
                    analysis.action = "block"

            # Apply cognitive load / bot probability boost
            if bot_prob_boost > 0:
                analysis.anomaly_score = min(1.0, analysis.anomaly_score + bot_prob_boost)
                analysis.risk_score = min(100.0, analysis.risk_score + (bot_prob_boost * 100))
                if "Active_Perturbation_Failed" not in analysis.detectors_triggered:
                    analysis.detectors_triggered.append("Active_Perturbation_Failed")

            # Populate findings if anomalies detected
            if analysis.detectors_triggered:
                for flag in analysis.detectors_triggered:
                    severity = self._flag_severity(analysis.risk_level)
                    result.findings.append(InspectionFinding(
                        plugin_name=self.name,
                        severity=severity,
                        category="UBA",
                        description=flag,
                        confidence=analysis.anomaly_score,
                        recommends_block=(analysis.action == "block"),
                        metadata={
                            "risk_level":  analysis.risk_level,
                            "risk_score":  analysis.risk_score,
                            "username":    username,
                        },
                    ))

            # AP-GDR Step 2 & 3: Take action based on mode + risk
            if analysis.action == "block" or analysis.risk_level == "critical":
                # Concept 2 (EGDR): Instead of dropping the connection, redirect mid-session 
                # to the Generative Decoy labyrinth if deception is active.
                if self._is_deception_enabled():
                    result.action = InspectionAction.REDIRECT_DECOY
                    result.metadata["decoy_reason"] = "Critical risk reached, transitioning to Labyrinth."
                else:
                    result.action = InspectionAction.BLOCK
                    
            elif analysis.action == "alert" and analysis.risk_level in ("high", "critical"):
                result.action = InspectionAction.LOG_ONLY
                
            elif analysis.risk_level == "medium" and self._is_deception_enabled():
                # Concept 1 (AP): Before we are certain, let's "poke" the attacker.
                # SSL-Aware: عند HTTPS+MITM الطلب الأولى لكل مستخدم تبدو "غريبة" لل**UBA
                # لأنه لم يتدرب بعد على أنماط HTTPS headers لهذا المستخدم.
                # نتحول إلى ALERT فقط (مراقبة) بدلاً من PERTURB (اختبار المستخدم) لمنع false positives.
                if context.is_ssl_inspected:
                    result.action = InspectionAction.LOG_ONLY
                    self.logger.debug(
                        "[UBA][SSL-Aware] Suppressed PERTURB → LOG_ONLY for MITM medium-risk: %s",
                        context.src_ip,
                    )
                else:
                    fault_type = self.fault_injector.evaluate_risk_for_perturbation(analysis.risk_score)
                    if fault_type != "NONE":
                        self.fault_injector.mark_flow_for_fault(context.flow_id, fault_type)
                        result.action = InspectionAction.PERTURB
                        result.metadata["perturbation_type"] = fault_type

            result.metadata["uba"] = {
                "username":      username,
                "risk_score":    analysis.risk_score,
                "risk_level":    analysis.risk_level,
                "anomaly_score": analysis.anomaly_score,
                "peer_group":    peer_group,
                "department":    user_department,
                "groups":        user_groups,
            }

            if analysis.detectors_triggered:
                try:
                    EventBus.publish_from_thread(Topics.ANOMALY_SCORED, result.metadata["uba"])
                except Exception as e:
                    self.logger.debug("Failed to dispatch UBA event: %s", e)

        except Exception as exc:
            self.logger.error("UBAPlugin inspection error: %s", exc, exc_info=True)

        result.processing_time_ms = (time.time() - start) * 1000
        return result

    @staticmethod
    def _flag_severity(risk_level: str) -> str:
        return {
            "critical": "CRITICAL",
            "high":     "HIGH",
            "medium":   "MEDIUM",
            "low":      "INFO",
        }.get(risk_level, "INFO")
