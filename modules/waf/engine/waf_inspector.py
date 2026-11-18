"""
Enterprise bunyanx — AI-Powered Web Application Firewall (WAF) Inspector

Settings are loaded from:  config/defaults/waf.yaml
Local overrides from:      config/waf.local.yaml  (not committed to git)

Architecture (10-Layer AI-WAF):

  HTTP Request
       │
  0. Settings Check         — master WAF on/off switch first
       │
  1. Honeypot Check         — instant blacklist on probe of /admin_backup, /.env …
       │
  2. WAF Preprocessor       — multi-layer decode (URL+B64+Hex+HTML+Unicode+SQL comments)
       │
  3. Feature Extractor      — 10 HTTP-level numerical features
       │
  4. AI Models Layer
       ├── NLP Model         — 1D-CNN+BiLSTM payload classifier
       ├── Bot Detector      — XGBoost behavioral bot classifier
       ├── Anomaly Detector  — heuristic + ml/inference/anomaly_detector
       └── Threat Intel      — AbuseIPDB / Spamhaus / OTX / Feodo
       │
  5. Risk Scoring Engine    — weighted ensemble → score [0.0, 1.0]
       │
  6. Policy Decision        — ALLOW / CHALLENGE / SOFT_BLOCK / BLOCK
       │
  Self-Learning Logger      — stores payload + label for weekly retraining

Integration points with existing system:
  - InspectorPlugin base class (inspection/framework/plugin_base.py)
  - InspectionContext, InspectionResult, InspectionFinding, InspectionAction
  - ml/inference/anomaly_detector.py  (reused as-is)
  - modules.ids_ips.engine.core.threat_intel (new — pluggable, optional)
"""

import logging
import time
import warnings
from typing import List, Optional, TYPE_CHECKING

# Suppress PyTorch framework-level warnings that are not actionable:
#   1. TypedStorage deprecation (PyTorch ≥ 2.0 internal change)
#   2. Slow numpy list-of-ndarrays tensor creation (replaced by torch.from_numpy above)
warnings.filterwarnings("ignore", category=UserWarning, message=".*TypedStorage is deprecated.*")
warnings.filterwarnings("ignore", category=UserWarning, message=".*Creating a tensor from a list of numpy.*")


from system.core.framework.plugin_base import (
    InspectorPlugin, InspectionContext, InspectionFinding,
    InspectionResult, InspectionAction, PluginPriority,
)
from modules.waf.engine.core.analysis.preprocessor      import WAFPreprocessor
from modules.waf.engine.core.analysis.feature_extractor import WafFeatureExtractor
from modules.waf.engine.core.defenses.honeypot          import HoneypotGuard
from modules.waf.engine.core.decision.risk_engine       import RiskScoringEngine, PolicyDecision
from modules.waf.engine.core.settings          import WAFSettings, get_waf_settings

# New WAAP Modules
from modules.waf.engine.core.defenses.api_schema_validator import APISchemaValidator
from modules.waf.engine.core.defenses.fingerprinting       import AdvancedFingerprinting
from modules.waf.engine.core.defenses.ato_protector        import ATOProtector
from modules.waf.engine.core.defenses.rate_limiter         import AdaptiveRateLimiter
from modules.waf.engine.core.advanced.shadow_autopilot     import ShadowAutopilot
from modules.waf.engine.core.decision.self_learning_logger  import WAFSelfLearningLogger
from modules.waf.engine.core.advanced.deception_engine      import DeceptionEngine
from modules.waf.engine.core.defenses.graphql_inspector     import GraphQLInspector

if TYPE_CHECKING:
    from modules.ids_ips.engine.core.threat_intel import ThreatIntelCache
    from modules.waf.ml_training.waf_nlp.model  import WAFNLPInference
    from modules.waf.ml_training.bot_detection.model import BotDetectionModel
    from modules.waf.ml_training.waf_gnn.model  import WAFGNNInference
    from modules.waf.ml_training.semantic_intent.model import SemanticIntentInspector
    from modules.waf.ml_training.waf_gnn.model import TemporalSessionTracker

import asyncio
from system.events.bus import EventBus
from system.events.topics import Topics

# ── Module-level singletons (used by API router for live reload) ──
_gnn_log_collector    = None   # type: Optional['SessionLogCollector']
_live_gnn_model       = None   # type: Optional['WAFGNNInference']
_live_temporal_tracker = None  # type: Optional['TemporalBiLSTMTracker']
_live_shadow_autopilot = None  # type: Optional['ShadowAutopilot']


logger = logging.getLogger(__name__)

try:
    import torch
    # Limit PyTorch CPU threads to 1 to prevent thread blocking & event loop starvation
    torch.set_num_threads(1)
    logger.info("WAF CPU Optimization: PyTorch set_num_threads(1) successfully configured")
except ImportError:
    logger.warning("WAF CPU Optimization: PyTorch not found. Skipping thread configuration.")


# ──────────────────────────────────────────────
#  WAFInspectorPlugin
# ──────────────────────────────────────────────

class WAFInspectorPlugin(InspectorPlugin):
    """
    AI-Powered WAF Inspector Plugin.

    Reads all settings from config/defaults/waf.yaml (via WAFSettings).
    Each feature can be individually toggled without code changes.

    Args:
        settings:       WAFSettings instance (loads from YAML if None)
        nlp_model:      Optional WAFNLPInference instance
        bot_model:      Optional BotDetectionModel instance
        gnn_model:      Optional WAFGNNInference instance
        threat_intel:   Optional ThreatIntelCache instance
        priority:       Plugin execution priority
    """

    def __init__(
        self,
        settings:         Optional[WAFSettings]          = None,
        nlp_model:        Optional['WAFNLPInference']    = None,
        bot_model:        Optional['BotDetectionModel']  = None,
        gnn_model:        Optional['WAFGNNInference']    = None,
        threat_intel:     Optional['ThreatIntelCache']   = None,
        gaf_model:        Optional['SemanticIntentInspector'] = None,
        temporal_tracker: Optional['TemporalSessionTracker']  = None,
        priority:         PluginPriority = PluginPriority.HIGH,
    ):
        super().__init__(name="waf_ai_inspector", priority=priority)

        # ── Load settings ───────────────────────
        self.cfg = settings or get_waf_settings()

        # ── Sub-components (built from settings) ─
        self.preprocessor = WAFPreprocessor(
            max_iterations=self.cfg.preprocessing.max_iterations
        )
        self.feature_ext  = WafFeatureExtractor()
        self.honeypot     = HoneypotGuard(
            score_boost           = self.cfg.honeypot.score_boost,
            blacklist_ttl_seconds = self.cfg.honeypot.blacklist_ttl_seconds,
            # tarpit_enabled=True # default
        )
        
        # ── WAAP Modules ────────────────────────
        self.api_validator = APISchemaValidator(
            max_payload_size=self.cfg.api_schema.max_payload_size
        )
        self.fingerprint_engine = AdvancedFingerprinting(
            check_ja3=self.cfg.fingerprint.check_ja3,
            check_headers=self.cfg.fingerprint.check_headers
        )
        self.ato_protector = ATOProtector(
            login_endpoints=["/login", "/api/auth/login", "/auth/token", "/api/login_api"],
            max_attempts_per_ip=self.cfg.ato_protector.max_attempts_per_ip,
            max_attempts_per_user=self.cfg.ato_protector.max_attempts_per_user,
            time_window_seconds=self.cfg.ato_protector.time_window_seconds
        )
        self.rate_limiter = AdaptiveRateLimiter(
            global_rate_limit=self.cfg.rate_limiter.global_rate_limit,
            ip_rate_limit=self.cfg.rate_limiter.ip_rate_limit,
            user_rate_limit=self.cfg.rate_limiter.user_rate_limit,
            time_window_seconds=self.cfg.rate_limiter.time_window_seconds
        )
        self.graphql_inspector = GraphQLInspector(
            max_depth=self.cfg.graphql_inspector.max_depth,
            max_batched_queries=self.cfg.graphql_inspector.max_batched_queries,
            detect_introspection=self.cfg.graphql_inspector.detect_introspection
        )
        rs = self.cfg.risk_scoring.thresholds
        self.risk_engine = RiskScoringEngine(
            w_nlp        = self.cfg.nlp.weight,
            w_anomaly    = self.cfg.anomaly.weight,
            w_bot        = self.cfg.bot.weight,
            w_reputation = self.cfg.threat_intel.weight,
            w_gaf        = self.cfg.gaf.weight,
            w_temporal   = self.cfg.temporal.weight,
            w_honeypot   = self.cfg.honeypot.weight,
            threshold_allow      = rs.allow,
            threshold_challenge  = rs.challenge,
            threshold_soft_block = rs.soft_block,
            dynamic_amplifiers   = getattr(self.cfg, 'dynamic_amplifiers', None)
        )

        # ── Optional AI models ──────────────────
        self.nlp_model    = nlp_model
        if self.nlp_model is None and self.cfg.nlp.enabled:
            from modules.waf.ml_training.waf_nlp.model import WAFNLPInference
            self.nlp_model = WAFNLPInference(model_path=self.cfg.nlp.model_path)

        self.bot_model    = bot_model
        if self.bot_model is None and self.cfg.bot.enabled:
            from modules.waf.ml_training.bot_detection.model import BotDetectionModel
            self.bot_model = BotDetectionModel(model_path=self.cfg.bot.model_path)

        self.gnn_model    = gnn_model
        if self.gnn_model is None and self.cfg.gnn.enabled:
            from modules.waf.ml_training.waf_gnn.model import WAFGNNInference
            self.gnn_model = WAFGNNInference(model_path=self.cfg.gnn.model_path)

        self.threat_intel = threat_intel

        self.gaf_model = gaf_model
        if self.gaf_model is None and self.cfg.gaf.enabled:
            from modules.waf.ml_training.semantic_intent.model import SemanticIntentInspector
            self.gaf_model = SemanticIntentInspector(model_path=self.cfg.gaf.model_path)

        self.temporal_tracker = temporal_tracker
        if self.temporal_tracker is None and self.cfg.temporal.enabled:
            from modules.waf.ml_training.waf_gnn.model import TemporalSessionTracker
            self.temporal_tracker = TemporalSessionTracker(model_path=self.cfg.temporal.model_path)

        logger.info(
            "WAFInspectorPlugin initialized | enabled=%s | mode=%s",
            self.cfg.enabled, self.cfg.mode
        )
        logger.info(self.cfg.summary())
        self._challenged_count = 0

        # ─ Self-Learning Logger ─ (disabled by default, controlled by waf.yaml) ─
        self.self_logger: Optional[WAFSelfLearningLogger] = None
        if self.cfg.self_learning.enabled:
            try:
                from system.database.database import SessionLocal
                self.self_logger = WAFSelfLearningLogger(
                    settings=self.cfg.self_learning,
                    db_session_factory=SessionLocal,
                )
                logger.info("WAF Self-Learning Logger activated (max_records=%d)",
                            self.cfg.self_learning.max_records)
            except Exception as e:
                logger.warning("WAF Self-Learning Logger init failed: %s", e)

        # ── Deception Engine (Patent PoC) ──
        self.deception_engine: Optional[DeceptionEngine] = None
        if getattr(self.cfg, 'deception_engine', None) and self.cfg.deception_engine.enabled:
            self.deception_engine = DeceptionEngine(self.cfg.deception_engine)


        # ── Session Log Collector (for GNN training data) ─
        global _gnn_log_collector
        if self.cfg.gnn.log_sessions:
            try:
                from modules.waf.engine.core.analysis.session_log_collector import SessionLogCollector
                _gnn_log_collector = SessionLogCollector(
                    output_path  = self.cfg.gnn.logs_path,
                    max_records  = self.cfg.gnn.max_log_records,
                )
                logger.info("GNN session log collector active → %s", self.cfg.gnn.logs_path)
            except Exception as e:
                logger.warning("Could not initialize GNN session log collector: %s", e)

        # ── Make live models accessible to API router ──────
        global _live_gnn_model, _live_temporal_tracker
        if self.gnn_model:
            _live_gnn_model = self.gnn_model
        if self.temporal_tracker:
            _live_temporal_tracker = self.temporal_tracker
            
        # ── Shadow Autopilot Initialization ────────────────
        global _live_shadow_autopilot
        self.autopilot = ShadowAutopilot(
            observation_window_hours=self.cfg.shadow_mode.observation_window_hours
        )
        _live_shadow_autopilot = self.autopilot
        
        # If enabled via settings, forcefully resume learning
        if self.cfg.shadow_mode.enabled:
            self.autopilot.start_learning(hours=self.cfg.shadow_mode.observation_window_hours)

        # Warm up ALL PyTorch models synchronously during init to prevent cold-start latency.
        _warmup_errors = []
        for _name, _obj in [
            ("nlp", self.nlp_model),
            ("gaf", self.gaf_model),
            ("gnn", self.gnn_model),
            ("bot", self.bot_model),
        ]:
            if _obj is None:
                continue
            try:
                if _name == "gnn" and hasattr(_obj, "predict"):
                    _obj.predict("warmup_session", {})
                elif _name == "bot" and hasattr(_obj, "predict"):
                    _obj.predict({})
                elif hasattr(_obj, "predict"):
                    _obj.predict("warmup")
                elif hasattr(_obj, "score"):
                    _obj.score("warmup", {})
            except Exception as _we:
                _warmup_errors.append(f"{_name}: {_we}")
        if _warmup_errors:
            logger.warning("WAF model warm-up partial failures: %s", _warmup_errors)
        else:
            logger.info("WAF PyTorch models (nlp+gaf+gnn+bot) warmed up synchronously during init.")

    # ── InspectorPlugin interface ───────────────

    def can_inspect(self, context: InspectionContext) -> bool:
        """Target HTTP/HTTPS traffic on configured ports."""
        # 🔴 Master switch — if WAF is disabled, skip all inspection
        if not self.cfg.enabled:
            return False
        ports = set(self.cfg.monitored_ports)
        return context.dst_port in ports or context.src_port in ports

    async def initialize(self) -> None:
        logger.info("WAFInspectorPlugin ready | mode=%s", self.cfg.mode)
        # ── Capture the running event loop for cross-thread EventBus publishing ──
        # _dispatch_event() runs inside asyncio.to_thread() (a worker thread),
        # so it cannot call asyncio.get_running_loop(). We store the loop here
        # (in an async context) and use run_coroutine_threadsafe() later.
        try:
            self._main_loop = asyncio.get_running_loop()
            logger.debug("[WAF] Main event loop captured for EventBus dispatch.")
        except RuntimeError:
            self._main_loop = None
            logger.warning("[WAF] Could not capture event loop — EventBus dispatch may be unavailable.")
        # Re-warm after async initialize() (loop is now running — ensures
        # device allocations are visible to the async inference path too).
        _warmup_errors = []
        for _name, _obj in [
            ("nlp", self.nlp_model),
            ("gaf", self.gaf_model),
            ("gnn", self.gnn_model),
            ("bot", self.bot_model),
        ]:
            if _obj is None:
                continue
            try:
                if _name == "gnn" and hasattr(_obj, "predict"):
                    _obj.predict("warmup_session", {})
                elif _name == "bot" and hasattr(_obj, "predict"):
                    _obj.predict({})
                elif hasattr(_obj, "predict"):
                    _obj.predict("warmup")
                elif hasattr(_obj, "score"):
                    _obj.score("warmup", {})
            except Exception as _we:
                _warmup_errors.append(f"{_name}: {_we}")
        if _warmup_errors:
            logger.warning("WAF model re-warm partial failures: %s", _warmup_errors)
        else:
            logger.info("WAF PyTorch models (nlp+gaf+gnn+bot) re-warmed after async init.")

    async def shutdown(self) -> None:
        logger.info("WAFInspectorPlugin shutdown")

    def on_threat_detected(self, event_data: dict) -> None:
        """
        Event callback for 'threat.detected' topic.
        Registers temporary dynamic blocks via IPBlocklistManager for high-confidence threats.
        """
        if not isinstance(event_data, dict):
            return
        ip = event_data.get("src_ip") or event_data.get("ip") or event_data.get("source_ip")
        if not ip:
            return
        # Do not dynamically block whitelisted IPs
        if self.cfg.is_ip_whitelisted(ip):
            return

        # Check confidence threshold to prevent false-positive auto-blocking
        confidence = float(event_data.get("confidence", 1.0))
        if confidence < 0.75:
            logger.debug("WAF skipping threat event for %s (low confidence: %.2f)", ip, confidence)
            return

        try:
            from modules.firewall.engine.ip_blocklist import get_blocklist_manager
            reason = event_data.get("description") or event_data.get("reason") or "WAF dynamic threat detection"
            get_blocklist_manager().block_ip_sync(
                ip=str(ip),
                reason=f"[waf_threat] {reason}",
                blocked_by="waf_inspector",
                duration_seconds=10 * 60,  # 10 minute temporary block
            )
            logger.info("WAF delegated dynamic block for high-confidence threat IP: %s (conf=%.2f)", ip, confidence)
        except Exception as exc:
            logger.warning("WAF failed to delegate block for %s: %s", ip, exc)

    def _dispatch_event(
        self,
        context: InspectionContext,
        request_path: str,
        result: InspectionResult,
        risk_score: float = 1.0,
        elapsed_ms: float = 0.0
    ) -> None:
        """Broadcast WAF block events to UI dashboard and EventBus for audio alerts."""
        action = result.action
        findings = result.findings or []

        # Update plugin statistics
        self._inspected_count += 1
        if findings:
            self._detected_count += 1
        if action == InspectionAction.BLOCK:
            self._blocked_count += 1
        elif action == InspectionAction.QUARANTINE:
            self._challenged_count = getattr(self, "_challenged_count", 0) + 1

        # ── Record session for GNN training data ──────────
        if _gnn_log_collector is not None:
            try:
                _gnn_log_collector.record(
                    src_ip        = context.src_ip,
                    path          = request_path,
                    method        = context.metadata.get("request_method", "GET"),
                    response_code = 403 if action == InspectionAction.BLOCK else 200,
                    session_id    = context.metadata.get("session_id", context.src_ip),
                    latency_ms    = elapsed_ms,
                    payload_bytes = 0,
                )
            except Exception:
                pass

        # ── Broadcast to Live Monitoring Dashboard + EventBus ────────
        # _dispatch_event() runs inside asyncio.to_thread() so we MUST use
        # EventBus.publish_from_thread() instead of await bus.publish().
        if action != InspectionAction.ALLOW or risk_score > self.cfg.logging.alert_threshold:
            try:
                primary_cat = (findings[0].category.lower() if findings and hasattr(findings[0], 'category') else "")
                primary_desc = (findings[0].description.lower() if findings and hasattr(findings[0], 'description') else "")

                threat_type = "waf"
                if "sqli" in primary_cat or "sql" in primary_cat or "sql" in primary_desc or "union" in primary_desc or "1=1" in primary_desc:
                    threat_type = "sqli"
                elif "rce" in primary_cat or "command" in primary_cat or "command" in primary_desc or "cat " in primary_desc or "semicolon" in primary_desc or "whoami" in primary_desc:
                    threat_type = "rce"
                elif "xss" in primary_cat or "script" in primary_cat or "<script>" in primary_desc:
                    threat_type = "xss"
                elif "traversal" in primary_cat or "path" in primary_cat or "etc/passwd" in primary_desc or ".." in primary_desc:
                    threat_type = "path_traversal"
                elif "bot" in primary_cat or "bot" in primary_desc:
                    threat_type = "abusive_bot"

                payload = {
                    "timestamp":       time.time(),
                    "src_ip":          context.src_ip,
                    "dst_ip":          context.dst_ip,
                    "path":            request_path,
                    "action":          action.name,
                    "risk_score":      round(risk_score, 2),
                    "latency_ms":      round(elapsed_ms, 2),
                    "threat_type":     threat_type,
                    "category":        primary_cat or "waf",
                    "triggers":        [f.category for f in findings],
                    "severity":        "HIGH" if action == InspectionAction.BLOCK else "MEDIUM",
                    "description":     (
                        findings[0].description if findings
                        else "Request blocked by WAF policy."
                    ),
                    "xai_explanation": (
                        findings[0].description if findings
                        else "Request blocked by deterministic policy."
                    ),
                }

                # ── Live dashboard (needs running loop) ───────────────────────
                main_loop = getattr(self, "_main_loop", None) or EventBus._main_loop
                if main_loop and main_loop.is_running():
                    import asyncio as _aio
                    from modules.waf.api.live_monitor import waf_dispatcher
                    _aio.run_coroutine_threadsafe(
                        waf_dispatcher.broadcast(payload), main_loop
                    )

                # ── EventBus → AudioManager → NativePlayer ────────────────────
                topic = (
                    Topics.WAF_BLOCK
                    if action == InspectionAction.BLOCK
                    else Topics.WAF_ALERT
                )
                EventBus.publish_from_thread(topic, payload)
                logger.debug(
                    "[WAF] EventBus published: %s | %s | score=%.2f",
                    topic, context.src_ip, risk_score,
                )

            except Exception as e:
                logger.debug("Failed to dispatch WAF event: %s", e)


    def inspect(self, context: InspectionContext, data: bytes = b"") -> InspectionResult:
        """
        Full AI-WAF inspection pipeline.

        Returns InspectionResult with:
          - action         (ALLOW / BLOCK / QUARANTINE)
          - findings       (list of InspectionFinding)
          - metadata       (risk_score, risk_breakdown, waf_features, …)
        """
        t_start = time.time()

        # ── Phase 10: Typed field adapter ────────────────────────────────────────
        # Prefer context.http typed fields (populated by ContextBuilder after
        # TLS decryption). Fall back to legacy metadata dict for old call sites.
        # data param falls back to context.http.body when b"" (Phase 10 default).
        _http = context.http
        if _http is not None:
            request_url    = _http.url or context.metadata.get("request_url", "")
            request_path   = _http.path or "/"
            request_query  = _http.query or ""
            request_method = _http.method or "GET"
            if not data:
                data = _http.body  # use body from context when not passed separately
        else:
            # Legacy path: metadata dict (kept for backward compat)
            request_url  = (
                context.metadata.get("request_url")
                or context.metadata.get("url", "")
            )
            request_path = (
                context.metadata.get("request_path")
                or context.metadata.get("path", "/")
            )
            request_query  = context.metadata.get("query_string", "")
            request_method = context.metadata.get("method") or context.metadata.get("request_method", "GET")

        # ── 🔴 MASTER SWITCH ─────────────────────────────────────────
        # Double-check here in case can_inspect was bypassed
        if not self.cfg.enabled:
            return InspectionResult(action=InspectionAction.ALLOW,
                                    metadata={"waf": "disabled"})

        # ── WHITELIST CHECK ──────────────────────────────────────────
        if self.cfg.is_ip_whitelisted(context.src_ip) or self.cfg.is_path_whitelisted(request_path):
            return InspectionResult(action=InspectionAction.ALLOW,
                                    metadata={"waf": "whitelisted"})

        # ── STATIC BLACKLIST CHECK ───────────────────────────────────
        if self.cfg.is_ip_blacklisted(context.src_ip):
            res = InspectionResult(
                action=InspectionAction.BLOCK,
                findings=[InspectionFinding(
                    plugin_name="waf_blacklist",
                    severity="HIGH",
                    category="Blacklist",
                    description=f"{context.src_ip} is statically blacklisted",
                    confidence=1.0,
                    recommends_block=True,
                )],
                metadata={"waf": "blacklisted"},
            )
            self._dispatch_event(context, request_path, res, risk_score=1.0, elapsed_ms=(time.time() - t_start)*1000)
            return res


        # Outbound traffic is skipped (WAF protects inbound server applications)
        if context.direction == "outbound" and not context.metadata.get("inspect_outbound_waf", False):
            return InspectionResult(action=InspectionAction.ALLOW, metadata={"waf": "outbound_allowed"})

        # Truncate oversized payloads
        max_bytes = self.cfg.performance.max_payload_inspect_bytes
        if len(data) > max_bytes:
            data = data[:max_bytes]

        findings: List[InspectionFinding] = []

        def check_timeout() -> Optional[InspectionResult]:
            elapsed = (time.time() - t_start) * 1000
            if elapsed > self.cfg.performance.max_inspection_time_ms:
                if self.cfg.performance.fail_open:
                    logger.warning(
                        "WAF inspection timed out after %.2fms (limit: %dms) under fail-open policy. Request allowed.",
                        elapsed, self.cfg.performance.max_inspection_time_ms
                    )
                    self._inspected_count += 1
                    self._detected_count += 1
                    return InspectionResult(
                        action=InspectionAction.ALLOW,
                        findings=[InspectionFinding(
                            plugin_name="waf_timeout",
                            severity="LOW",
                            category="Timeout",
                            description=f"WAF inspection timed out after {elapsed:.2f}ms (limit: {self.cfg.performance.max_inspection_time_ms}ms) under fail-open policy",
                            confidence=0.5,
                            recommends_block=False
                        )],
                        processing_time_ms=elapsed,
                        metadata={
                            "waf": "timeout_fail_open",
                            "latency_ms": round(elapsed, 2),
                        }
                    )
                else:
                    logger.error(
                        "WAF inspection timed out after %.2fms (limit: %dms) under fail-closed policy. Request blocked.",
                        elapsed, self.cfg.performance.max_inspection_time_ms
                    )
                    self._inspected_count += 1
                    self._detected_count += 1
                    self._blocked_count += 1
                    try:
                        loop = asyncio.get_event_loop()
                        if loop.is_running():
                            payload = {
                                "timestamp": time.time(),
                                "src_ip": context.src_ip,
                                "path": request_path,
                                "action": InspectionAction.BLOCK.name,
                                "risk_score": 1.0,
                                "latency_ms": round(elapsed, 2),
                                "triggers": ["Timeout"],
                                "xai_explanation": "Inspection timed out under fail-closed policy."
                            }
                            # Dispatch to local websocket (optional, kept for backward compat)
                            from modules.waf.api.live_monitor import waf_dispatcher
                            loop.create_task(waf_dispatcher.broadcast(payload))
                            
                            # Fire global event for Audio/SSE and cross-process dispatchers
                            async def _publish_block():
                                bus = await EventBus.instance()
                                await bus.publish(Topics.WAF_BLOCK, payload)
                            loop.create_task(_publish_block())
                    except Exception as e:
                        logger.debug("Failed to dispatch live event: %s", e)

                    return InspectionResult(
                        action=InspectionAction.BLOCK,
                        findings=[InspectionFinding(
                            plugin_name="waf_timeout",
                            severity="HIGH",
                            category="Timeout",
                            description=f"WAF inspection timed out after {elapsed:.2f}ms (limit: {self.cfg.performance.max_inspection_time_ms}ms) under fail-closed policy",
                            confidence=1.0,
                            recommends_block=True
                        )],
                        processing_time_ms=elapsed,
                        metadata={
                            "waf": "timeout_fail_closed",
                            "latency_ms": round(elapsed, 2),
                            "risk_score": 1.0,
                            "risk_decision": "BLOCK"
                        }
                    )
            return None

        # ── 1. HONEYPOT CHECK & TARPITTING ───────────────────────────
        honeypot_boost = 0.0
        if self.cfg.honeypot.enabled:
            hp_result = self.honeypot.check(context.src_ip, request_path)
            honeypot_boost = hp_result.score_boost if hp_result.triggered else 0.0

            if hp_result.triggered:
                # Active Deception (Tarpitting) — Non-blocking metadata assignment for proxy layer
                if hp_result.tarpit_delay_sec > 0:
                    logger.debug("Tarpit delay metadata recorded for IP %s (%s seconds)", context.src_ip, hp_result.tarpit_delay_sec)

                findings.append(InspectionFinding(
                    plugin_name="waf_honeypot",
                    severity="HIGH",
                    category="Honeypot",
                    description=f"Honeypot triggered: {hp_result.path}",
                    confidence=0.99,
                    recommends_block=True,
                    metadata={"honeypot_path": hp_result.path},
                ))
                
        # ── 1.1 RATE LIMITING ─────────────────────────────────────────
        if self.cfg.rate_limiter.enabled:
             # Assume user_id is passed down from an Auth inspector upstream if available
             user_id = context.metadata.get("user_id") 
             is_allowed, rl_reason = self.rate_limiter.evaluate_request(context.src_ip, user_id, request_path)
             if not is_allowed:
                 # Rate limit exceeded. Soft Block (429)
                 res = InspectionResult(
                     action=InspectionAction.BLOCK, # Translated to 429 upstream
                     findings=[InspectionFinding(
                         plugin_name="waap_rate_limiter",
                         severity="MEDIUM",
                         category="Rate Limit Exceeded",
                         description=rl_reason,
                         confidence=1.0,
                         recommends_block=True
                     )],
                     metadata={"waf": "rate_limited", "reason": rl_reason}
                 )
                 self._dispatch_event(context, request_path, res, risk_score=0.8, elapsed_ms=(time.time() - t_start)*1000)
                 return res

        # ── 1.2 ATO PROTECTOR ─────────────────────────────────────────
        ato_risk = 0.0
        if self.cfg.ato_protector.enabled and self.ato_protector.is_login_endpoint(request_path):
             username_attempt = context.metadata.get("login_username") # if parsed upstream
             is_ato_attack, ato_risk, ato_reason = self.ato_protector.track_and_evaluate(context.src_ip, username_attempt)
             if is_ato_attack:
                  findings.append(InspectionFinding(
                      plugin_name="waap_ato_protector",
                      severity="HIGH",
                      category="Account Takeover",
                      description=ato_reason,
                      confidence=ato_risk,
                      recommends_block=True
                  ))
                  # Instantly bump the honeypot boost variable to act as generic risk scalar
                  honeypot_boost += ato_risk 

        # ── 1.3 CLIENT FINGERPRINTING ─────────────────────────────────
        if self.cfg.fingerprint.enabled:
             ja3_hash = context.metadata.get("ja3_hash")
             headers = context.metadata.get("request_headers", {}) # Expecting dict of headers
             user_agent = headers.get("user-agent", "")

             # SSL-Aware: إذا تم فك التشفير بالـ MITM، فإن JA3 يعكس بصمة الـ Proxy
             # وليس المتصفح الحقيقي → نُمرّر None لتعطيل فحص TLS Fingerprint
             _ssl_cfg = getattr(self.cfg, 'ssl_aware', None)
             _skip_ja3 = (
                 context.is_ssl_inspected
                 and _ssl_cfg is not None
                 and _ssl_cfg.enabled
                 and _ssl_cfg.skip_ja3_on_decrypted
             )
             if _skip_ja3:
                 logger.debug("[WAF][SSL-Aware] Skipping JA3 fingerprint (MITM-decrypted traffic) for %s", context.src_ip)
                 _effective_ja3 = None
             else:
                 _effective_ja3 = ja3_hash

             fp_result = self.fingerprint_engine.analyze(user_agent, headers, _effective_ja3)
             if fp_result.is_suspicious:
                 findings.append(InspectionFinding(
                     plugin_name="waap_fingerprint",
                     severity="MEDIUM",
                     category="Bot Fingerprint Spoofing",
                     description=fp_result.reason,
                     confidence=fp_result.risk_score,
                     recommends_block=fp_result.risk_score >= 0.8
                 ))
                 boost_weight = self.cfg.dynamic_amplifiers.fingerprint_boost_weight if getattr(self.cfg, 'dynamic_amplifiers', None) else 0.5
                 honeypot_boost += (fp_result.risk_score * boost_weight) # Weight it into the final WAF risk

        # ── 1.4 API SCHEMA VALIDATION ─────────────────────────────────
        content_type = context.metadata.get("request_headers", {}).get("content-type", "")
        if self.cfg.api_schema.enabled:
            api_val = self.api_validator.validate(request_path, data, content_type)
            if not api_val.is_valid:
                 findings.append(InspectionFinding(
                     plugin_name="waap_api_validator",
                     severity="HIGH" if api_val.violation_score > 0.7 else "MEDIUM",
                     category="API Schema Violation",
                     description=api_val.violation_reason,
                     confidence=api_val.violation_score,
                     recommends_block=api_val.violation_score > 0.6
                 ))
                 honeypot_boost += api_val.violation_score

        # ── 1.5 GRAPHQL DEEP INSPECTION ───────────────────────────────
        if self.cfg.graphql_inspector.enabled:
             # Basic decode for JSON payload inspection
             raw_decoded = data.decode('utf-8', errors='ignore')
             is_gql, gql_val = self.graphql_inspector.inspect(raw_decoded, content_type)
             if is_gql and not gql_val.is_valid:
                 findings.append(InspectionFinding(
                     plugin_name="waap_graphql_inspector",
                     severity="HIGH" if gql_val.violation_score > 0.7 else "MEDIUM",
                     category="GraphQL Attack Detected",
                     description=gql_val.violation_reason,
                     confidence=gql_val.violation_score,
                     recommends_block=gql_val.violation_score > 0.6
                 ))
                 honeypot_boost += gql_val.violation_score

        # ── 2. PREPROCESSING ─────────────────────────────────────────
        if self.cfg.preprocessing.enabled:
            decoded_text, prep_meta = self.preprocessor.decode(data)
        else:
            decoded_text = data.decode('utf-8', errors='replace')
            prep_meta = {"encoding_layers": [], "iterations": 0,
                         "had_null_bytes": False,
                         "original_length": len(data), "decoded_length": len(data)}

        # ── 2.1 INJECT URL + QUERY STRING INTO INSPECTION SURFACE ────
        # SQL injection, XSS, and path traversal frequently appear in the
        # URL / query string (e.g. ?q=' UNION SELECT ...).  The body alone
        # (decoded_text) would miss these entirely.  Prepend the full URL
        # surface so every downstream rule, NLP model, and GAF sees it.
        _url_surface = " ".join(filter(None, [
            request_method,
            request_url or request_path,
            request_query,
        ]))
        if _url_surface.strip():
            _url_decoded, _ = self.preprocessor.decode(_url_surface.encode('utf-8', errors='replace'))
            decoded_text = _url_decoded + ("\n" if decoded_text else "") + decoded_text
                         
        # ── 2.5 SHADOW AUTOPILOT OBSERVATION ─────────────────────────
        if self.cfg.shadow_mode.enabled and self.autopilot.is_learning():
            try:
                # Capture structural data without blocking
                req_method = context.metadata.get("request_method", "GET")
                req_headers = context.metadata.get("request_headers", {})
                self.autopilot.observe(request_path, req_method, req_headers, len(data))
            except Exception as e:
                logger.debug("Shadow Autopilot Observe error: %s", e)

        # ── 2.8 INTENT-PROVING DECEPTION CHECK (PATENT POC) ──────────
        intent_proven = False
        evidence = ""
        if self.deception_engine:
            intent_proven, intent_score, evidence = self.deception_engine.analyze_request(
                payload_str=decoded_text,
                url_path=request_path
            )
            if intent_proven:
                findings.append(InspectionFinding(
                    plugin_name="waap_deception",
                    severity="CRITICAL",
                    category="Intent Proven",
                    description=evidence,
                    confidence=1.0,
                    recommends_block=True
                ))
                logger.critical("INTENT PROVEN: %s", evidence)
                # We do NOT return early here anymore; we let the RiskEngine compute 
                # the 100% breakdown for unified logging.

        # ── 3. FEATURE EXTRACTION ────────────────────────────────────
        timeout_res = check_timeout()
        if timeout_res:
            return timeout_res
        # Feature extraction is lightweight and required for heuristics, logging, and bot detection
        waf_features = self.feature_ext.extract(decoded_text, prep_meta, request_url)

        # ── 3.5 RULE-BASED OVERRIDE (Defense-in-Depth) ───────────────────────
        # Deterministic rules that block regardless of AI model score.
        # These cover attack patterns that ML models may under-score (e.g., Stored XSS
        # in POST body, Command Injection via form fields, SQL injection in query strings).
        if self.cfg.is_blocking:
            import re as _re
            import urllib.parse as _urlparse

            # XSS: explicit tags/event handlers in body content
            _XSS_RULE = _re.compile(
                r'<\s*script[\s>]|javascript\s*:|'
                r'on(?:error|load|click|mouseover|focus|dblclick|submit|input|change)\s*=|'
                r'<\s*img[^>]+src\s*=|<\s*svg[^>]+on|<\s*iframe[\s>]|'
                r'document\s*\.\s*cookie|eval\s*\(|alert\s*\(|fromCharCode',
                _re.IGNORECASE,
            )
            # Command Injection: shell operators + common OS commands.
            # [\s+]* covers both whitespace AND `+` (URL form-encoded space in POST bodies:
            # `127.0.0.1; cat /etc/passwd` → `127.0.0.1;+cat+/etc/passwd` after form encoding)
            _CMD_RULE = _re.compile(
                r'(?:;|\||\&\&|`|\$\()([\s+]*)(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|python|perl|ruby|php)\b|'
                r'\.\./.*(?:etc/passwd|etc/shadow|proc/self)|'
                r'(?:/bin/|/usr/bin/)(?:bash|sh|nc|cat)',
                _re.IGNORECASE,
            )
            # SQL Injection: UNION-based, tautologies, comment bypass, blind time-based
            _SQL_RULE = _re.compile(
                r"union\s+(?:all\s+)?select\b|"
                r"(?:--|#)\s*$|"
                r"\bor\s+[\w'\"]+\s*=\s*[\w'\"]+|"
                r"\bsleep\s*\(\s*\d+\s*\)|\bwaitfor\s+delay\b|"
                r"\bexec(?:ute)?\s+(?:xp_|sp_)|\bxp_cmdshell\b|"
                r"information_schema\b|pg_sleep\b|"
                r"'\s*(?:or|and)\s+'[^']*'\s*=\s*'[^']*'|"
                r"'\s*;\s*(?:drop|insert|update|delete|select)\b",
                _re.IGNORECASE,
            )
            # GraphQL Abuse: introspection + sensitive field harvesting
            _GQL_RULE = _re.compile(
                r'__(?:schema|type|typename|introspectiontype)|'
                r'introspection|'
                r'\{\s*system\b|\{\s*admin\b|'
                r'\bpassword\b.*\bquery\b|\busers?\b.*\bpassword\b',
                _re.IGNORECASE,
            )

            # Scan decoded_text + unquote_plus version to catch both
            # standard URL encoding (%20) and form encoding (+ → space)
            _plus_decoded = _urlparse.unquote_plus(decoded_text)
            _scan_target = decoded_text if decoded_text == _plus_decoded else decoded_text + "\n" + _plus_decoded

            _xss_match = _XSS_RULE.search(_scan_target)
            _cmd_match = _CMD_RULE.search(_scan_target)
            _sql_match = _SQL_RULE.search(_scan_target)
            _gql_match = _GQL_RULE.search(_scan_target)

            if _xss_match or _cmd_match or _sql_match or _gql_match:
                if _sql_match:
                    _attack_type = "SQL Injection"
                    _match_obj   = _sql_match
                elif _xss_match:
                    _attack_type = "XSS"
                    _match_obj   = _xss_match
                elif _gql_match:
                    _attack_type = "GraphQL Introspection Abuse"
                    _match_obj   = _gql_match
                else:
                    _attack_type = "Command Injection"
                    _match_obj   = _cmd_match

                _matched = _match_obj.group(0)[:80]
                logger.warning(
                    "WAF [RULE-BLOCK] %s detected | IP=%s url=%s match=%r",
                    _attack_type, context.src_ip, request_url or request_path, _matched,
                )

                _rule_finding = InspectionFinding(
                    plugin_name="waf_rules",
                    severity="CRITICAL",
                    category=f"Injection: {_attack_type}",
                    description=f"Deterministic rule matched {_attack_type} pattern: {_matched!r}",
                    confidence=1.0,
                    recommends_block=True,
                    metadata={"rule_match": _matched, "attack_type": _attack_type},
                )
                res = InspectionResult(
                    action=InspectionAction.BLOCK,
                    findings=[_rule_finding],
                    metadata={
                        "waf": "rule_blocked",
                        "rule_type": _attack_type,
                        "risk_score": 1.0,
                        "risk_decision": "BLOCK",
                    },
                )
                self._dispatch_event(context, request_path, res, risk_score=1.0, elapsed_ms=(time.time() - t_start)*1000)
                return res

        # ── 4. AI MODELS LAYER ───────────────────────────────────────

        # Extract query parameters and HTTP body for AI models (NLP / GAF) to prevent false positives on HTTP headers
        inspectable_text = decoded_text
        try:
            if decoded_text.startswith("GET ") or decoded_text.startswith("POST ") or decoded_text.startswith("PUT ") or decoded_text.startswith("DELETE ") or decoded_text.startswith("PATCH "):
                parts = decoded_text.split("\r\n\r\n", 1)
                if len(parts) == 1:
                    parts = decoded_text.split("\n\n", 1)
                
                headers_part = parts[0]
                body_part = parts[1] if len(parts) > 1 else ""
                
                lines = headers_part.split("\n")
                if lines:
                    request_line = lines[0].strip()
                    req_parts = request_line.split()
                    if len(req_parts) >= 2:
                        url_path = req_parts[1]
                        if "?" in url_path:
                            query_string = url_path.split("?", 1)[1]
                            inspectable_text = f"{query_string}\n{body_part}"
                        else:
                            inspectable_text = body_part
                    else:
                        inspectable_text = body_part
                else:
                    inspectable_text = body_part
        except Exception:
            pass

        # 4a. NLP attack detection with Certified Robustness (Randomized Smoothing)
        nlp_score, nlp_label = 0.0, "benign"
        cert_radius = 0.0
        timeout_res = check_timeout()
        if timeout_res:
            return timeout_res
        if self.cfg.nlp.enabled and self.nlp_model:
            try:
                if getattr(self.nlp_model, "device", None) and self.nlp_model.device.type == "cpu":
                    # On CPU, bypass loop-based Randomized Smoothing to keep latency < 2ms
                    nlp_score, nlp_label = self.nlp_model.predict(inspectable_text)
                    cert_radius = 0.0
                else:
                    # On GPU/CUDA, leverage full certified robustness
                    smoothed_label, p_top, cert_radius = self.nlp_model.predict_smoothed(inspectable_text, N=100, p=0.05)
                    nlp_label = smoothed_label
                    if smoothed_label == "benign":
                        nlp_score = 1.0 - p_top
                    else:
                        nlp_score = p_top
            except Exception as e:
                logger.error("WAF CPU/Execution safety: NLP model prediction crashed: %s. Falling back to default scoring.", e)

        # 4b. Bot detection
        bot_score, bot_label  = 0.0, "legitimate_user"
        timeout_res = check_timeout()
        if timeout_res:
            return timeout_res
        if self.cfg.bot.enabled and self.bot_model:
            try:
                bot_features = self._build_bot_features(context, waf_features)
                bot_score, bot_label = self.bot_model.predict(bot_features)

                # SSL-Aware: الـ Proxy يُعيد بناء HTTP Headers عند فك التشفير،
                # مما يجعل الطلب يبدو كـ "Bot" للنموذج. نُخفف الـ bot_score
                # بمعامل قابل للتحكم من waf.yaml (ssl_aware.bot_score_damping)
                _ssl_cfg = getattr(self.cfg, 'ssl_aware', None)
                if (
                    context.is_ssl_inspected
                    and _ssl_cfg is not None
                    and _ssl_cfg.enabled
                    and bot_score > 0.0
                ):
                    _damped = bot_score * _ssl_cfg.bot_score_damping
                    logger.debug(
                        "[WAF][SSL-Aware] bot_score damped: %.3f → %.3f (damping=%.2f) for %s",
                        bot_score, _damped, _ssl_cfg.bot_score_damping, context.src_ip
                    )
                    bot_score = _damped
            except Exception as e:
                logger.error("WAF CPU/Execution safety: Bot model prediction crashed: %s. Falling back to default scoring.", e)

        # 4c-GNN. Session-Level GNN Threat Detector
        gnn_score = 0.0
        if self.cfg.gnn.enabled and self.gnn_model:
            try:
                session_id   = context.metadata.get("session_id", context.src_ip)
                gnn_features = {
                    "request_length":      waf_features.get("request_length",      0.0),
                    "payload_entropy":     waf_features.get("payload_entropy",     0.0),
                    "special_char_ratio":  waf_features.get("special_char_ratio",  0.0),
                    "sql_keyword_count":   waf_features.get("sql_keyword_count",   0.0),
                    "xss_keyword_count":   waf_features.get("xss_keyword_count",   0.0),
                    "encoding_layer_count":waf_features.get("encoding_layer_count",0.0),
                    "has_null_byte":       waf_features.get("has_null_byte",       0.0),
                }
                gnn_score = self.gnn_model.predict(session_id, gnn_features)
            except Exception as e:
                logger.error("WAF CPU/Execution safety: GNN model prediction crashed: %s. Falling back to 0.0.", e)

        # 4d. Threat Intelligence
        reputation_score = 0.0
        if self.cfg.threat_intel.enabled and self.threat_intel:
            try:
                # Check metadata cache first
                reputation_score = context.metadata.get("reputation_score_cached")
                if reputation_score is None:
                    coro = self.threat_intel.get_ip_score(context.src_ip)
                    try:
                        loop = asyncio.get_running_loop()
                    except RuntimeError:
                        loop = None

                    if loop and loop.is_running():
                        fut = asyncio.run_coroutine_threadsafe(coro, loop)
                        reputation_score = fut.result(timeout=2.0)
                    else:
                        reputation_score = asyncio.run(coro)
            except Exception as e:
                logger.debug("ThreatIntel lookup failed: %s. Defaulting to 0.0.", e)
                reputation_score = 0.0

        # 4d. Quick heuristic anomaly from features (rules-based fallback)
        anomaly_score = 0.0
        if self.cfg.anomaly.enabled:
            anomaly_score = self._heuristic_anomaly_score(waf_features)

        # 4e. GAF (Layer 4) Semantic Intent
        gaf_score, gaf_label = 0.0, "benign_query"
        if self.cfg.gaf.enabled and self.gaf_model:
            # Skip GAF if there's no meaningful text to evaluate.
            # An empty body / no query-string produces unreliable transformer
            # scores (effectively random) that look like false positives.
            _gaf_text = inspectable_text.strip()
            if len(_gaf_text) < 8:
                pass  # No meaningful content — leave gaf_score = 0.0
            else:
                elapsed = (time.time() - t_start) * 1000
                if getattr(self.gaf_model, "device", None) and self.gaf_model.device.type == "cpu" and elapsed > 200.0:
                    logger.warning("Skipping GAF transformer inference on CPU to prevent WAF timeout (elapsed: %.2fms)", elapsed)
                else:
                    try:
                        gaf_score, gaf_label = self.gaf_model.predict(_gaf_text)
                    except Exception as e:
                        logger.error("WAF CPU/Execution safety: GAF model prediction crashed: %s. Falling back to default scoring.", e)


        # 4f. Temporal BiLSTM (Layer 7) Stateful Tracker
        temporal_score = 0.0
        if self.cfg.temporal.enabled and self.temporal_tracker:
            try:
                headers = context.metadata.get("request_headers", {})
                header_count = len(headers)
                cookie_count = len(headers.get("cookie", "").split(";")) if "cookie" in headers else 0
                temporal_score = self.temporal_tracker.record_and_predict(
                    ip_address=context.src_ip,
                    latency_ms=round((time.time() - t_start) * 1000, 2),
                    header_count=header_count,
                    cookie_count=cookie_count,
                    payload_bytes=len(data)
                )

                # SSL-Aware: Temporal BiLSTM يرصد "نمط APT" في طلبات الـ HTTPS الأولى
                # لأن المتصفح يُعيد المحاولة عند فشل الاتصال → latency patterns متسارعة غير طبيعية
                # وكذلك تختلف cookie_count وheader_count عن الطلبات المباشرة → false APT signal.
                _ssl_cfg = getattr(self.cfg, 'ssl_aware', None)
                if (
                    context.is_ssl_inspected
                    and _ssl_cfg is not None
                    and _ssl_cfg.enabled
                    and temporal_score > 0.0
                ):
                    _orig_temp = temporal_score
                    temporal_score = temporal_score * _ssl_cfg.temporal_score_damping
                    logger.debug(
                        "[WAF][SSL-Aware] temporal_score damped: %.3f → %.3f (damping=%.2f) for %s",
                        _orig_temp, temporal_score, _ssl_cfg.temporal_score_damping, context.src_ip
                    )
            except Exception as e:
                logger.error("WAF CPU/Execution safety: Temporal tracker prediction crashed: %s. Falling back to default scoring.", e)

        # ── 5. RISK SCORING ──────────────────────────────────────────
        timeout_res = check_timeout()
        if timeout_res:
            return timeout_res
        # Blend GNN session score into bot_score.
        # Use weighted average (not max) so a GNN warm-start model trained on
        # synthetic data cannot unilaterally force combined_bot to 1.00.
        # Once GNN is trained on real traffic, its contribution will be accurate.
        gnn_override_weight = self.cfg.dynamic_amplifiers.gnn_override_weight if getattr(self.cfg, 'dynamic_amplifiers', None) else 0.35
        gnn_weight = gnn_override_weight if self.cfg.gnn.enabled and gnn_score > 0 else 0.0
        bot_weight = 1.0 - gnn_weight

        # SSL-Aware: GNN يرى جلسات طلبات متسارعة (فشل VIP + retry) كـ نمط تعددي → MULTI-REQUEST ATTACK
        # بدون damping سيُعوّض تخفيف bot_score. نُطبّق نفس المعامل لمنع التعويض.
        _ssl_cfg = getattr(self.cfg, 'ssl_aware', None)
        if (
            context.is_ssl_inspected
            and _ssl_cfg is not None
            and _ssl_cfg.enabled
            and gnn_score > 0.0
        ):
            _orig_gnn = gnn_score
            gnn_score = gnn_score * _ssl_cfg.gnn_score_damping
            logger.debug(
                "[WAF][SSL-Aware] gnn_score damped: %.3f → %.3f (damping=%.2f) for %s",
                _orig_gnn, gnn_score, _ssl_cfg.gnn_score_damping, context.src_ip
            )

        combined_bot_score = min(1.0, bot_score * bot_weight + gnn_score * gnn_weight)

        breakdown = self.risk_engine.calculate(
            nlp_score        = nlp_score,
            anomaly_score    = anomaly_score,
            bot_score        = combined_bot_score,
            reputation_score = reputation_score,
            honeypot_boost   = honeypot_boost,
            gaf_score        = gaf_score,
            temporal_score   = temporal_score,
            intent_proven    = intent_proven,
        )

        risk_score = breakdown.final_score
        decision   = breakdown.decision

        # ── 6. POLICY DECISION ───────────────────────────────────────
        # In monitor/learning mode: never block, always allow
        if not self.cfg.is_blocking:
            action = InspectionAction.ALLOW
        elif decision == PolicyDecision.BLOCK:
            action = InspectionAction.BLOCK
        elif decision == PolicyDecision.SOFT_BLOCK:
            action = InspectionAction.BLOCK     # map to framework's BLOCK
        elif decision == PolicyDecision.CHALLENGE:
            action = InspectionAction.QUARANTINE  # let upstream issue CAPTCHA
        else:
            action = InspectionAction.ALLOW

        # After a BLOCK: record it in the GNN session so future requests from
        # this IP are scored with awareness of the block history.
        # We do NOT clear the session — erasing it would let attackers evade
        # detection by spacing requests across multiple "fresh" sessions.
        # The session graph (attack pattern memory) is preserved; only the
        # block count is incremented to amplify future scoring.
        if action == InspectionAction.BLOCK and self.gnn_model:
            try:
                session_id = context.metadata.get("session_id", context.src_ip)
                self.gnn_model.record_block(session_id)
            except Exception:
                pass
        if action == InspectionAction.BLOCK and self.temporal_tracker:
            try:
                self.temporal_tracker.clear_ip(context.src_ip)
            except Exception:
                pass


        # ── Build findings for significant threats ────────────────────
        if gaf_score > self.cfg.gaf.detection_threshold:
            findings.append(InspectionFinding(
                plugin_name="waf_gaf",
                severity="HIGH",
                category="GAF: Prompt Injection",
                description=f"GAF transformer detected prompt injection (score={gaf_score:.2f})",
                confidence=gaf_score,
                recommends_block=gaf_score > 0.75,
                metadata={"gaf_label": gaf_label, "gaf_score": gaf_score},
            ))

        if temporal_score > self.cfg.temporal.detection_threshold:
            findings.append(InspectionFinding(
                plugin_name="waf_temporal",
                severity="HIGH",
                category="Temporal: Stateful Session Anomaly",
                description=f"Temporal BiLSTM tracker detected sequence anomaly (score={temporal_score:.2f})",
                confidence=temporal_score,
                recommends_block=temporal_score > 0.70,
                metadata={"temporal_score": temporal_score},
            ))

        if nlp_score > 0.5:
            findings.append(InspectionFinding(
                plugin_name="waf_nlp",
                severity=self._score_to_severity(nlp_score),
                category=f"AI-WAF: {nlp_label.replace('_', ' ').title()}",
                description=f"NLP model detected {nlp_label} pattern (score={nlp_score:.2f})",
                confidence=nlp_score,
                recommends_block=nlp_score > 0.75,
                metadata={"nlp_label": nlp_label, "nlp_score": nlp_score},
            ))

        if bot_score > 0.5:
            findings.append(InspectionFinding(
                plugin_name="waf_bot",
                severity=self._score_to_severity(bot_score),
                category=f"AI-WAF: Bot Detected ({bot_label})",
                description=f"Bot detector identified {bot_label} (score={bot_score:.2f})",
                confidence=bot_score,
                recommends_block=bot_score > 0.8,
                metadata={"bot_label": bot_label, "bot_score": bot_score},
            ))

        # GNN session-graph finding
        if gnn_score > 0.5:
            findings.append(InspectionFinding(
                plugin_name="waf_gnn",
                severity=self._score_to_severity(gnn_score),
                category="AI-WAF: GNN Session Graph Anomaly",
                description=f"GNN session graph detected multi-request attack pattern (score={gnn_score:.2f})",
                confidence=gnn_score,
                recommends_block=gnn_score > 0.75,
                metadata={"gnn_score": gnn_score},
            ))

        if reputation_score > 0.4:
            findings.append(InspectionFinding(
                plugin_name="waf_threat_intel",
                severity="HIGH" if reputation_score > 0.7 else "MEDIUM",
                category="AI-WAF: Threat Intelligence",
                description=f"IP {context.src_ip} has known bad reputation (score={reputation_score:.2f})",
                confidence=reputation_score,
                recommends_block=reputation_score > 0.7,
                metadata={"reputation_score": reputation_score},
            ))

        # ── 6.5 DECOY INJECTION TRIGGER ──────────────────────────────
        waf_decoy_payload = None
        if self.deception_engine is not None and action != InspectionAction.BLOCK:
            # SSL-Aware: عند فك التشفير عبر MITM نستخدم عتبة أعلى لمنع الحلقة الذاتية:
            #   1. الـ Proxy يُنشئ حركة تُشغّل Deception (عتبة 0.40)
            #   2. Deception يُحقن parameter وهمي
            #   3. NLP/GNN يرى الـ parameter الوهمي كـ XSS/SQLi → block
            #   الحل: رفع العتبة إلى 0.70 للـ HTTPS المفكوكة فقط
            _ssl_cfg = getattr(self.cfg, 'ssl_aware', None)
            _deception_threshold = (
                _ssl_cfg.deception_injection_threshold
                if context.is_ssl_inspected and _ssl_cfg is not None and _ssl_cfg.enabled
                else self.cfg.deception_engine.injection_threshold
            )
            if _deception_threshold <= risk_score < self.cfg.risk_scoring.thresholds.block:
                session_id = context.metadata.get("session_id", context.src_ip)
                surface = "bola"
                if any("Bot" in f.category for f in findings):
                    surface = "scraping"

                waf_decoy_payload = self.deception_engine.generate_decoy(
                    session_id=session_id,
                    ip_address=context.src_ip,
                    attack_surface=surface
                )
                logger.info("Injecting Decoy Object for IP %s (Risk: %.2f)", context.src_ip, risk_score)

        # ── 7. XAI EXPLANATION DECODING ──────────────────────────────
        xai_explanation = ""
        if self.cfg.xai_explainer.enabled and risk_score > 0.0:
            xai_explanation = self.risk_engine.explain_decision(breakdown)
            
            # Attach XAI context to the highest severity finding for SIEM export
            if findings:
                findings[0].metadata["xai_context"] = xai_explanation

        # ── Assemble result ──────────────────────────────────────────
        latency_ms = (time.time() - t_start) * 1000

        result = InspectionResult(
            action=action,
            findings=findings,
            processing_time_ms=latency_ms,
            metadata={
                "risk_score":       risk_score,
                "risk_decision":    decision.value,
                "risk_breakdown":   breakdown.to_dict(),
                "waf_features":     waf_features,
                "prep_meta":        prep_meta,
                "nlp_label":        nlp_label,
                "bot_label":        bot_label,
                "gnn_score":        gnn_score,
                "gaf_label":        gaf_label,
                "gaf_score":        gaf_score,
                "temporal_score":   temporal_score,
                "certified_radius":  cert_radius,
                "latency_ms":       round(latency_ms, 2),
                "waf_decoy_payload": waf_decoy_payload,  # Signal for API Router to attach decoy header
                "xai_explanation":  xai_explanation,      # Add Transparent Context
            },
        )


        logger.info(
            "WAF [%s] → %s (risk=%.2f, decision=%s) | latency=%.1fms",
            context.src_ip, action.name, risk_score, decision.value, latency_ms
        )

        # Update plugin statistics
        self._inspected_count += 1
        if findings:
            self._detected_count += 1
        if action == InspectionAction.BLOCK:
            self._blocked_count += 1
        elif action == InspectionAction.QUARANTINE:
            self._challenged_count = getattr(self, "_challenged_count", 0) + 1

        # ── Record session for GNN training data ──────────
        if _gnn_log_collector is not None:
            try:
                _gnn_log_collector.record(
                    src_ip        = context.src_ip,
                    path          = context.metadata.get("request_path", "/"),
                    method        = context.metadata.get("request_method", "GET"),
                    response_code = 403 if action == InspectionAction.BLOCK else 200,
                    session_id    = context.metadata.get("session_id", context.src_ip),
                    latency_ms    = latency_ms,
                    payload_bytes = len(data),
                )
            except Exception:
                pass  # never let logging break the WAF

        # ── Broadcast to Live Monitoring Dashboard ────────
        if action != InspectionAction.ALLOW or risk_score > self.cfg.logging.alert_threshold:
            # Emit event to WebSocket clients (non-blocking)
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    payload = {
                        "timestamp": time.time(),
                        "src_ip": context.src_ip,
                        "path": request_path,
                        "action": action.name,
                        "risk_score": round(risk_score, 2),
                        "latency_ms": round(latency_ms, 2),
                        "triggers": [f.category for f in findings],
                        "xai_explanation": xai_explanation
                    }
                    from modules.waf.api.live_monitor import waf_dispatcher
                    loop.create_task(waf_dispatcher.broadcast(payload))
                    
                    # Fire global EventBus for Audio Alerts and cross-process tracking
                    async def _publish_waf():
                        bus = await EventBus.instance()
                        topic = Topics.WAF_BLOCK if action == InspectionAction.BLOCK else Topics.WAF_ALERT
                        await bus.publish(topic, payload)
                    loop.create_task(_publish_waf())
            except Exception as e:
                logger.debug("Failed to dispatch live event: %s", e)

        # ─ Self-Learning Record ─ (gated by settings) ─
        if self.self_logger is not None:
            try:
                auto_label: Optional[int] = None
                label_src              = "auto"
                if action == InspectionAction.BLOCK:
                    auto_label = 1
                    label_src  = "auto_block"
                elif action == InspectionAction.ALLOW and not findings:
                    auto_label = 0
                    label_src  = "auto_allow"

                self.self_logger.record(
                    src_ip         = context.src_ip,
                    request_path   = request_path,
                    request_method = context.metadata.get("request_method", "GET"),
                    payload        = decoded_text[:4096] if decoded_text else "",
                    features       = waf_features,
                    risk_score     = risk_score,
                    decision       = decision.value,
                    nlp_score      = nlp_score,
                    bot_score      = bot_score,
                    anomaly_score  = anomaly_score,
                    reputation     = reputation_score,
                    label          = auto_label,
                    label_source   = label_src,
                )
            except Exception:
                pass  # never let the logger break the WAF

        return result

    # ── Private helpers ────────────────────────

    @staticmethod
    def _score_to_severity(score: float) -> str:
        if score >= 0.9: return "CRITICAL"
        if score >= 0.7: return "HIGH"
        if score >= 0.5: return "MEDIUM"
        return "LOW"

    @staticmethod
    def _heuristic_anomaly_score(features: dict) -> float:
        """
        Quick rules-based anomaly score from WAF features.
        Used when the Anomaly Detector model is not available.
        Serves as a lightweight fallback.
        """
        score = 0.0

        # High entropy → possible encrypted/random payload
        if features.get("payload_entropy", 0) > 0.85:
            score += 0.2

        # Many attack keywords
        sql_kw = features.get("sql_keyword_count", 0)
        xss_kw = features.get("xss_keyword_count", 0)
        if sql_kw > 3:
            score += min(sql_kw * 0.05, 0.3)
        if xss_kw > 2:
            score += min(xss_kw * 0.05, 0.25)

        # Multiple encoding layers = obfuscation attempt
        enc_layers = features.get("encoding_layer_count", 0)
        if enc_layers > 1:
            score += min(enc_layers * 0.1, 0.3)

        # High special character ratio
        if features.get("special_char_ratio", 0) > 0.3:
            score += 0.15

        # Null byte present
        if features.get("has_null_byte", 0) > 0:
            score += 0.25

        return min(score, 1.0)

    @staticmethod
    def _build_bot_features(context: InspectionContext, waf_features: dict) -> dict:
        """Map inspection context + WAF features to bot detection features."""
        meta = context.metadata
        return {
            "request_rate":          meta.get("request_rate", 1.0),
            "iat_variance":          meta.get("iat_variance", 1.0),
            "session_duration":      meta.get("session_duration", 60.0),
            "unique_endpoints":      meta.get("unique_endpoints", 1),
            "user_agent_entropy":    meta.get("user_agent_entropy", 0.5),
            "header_count":          meta.get("header_count", 10),
            "accept_language_valid": meta.get("accept_language_valid", 1.0),
            "cookie_count":          meta.get("cookie_count", 0),
            "referer_present":       meta.get("referer_present", 0.0),
            "method_diversity":      meta.get("method_diversity", 1),
        }
