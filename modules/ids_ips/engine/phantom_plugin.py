"""
PHANTOM IDS/IPS — Unified Inspection Plugin
============================================
Production Orchestrator for the PHANTOM framework inside bunyanx NGFW.

Pipeline per packet
-------------------
  1. SBE (Layer 1) — Spectral Byte Encode the payload → 256-dim vector
  2. CTGB (Layer 2) — Update causal graph with src→dst flow + SBE vector
  3. PHANTOMInference (Layer 3) — GNN+Transformer threat classification
  4. IPSEngine (Legacy) — Signature + Reputation + UBA ZTA checks
  5. Fusion decision — PHANTOM score × legacy signals → final action

Graceful degradation
--------------------
  - If numpy/pywt missing → SBE returns zero vector; CTGB graph still builds
  - If no trained model → PHANTOMInference runs heuristic fallback
  - If IPSEngine raises → logged, does NOT crash the pipeline (fail-open safe)

Thread safety
-------------
  All PHANTOM sub-components are already thread-safe.
  This plugin is a singleton instantiated once by ModuleManager.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

class _NoOpTracker:
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def set(self, k, v): pass
    def set_status_error(self, e): pass

from system.core.framework.plugin_base import (
    InspectorPlugin,
    InspectionContext,
    InspectionResult,
    InspectionAction,
    PluginPriority,
)

logger = logging.getLogger(__name__)

# ── Lazy imports (graceful degradation) ──────────────────────────────────────

try:
    import numpy as np
    from modules.ids_ips.engine.spectral.sbe import SpectralCache
    _SBE_AVAILABLE = True
except ImportError:
    np = None  # type: ignore[assignment]
    _SBE_AVAILABLE = False
    logger.warning("PHANTOM: numpy/pywt not available — SBE disabled, zero-vector fallback active.")

try:
    from modules.ids_ips.engine.graph.ctgb import CausalTemporalGraphBuilder, CausalGraph
    _CTGB_AVAILABLE = True
except ImportError:
    _CTGB_AVAILABLE = False
    logger.warning("PHANTOM: CTGB unavailable.")

try:
    from modules.ids_ips.engine.model.phantom_classifier import PHANTOMInference, PHANTOMResult
    _MODEL_AVAILABLE = True
except ImportError:
    _MODEL_AVAILABLE = False
    logger.warning("PHANTOM: PHANTOMInference unavailable.")


# ── Per-host SBE history (feeds Transformer temporal sequence) ───────────────

_SBE_HISTORY: Dict[str, deque] = defaultdict(lambda: deque(maxlen=32))
_SBE_HISTORY_LOCK = __import__("threading").RLock()


# ── Result dataclass ─────────────────────────────────────────────────────────

@dataclass
class PHANTOMInspectionRecord:
    """XAI evidence attached to InspectionResult.metadata['phantom']."""
    sample_id: str
    src_ip: str
    dst_ip: str
    sbe_available: bool
    causal_density: float
    phantom_class: str
    phantom_confidence: float
    phantom_is_threat: bool
    inference_ms: float
    legacy_action: str
    final_action: str
    latency_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sample_id":          self.sample_id,
            "src_ip":              self.src_ip,
            "dst_ip":              self.dst_ip,
            "sbe_available":       self.sbe_available,
            "causal_density":      round(self.causal_density, 4),
            "phantom_class":       self.phantom_class,
            "phantom_confidence":  round(self.phantom_confidence, 4),
            "phantom_is_threat":   self.phantom_is_threat,
            "inference_ms":        round(self.inference_ms, 2),
            "legacy_action":       self.legacy_action,
            "final_action":        self.final_action,
            "latency_ms":          round(self.latency_ms, 2),
        }


# ── Main Plugin ───────────────────────────────────────────────────────────────

class PHANTOMPlugin(InspectorPlugin):
    """
    PHANTOM IDS/IPS Inspection Plugin.

    Registered in ModuleManager as "ids_ips" → "PHANTOMPlugin".
    Replaces the old IPSEngine-only pipeline with the full PHANTOM stack.
    """

    # Traffic-type filter: inspect ALL traffic
    SUPPORTED_PROTOCOLS = {"TCP", "UDP", "ICMP", "TLS", "HTTP", "DNS", "ANY"}

    def __init__(self) -> None:
        super().__init__(name="PHANTOMPlugin", priority=PluginPriority.HIGH)

        # ── Layer 1: Spectral Byte Encoder ───────────────────────────────
        self._sbe: Optional[SpectralCache] = None
        if _SBE_AVAILABLE:
            self._sbe = SpectralCache(maxsize=8192)

        # ── Layer 2: Causal Temporal Graph Builder ───────────────────────
        self._ctgb: Optional[CausalTemporalGraphBuilder] = None
        if _CTGB_AVAILABLE:
            self._ctgb = CausalTemporalGraphBuilder(
                tau=30.0,
                causal_threshold=0.30,
                max_history=20,
                max_idle_seconds=300.0,
            )

        # ── Layer 3: PHANTOM Classifier ──────────────────────────────────
        self._phantom: Optional[PHANTOMInference] = None
        if _MODEL_AVAILABLE:
            self._phantom = PHANTOMInference(seq_len=16)

        # ── Layer 4: Online Continual Learner ────────────────────────────
        self._ocl: Optional[Any] = None
        if _MODEL_AVAILABLE:
            try:
                from modules.ids_ips.engine.learning.ocl_engine import OnlineContinualLearner
                pt_model = self._phantom._pt_model if self._phantom else None
                self._ocl = OnlineContinualLearner(model=pt_model)
                if self._phantom:
                    self._phantom.use_pytorch_for_ocl = True
            except Exception as exc:
                logger.warning("PHANTOM: OnlineContinualLearner initialization failed: %s", exc)

        # ── Layer 5: Legacy IPSEngine (signatures, reputation, UBA ZTA) ─
        self._ips: Optional[Any] = None
        self._ips_initialized = False

        # ── Config (injected by ModuleManager via plugin.config = …) ──────────
        # ModuleManager injects only the base.yaml modules.ids_ips section.
        # initialize() calls _load_settings() to merge the full settings.yaml.
        self.config: Dict[str, Any] = {}
        self._settings_path: str = ""  # resolved in initialize()

        # ── Telemetry ────────────────────────────────────────────────────────
        self._tel = None
        try:
            from modules.ids_ips.engine.core.telemetry import Telemetry
            self._tel = Telemetry.instance()
        except Exception:
            pass

        # ── Stats ────────────────────────────────────────────────────────
        self._total_inspected = 0
        self._total_blocked   = 0
        self._total_phantom_threats = 0

        # Register plugin singleton with the API layer
        try:
            from modules.ids_ips.api.router import register_phantom_plugin
            register_phantom_plugin(self)
        except Exception as e:
            logger.warning("PHANTOMPlugin: failed to register with API router: %s", e)

        logger.info(
            "PHANTOMPlugin ready  |  SBE=%s  CTGB=%s  Model=%s  Backend=%s",
            _SBE_AVAILABLE, _CTGB_AVAILABLE, _MODEL_AVAILABLE,
            self._phantom.backend if self._phantom else "none",
        )

    # ── Plugin lifecycle ──────────────────────────────────────────────────────

    def can_inspect(self, context: InspectionContext) -> bool:
        """PHANTOM inspects all TCP/UDP traffic — always returns True."""
        return True

    def initialize(self) -> None:
        """Called by ModuleManager after config injection."""
        self._load_settings()   # merge settings.yaml into self.config
        self._bootstrap_legacy_ips()

        # Configure the dynamic blocklist from settings.yaml
        try:
            from modules.ids_ips.engine.blocklist.dynamic_blocklist import DynamicBlocklist
            self._blocklist = DynamicBlocklist.instance()
            self._blocklist.configure(self.config, base_dir=self._base_dir)
        except Exception as exc:
            logger.warning("PHANTOMPlugin: DynamicBlocklist unavailable: %s", exc)
            self._blocklist = None

        logger.info(
            "PHANTOMPlugin initialized | settings=%s | trusted_ips=%d "
            "| internal_networks=%d | never_block_dst=%d | blocklist=%s",
            self._settings_path,
            len(self.config.get("trusted_ips", [])),
            len(self.config.get("internal_networks", [])),
            len(self.config.get("never_block_dst", [])),
            "ON" if self._blocklist else "OFF",
        )

    def _load_settings(self) -> None:
        """Load modules/ids_ips/config/settings.yaml and merge into self.config.

        ModuleManager only injects the slim base.yaml modules.ids_ips block::

            {'enabled': True, 'config_path': 'modules/ids_ips/config/settings.yaml',
             'mode': 'blocking'}

        We must read settings.yaml ourselves to get trusted_ips,
        internal_networks, never_block_dst, class_thresholds, etc.
        """
        import os
        import yaml

        config_path = self.config.get("config_path", "modules/ids_ips/config/settings.yaml")

        # Resolve relative to project root (3 levels above modules/ids_ips/engine/)
        base_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..", "..")
        )
        self._base_dir = base_dir  # stored for blocklist configure()
        full_path = os.path.join(base_dir, config_path)
        self._settings_path = full_path

        if not os.path.exists(full_path):
            logger.warning(
                "PHANTOMPlugin: settings.yaml not found at %s — "
                "trusted_ips / internal_networks / never_block_dst will be empty!",
                full_path,
            )
            return

        try:
            with open(full_path, encoding="utf-8") as fh:
                settings = yaml.safe_load(fh) or {}
            # Deep-merge settings.yaml into self.config.
            # base.yaml values (enabled, mode, config_path) are preserved;
            # settings.yaml provides the operational knobs.
            for key, value in settings.items():
                if key not in self.config:
                    self.config[key] = value
                elif isinstance(self.config[key], dict) and isinstance(value, dict):
                    self.config[key].update(value)  # shallow merge for dicts
                # lists and scalars from settings.yaml win over base.yaml
                else:
                    self.config[key] = value
            logger.debug(
                "PHANTOMPlugin: loaded settings from %s (keys: %s)",
                full_path, list(settings.keys())
            )
        except Exception as exc:
            logger.error(
                "PHANTOMPlugin: failed to load settings from %s: %s",
                full_path, exc
            )

    def _bootstrap_legacy_ips(self) -> None:
        if self._ips_initialized:
            return
        try:
            from modules.ids_ips.engine.core.engine import IPSEngine
            self._ips = IPSEngine()
            self._ips.sync_config()
            self._ips_initialized = True
            logger.info("PHANTOMPlugin: Legacy IPSEngine bootstrapped.")
        except Exception as exc:
            logger.warning("PHANTOMPlugin: Legacy IPSEngine unavailable (%s). Skipping.", exc)

    # ── Main inspect() ────────────────────────────────────────────────────────

    def inspect(
        self,
        context: InspectionContext,
        payload: bytes = b"",
    ) -> InspectionResult:
        t_start = time.perf_counter()
        self._total_inspected += 1
        sample_id = ""

        src_ip = context.src_ip
        dst_ip = context.dst_ip
        ts     = context.timestamp or time.time()

        # ── Phase 10: Typed field adapter ─────────────────────────────
        # Build a complete synthetic HTTP payload from ctx.http so the
        # signature engine can scan the FULL request: method, URL (including
        # query string where SQLi/XSS/LFI live), headers, and body.
        # Previously this only used ctx.http.body — empty for all GET attacks.
        if not payload and context.http is not None:
            _h = context.http
            # Reconstruct the HTTP request line + key headers + body
            _url_path = f"{_h.path or '/'}" + (f"?{_h.query}" if getattr(_h, 'query', '') else "")
            _request_line = (
                f"{_h.method or 'GET'} {_url_path} HTTP/1.1\r\n"
            ).encode("utf-8", errors="replace")
            _host_header = (
                f"Host: {_h.host or context.dst_ip}\r\n"
            ).encode("utf-8", errors="replace")
            # Serialize headers dict → bytes for header-based sig matching
            _headers_bytes = b""
            if _h.headers:
                for k, v in _h.headers.items():
                    _headers_bytes += f"{k}: {v}\r\n".encode("utf-8", errors="replace")
            _body = _h.body if _h.body else b""
            payload = _request_line + _host_header + _headers_bytes + b"\r\n" + _body

        # ── Dynamic Blocklist: INSTANT CHECK (before any ML) ─────────────
        # Phase 10: prefer typed fields (context.tls.sni, context.http.host)
        # before falling back to metadata dict.
        _meta        = context.metadata or {}
        _dst_domain  = (
            (context.tls.sni if context.tls else None)
            or (context.http.host if context.http else None)
            or _meta.get("domain") or _meta.get("host") or dst_ip or ""
        ).lower().strip()

        _bl = getattr(self, "_blocklist", None)
        if _bl and _bl.is_blocked(_dst_domain):
            _bl_latency = (time.perf_counter() - t_start) * 1000
            logger.warning(
                "[Blocklist] INSTANT BLOCK | %s->%s | %.2fms",
                src_ip, _dst_domain, _bl_latency,
            )
            from system.core.framework.plugin_base import InspectionFinding
            _bl_result = InspectionResult(
                action=InspectionAction.BLOCK,
                findings=[
                    InspectionFinding(
                        severity="HIGH",
                        category="dynamic_blocklist",
                        description=(
                            f"{_dst_domain} is in the dynamic threat blocklist "
                            f"(auto-blocked after {self.config.get('dynamic_blocklist', {}).get('detection_threshold', 3)} detections)"
                        ),
                        plugin_name="PHANTOMPlugin:blocklist",
                        confidence=1.0,
                    )
                ],
            )
            _bl_result.metadata["blocklist_hit"] = True
            _bl_result.metadata["dst_domain"]    = _dst_domain
            _bl_result.metadata["latency_ms"]    = round(_bl_latency, 3)
            return _bl_result

        # ── Trusted / Internal IP Checks ─────────────────────────────────
        # All values come from settings.yaml — no IPs are hardcoded here.
        #
        # trusted_ips      — exact src or dst IPs that are never blocked.
        # internal_networks — CIDR prefixes (e.g. "10.", "192.168."); if src
        #                     matches, traffic is treated as internal and is
        #                     logged but NOT blocked (prevents self-DoS).
        # never_block_dst  — exact dst IPs/names (e.g. "FIREWALL_IP") that
        #                     must never become the target of a block rule.

        # Phase 10: use ConfigLoader as single source of truth for trusted/internal.
        # context.is_internal is already computed by ContextBuilder (fast path).
        # Module config.get("trusted_ips") still supported as PHANTOM-local override.
        from system.core.config_loader import ConfigLoader

        _never_block_dst = set(self.config.get("never_block_dst", []))
        _local_trusted   = set(self.config.get("trusted_ips", []))

        _src_is_trusted  = (src_ip in _local_trusted) or ConfigLoader.is_trusted(src_ip)
        _dst_is_trusted  = (dst_ip in _local_trusted) or ConfigLoader.is_trusted(dst_ip)
        _src_is_internal = context.is_internal or ConfigLoader.is_internal(src_ip)
        _dst_is_protected = dst_ip in _never_block_dst

        _is_trusted      = _src_is_trusted
        _is_internal_src = _src_is_internal and not _src_is_trusted  # log only, no block


        if _is_trusted:
            logger.debug(
                "[PHANTOM] Trusted IP — skipping block for %s\u2192%s (telemetry-only)",
                src_ip, dst_ip
            )
        if _src_is_internal and not _is_trusted:
            logger.debug(
                "[PHANTOM] Internal src %s\u2192%s — will log threat but never block src",
                src_ip, dst_ip
            )
        if _dst_is_protected and not _is_trusted:
            logger.debug(
                "[PHANTOM] Protected dst %s — block on this destination suppressed",
                dst_ip
            )

        # ── Telemetry: Pipeline root span ─────────────────────────────────
        span_ctx = self._tel.trace.pipeline(src_ip, dst_ip) if self._tel else _NoOpTracker()
        
        with span_ctx as root_span:
            if self._tel:
                self._tel.metrics.record_packet(protocol=context.protocol, direction=context.direction)
            
            # ── Layer 1: Spectral Byte Encoding ──────────────────────────────
            sbe_vec    = None
            sbe_avail  = False
            
            sbe_span_ctx = self._tel.trace.sbe() if self._tel else _NoOpTracker()
            with sbe_span_ctx as sbe_span:
                if self._sbe is not None and payload:
                    try:
                        s0 = time.perf_counter()
                        sbe_vec   = self._sbe.encode(payload)
                        sbe_avail = True
                        dt = (time.perf_counter() - s0) * 1000
                        if self._tel:
                            self._tel.log.sbe_encoded(src_ip, len(payload), cache_hit=False, elapsed_ms=dt)
                    except Exception as exc:
                        sbe_span.set_status_error(str(exc))
                        logger.debug("SBE encode failed for %s→%s: %s", src_ip, dst_ip, exc)

            # ── Layer 2: Causal Temporal Graph ───────────────────────────────
            causal_density = 0.0
            ctgb_span_ctx = self._tel.trace.ctgb() if self._tel else _NoOpTracker()
            with ctgb_span_ctx as ctgb_span:
                if self._ctgb is not None:
                    try:
                        graph = self._ctgb.update(src_ip, dst_ip, sbe_vec, ts)
                        causal_density = graph.causal_density()
                        ctgb_span.set("causal_density", causal_density)
                        if self._tel:
                            self._tel.metrics.set_causal_density(causal_density)
                            self._tel.metrics.set_graph_topology(len(graph.nodes), len(graph.edges))
                            # self._tel.log.graph_updated(...)  # skipped for performance
                    except Exception as exc:
                        ctgb_span.set_status_error(str(exc))
                        logger.debug("CTGB update failed: %s", exc)

            # ── Layer 3: PHANTOM Threat Classification ────────────────────────
            phantom_class      = "benign"
            phantom_confidence = 0.0
            phantom_is_threat  = False
            inference_ms       = 0.0

            hgtc_span_ctx = self._tel.trace.hgtc() if self._tel else _NoOpTracker()
            with hgtc_span_ctx as hgtc_span:
                if self._phantom is not None and sbe_vec is not None:
                    try:
                        with _SBE_HISTORY_LOCK:
                            hist = list(_SBE_HISTORY[src_ip])

                        result: PHANTOMResult = self._phantom.predict(
                            sbe=sbe_vec,
                            temporal_sbes=hist if hist else None,
                            causal_density=causal_density,
                        )

                        phantom_class      = result.threat_class
                        phantom_confidence = result.confidence
                        phantom_is_threat  = result.is_threat
                        inference_ms       = result.inference_ms
                        sample_id          = result.sample_id

                        # ── SSL-Aware: تخفيف PHANTOM scores للحركة المفكوكة ──────
                        # عند HTTPS+MITM يُعيد الـ Proxy بناء الـ payload بترويسات HTTP
                        # مختلفة عن المتصفح الحقيقي → SBE يرى توليفة bytes غير مألوفة
                        # → causal_density وconfidence ترتفع بشكل كاذب.
                        # الهجمات الحقيقية (C2, exploit) ستظل فوق العتبة بعد التخفيف.
                        if context.is_ssl_inspected and phantom_confidence > 0.0:
                            _orig_conf    = phantom_confidence
                            _orig_density = causal_density
                            phantom_confidence = phantom_confidence * 0.60
                            causal_density     = causal_density     * 0.70
                            # أعد تقييم is_threat بعد التخفيف
                            _conf_threshold = self.config.get(
                                "classifier", {}
                            ).get("confidence_threshold",
                                  self.config.get("phantom_confidence_threshold", 0.70))
                            phantom_is_threat = (
                                phantom_confidence >= _conf_threshold
                                or (causal_density >= self.config.get("causal_density_threshold", 0.50)
                                    and phantom_confidence >= 0.50)
                            )
                            logger.debug(
                                "[PHANTOM][SSL-Aware] Damped: conf %.3f→%.3f "
                                "density %.3f→%.3f is_threat=%s src=%s",
                                _orig_conf, phantom_confidence,
                                _orig_density, causal_density,
                                phantom_is_threat, src_ip,
                            )


                        hgtc_span.set("threat_class", phantom_class)
                        hgtc_span.set("confidence", phantom_confidence)

                        if self._tel:
                            self._tel.metrics.record_inference_latency(inference_ms / 1000.0)
                            if phantom_is_threat:
                                self._tel.metrics.record_threat(phantom_class)
                                self._tel.log.inference_result(
                                    src_ip, dst_ip, phantom_class, 
                                    phantom_confidence, True, inference_ms
                                )

                        # Update SBE history for this host
                        with _SBE_HISTORY_LOCK:
                            _SBE_HISTORY[src_ip].append(sbe_vec)

                        # Cache SBE vector for analyst feedback window
                        if sbe_vec is not None and result is not None:
                            try:
                                from modules.ids_ips.api.router import cache_sample_sbe
                                cache_sample_sbe(result.sample_id, sbe_vec)
                            except Exception as e:
                                pass

                        if phantom_is_threat:
                            self._total_phantom_threats += 1
                            logger.warning(
                                "PHANTOM THREAT | %s→%s | class=%s conf=%.3f "
                                "causal_density=%.3f inference=%.1fms",
                                src_ip, dst_ip, phantom_class,
                                phantom_confidence, causal_density, inference_ms,
                            )
                            # FIX-FP-04: Only publish THREAT_DETECTED (which triggers AutoBlock)
                            # when confidence meets the configured threshold AND fusion will block.
                            # Low-conf detections (conf < threshold) on file uploads were causing
                            # false positives: ip_blocklist subscribes to THREAT_DETECTED and calls
                            # block_ip_sync() without any confidence check.
                            if _src_is_internal:
                                _int_thresh = float(
                                    self.config.get("internal_block_threshold", 0.92)
                                )
                                # Internal devices generating parallel DNS/HTTP bursts (e.g. mobile apps)
                                # are suppressed unless extreme confidence (>= 0.92) or critical exploit
                                _will_block = (phantom_confidence >= _int_thresh) and (
                                    phantom_class != "dos_ddos" or phantom_confidence >= 0.95
                                )
                            else:
                                _pub_conf_threshold = self.config.get(
                                    "classifier", {}
                                ).get("confidence_threshold",
                                      self.config.get("phantom_confidence_threshold", 0.75))
                                _will_block = (phantom_confidence >= _pub_conf_threshold) or (
                                    causal_density >= self.config.get("causal_density_threshold", 0.50)
                                    and phantom_confidence >= 0.50
                                )
                            try:
                                from system.events.bus import EventBus
                                from system.events.topics import Topics
                                if _will_block:
                                    # High-confidence confirmed threat → AutoBlock-eligible event
                                    EventBus.publish_from_thread(Topics.THREAT_DETECTED, {
                                        "src_ip":           src_ip,
                                        "dst_ip":           dst_ip,
                                        "threat_class":     phantom_class,
                                        "confidence":       phantom_confidence,
                                        "causal_density":   causal_density,
                                        "detection_method": "PHANTOM",
                                        "severity":         "CRITICAL" if phantom_confidence >= 0.90 else "HIGH",
                                        "description":      f"PHANTOM detected {phantom_class} (conf={phantom_confidence:.3f}, causal_density={causal_density:.3f})",
                                    })
                                else:
                                    # Low-confidence signal or internal app burst: log for SIEM/telemetry only.
                                    # Do NOT publish THREAT_DETECTED — it triggers AutoBlock.
                                    logger.info(
                                        "[PHANTOM] Internal/sub-threshold detection logged (no AutoBlock): "
                                        "%s class=%s conf=%.3f (internal=%s)",
                                        src_ip, phantom_class, phantom_confidence, _src_is_internal,
                                    )
                            except Exception as _bus_ex:
                                logger.warning("PHANTOM: Failed to publish threat event: %s", _bus_ex)

                    except Exception as exc:
                        hgtc_span.set_status_error(str(exc))
                        logger.error("PHANTOM inference error: %s", exc)

            # ── Layer 4: Legacy IPSEngine ─────────────────────────────────────
            legacy_action_str = "ALLOW"
            from system.policy.schema import PolicyContext, Action
            if self._ips is not None:
                try:
                    policy_ctx = PolicyContext(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=context.src_port,
                        dst_port=context.dst_port,
                        protocol=context.protocol,
                        # Phase 10: typed fields first, metadata fallback
                        domain=(
                            (context.tls.sni if context.tls else None)
                            or (context.http.host if context.http else None)
                            or (_meta.get("domain") if context.metadata else None)
                        ),
                    )
                    policy_ctx.metrics = context.metadata
                    legacy_action = self._ips.evaluate(policy_ctx, payload)
                    legacy_action_str = legacy_action.name
                except Exception as exc:
                    logger.error("Legacy IPSEngine error (non-fatal): %s", exc, exc_info=True)

            # ── Fusion Decision ──────────────────────────────────────────
            fusion_span_ctx = self._tel.trace.fusion() if self._tel else _NoOpTracker()
            with fusion_span_ctx as fuse_span:
                final_action = self._fuse_decision(
                    phantom_is_threat=phantom_is_threat,
                    phantom_confidence=phantom_confidence,
                    causal_density=causal_density,
                    legacy_action_str=legacy_action_str,
                    phantom_class=phantom_class,
                )
                fuse_span.set("action", final_action.name)
                root_span.set("action", final_action.name)

            # ── XAI Evidence ──────────────────────────────────────────────
            latency_ms = (time.perf_counter() - t_start) * 1000
            if self._tel:
                self._tel.metrics.record_pipeline_latency(latency_ms / 1000.0)

            record = PHANTOMInspectionRecord(
                sample_id=sample_id,
                src_ip=src_ip,
                dst_ip=dst_ip,
                sbe_available=sbe_avail,
                causal_density=causal_density,
                phantom_class=phantom_class,
                phantom_confidence=phantom_confidence,
                phantom_is_threat=phantom_is_threat,
                inference_ms=inference_ms,
                legacy_action=legacy_action_str,
                final_action=final_action.name,
                latency_ms=latency_ms,
            )

            if final_action == InspectionAction.BLOCK:
                # ── Dynamic Blocklist: feed detection counter (ALL threats) ──
                # Must run BEFORE the src-based overrides so that even trusted
                # or internal src IPs contribute to the dst domain counter.
                # The blocklist blocks the DOMAIN, not the src IP.
                _bl = getattr(self, "_blocklist", None)
                if _bl and _dst_domain:
                    newly_blocked = _bl.record_detection(_dst_domain)
                    if newly_blocked:
                        logger.warning(
                            "[Blocklist] AUTO-BLOCKED %s after %d detections "
                            "| last_src=%s class=%s conf=%.3f",
                            _dst_domain,
                            self.config.get("dynamic_blocklist", {}).get(
                                "detection_threshold", 3
                            ),
                            src_ip, phantom_class, phantom_confidence,
                        )

                # ── Override 1: Trusted IP → always ALLOW ────────────────
                if _is_trusted:
                    logger.info(
                        "[PHANTOM] Trusted IP %s\u2192%s — block overridden to ALLOW "
                        "(class=%s conf=%.3f)",
                        src_ip, dst_ip, phantom_class, phantom_confidence
                    )
                    final_action = InspectionAction.ALLOW

                # ── Override 2: Internal src — enforce internal_block_threshold ──
                elif _src_is_internal:
                    _int_thresh = float(
                        self.config.get("internal_block_threshold", ConfigLoader.get_internal_block_threshold())
                    )
                    if phantom_confidence >= _int_thresh:
                        # High-confidence internal threat: BLOCK (compromised host / pen-test)
                        self._total_blocked += 1
                        logger.warning(
                            "[PHANTOM] HIGH-CONF INTERNAL THREAT BLOCKED %s\u2192%s "
                            "class=%s conf=%.3f \u2265 threshold=%.2f",
                            src_ip, dst_ip, phantom_class, phantom_confidence, _int_thresh
                        )
                        # final_action stays BLOCK
                    else:
                        # Below threshold: log for analyst review, allow traffic
                        logger.error(
                            "[PHANTOM] INTERNAL THREAT (not blocked) %s\u2192%s "
                            "class=%s conf=%.3f < threshold=%.2f — review or lower threshold",
                            src_ip, dst_ip, phantom_class, phantom_confidence, _int_thresh
                        )
                        final_action = InspectionAction.ALLOW


                # ── Override 3: Protected dst → ALLOW ──────────────────
                elif _dst_is_protected:
                    logger.warning(
                        "[PHANTOM] Block suppressed — dst %s is in never_block_dst "
                        "(src=%s class=%s conf=%.3f)",
                        dst_ip, src_ip, phantom_class, phantom_confidence
                    )
                    final_action = InspectionAction.ALLOW

                # ── External threat → enforce BLOCK ──────────────────────
                else:
                    self._total_blocked += 1
                    if self._tel:
                        self._tel.metrics.record_block(phantom_class)
                        self._tel.log.block(src_ip, dst_ip, phantom_class, phantom_confidence)

                    try:
                        from system.events.bus import EventBus
                        from system.events.topics import Topics
                        EventBus.publish_from_thread(Topics.RESPONSE_BLOCK, {
                            "src_ip":           src_ip,
                            "dst_ip":           dst_ip,
                            "threat_class":     phantom_class,
                            "confidence":       phantom_confidence,
                            "action":           "BLOCK",
                            "reason":           f"PHANTOM blocked {phantom_class}",
                        })
                    except Exception as _bus_ex:
                        logger.warning("PHANTOM: Failed to publish block event: %s", _bus_ex)
            elif phantom_is_threat:
                if self._tel:
                    self._tel.log.allow_low_conf(src_ip, phantom_class, phantom_confidence)

            # Resolve threshold (single helper — no duplicated config lookups)
            conf_threshold = self._get_conf_threshold()

            from system.core.framework.plugin_base import InspectionFinding
            result = InspectionResult(action=final_action)

            # Always attach phantom metadata to result.metadata (accessible via pipeline)
            result.metadata["phantom"] = record.to_dict()

            # Add InspectionFinding ONLY when we are actually blocking.
            # FIX-FP-03: Previously added a finding for any phantom_is_threat=True
            # even when final_action was ALLOW (conf < threshold). This caused
            # CVAS to announce threats and AutoBlock to fire on every file upload.
            if phantom_is_threat and final_action == InspectionAction.BLOCK:
                severity = "CRITICAL" if phantom_confidence >= conf_threshold else "HIGH"
                result.findings.append(InspectionFinding(
                    plugin_name="PHANTOMPlugin",
                    severity=severity,
                    category=phantom_class,
                    description=(
                        f"PHANTOM detected {phantom_class} "
                        f"(conf={phantom_confidence:.3f}, "
                        f"causal_density={causal_density:.3f})"
                    ),
                    confidence=phantom_confidence,
                    recommends_block=True,
                    metadata=record.to_dict(),
                ))
            elif phantom_is_threat:
                # Low-confidence detection: attach to metadata for analyst review only.
                # Do NOT emit a finding — this avoids false-positive alerts on file uploads.
                logger.info(
                    "[PHANTOM] Low-conf threat (not blocking): %s→%s class=%s conf=%.3f "
                    "(threshold=%.2f causal_density=%.3f)",
                    src_ip, dst_ip, phantom_class,
                    phantom_confidence, conf_threshold, causal_density,
                )
            elif final_action.name == "LOG_ONLY":
                # FIX: LOG_ONLY was previously unhandled — threats fell through all
                # branches with no audit trail.  Now we log to DB event store.
                logger.warning(
                    "[PHANTOM] LOG_ONLY action: %s→%s class=%s conf=%.3f "
                    "(require_legacy_confirm=True, legacy did not confirm)",
                    src_ip, dst_ip, phantom_class, phantom_confidence,
                )
                if self._tel:
                    self._tel.log.inference_result(
                        src_ip, dst_ip, phantom_class,
                        phantom_confidence, True, inference_ms
                    )
                try:
                    from system.events.bus import EventBus
                    from system.events.topics import Topics
                    EventBus.publish_from_thread(Topics.THREAT_DETECTED, {
                        "src_ip":           src_ip,
                        "dst_ip":           dst_ip,
                        "threat_class":     phantom_class,
                        "confidence":       phantom_confidence,
                        "causal_density":   causal_density,
                        "detection_method": "PHANTOM:LOG_ONLY",
                        "severity":         "MEDIUM",
                        "description":      (
                            f"PHANTOM LOG_ONLY: {phantom_class} "
                            f"(conf={phantom_confidence:.3f}, legacy not confirmed)"
                        ),
                    })
                except Exception as _bus_ex:
                    logger.warning("PHANTOM: Failed to publish LOG_ONLY event: %s", _bus_ex)


            # Mirror to context.metadata for downstream enrichers / UBA integration
            if context.metadata is None:
                context.metadata = {}
            context.metadata["phantom"] = record.to_dict()

            return result

    # ── Async wrapper with hard wall-clock timeout ────────────────────────────

    async def inspect_async(
        self,
        context: InspectionContext,
        data: bytes,
    ) -> InspectionResult:
        """Async entry-point called by the async inspection pipeline.

        Runs the synchronous inspect() in a thread pool with a strict
        5-second wall-clock timeout so that slow PyTorch/CTGB inference
        never blocks the event loop for 60+ seconds.

        On timeout → returns ALLOW (fail-open) with a warning finding so the
        proxy can respond to the client within the expected timeframe. The
        pipeline's own 60s wall-clock guard then acts as the last resort.

        Why not asyncio.wait_for(to_thread(...))?
          asyncio.wait_for cancels the *future* but NOT the underlying
          thread — the thread keeps running. Here we just don't await it
          beyond our budget, and the thread finishes naturally in ≤10s
          (bounded by the YARA C-level and PyTorch timeouts inside inspect()).
        """
        import asyncio
        from system.core.framework.plugin_base import InspectionResult, InspectionAction, InspectionFinding

        _PHANTOM_WALL_TIMEOUT = 5.0  # seconds — must be < attack script read timeout (5s)

        loop = asyncio.get_running_loop()
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(None, self.inspect, context, data),
                timeout=_PHANTOM_WALL_TIMEOUT,
            )
            return result
        except asyncio.TimeoutError:
            logger.warning(
                "[PHANTOMPlugin] inspect_async wall-clock timeout (%.1fs) "
                "for %s→%s — returning ALLOW (fail-open)",
                _PHANTOM_WALL_TIMEOUT,
                context.src_ip, context.dst_ip,
            )
            fast_result = InspectionResult(action=InspectionAction.ALLOW)
            fast_result.findings.append(InspectionFinding(
                plugin_name="PHANTOMPlugin",
                severity="LOW",
                category="inspection_timeout",
                description=(
                    f"PHANTOMPlugin wall-clock timeout ({_PHANTOM_WALL_TIMEOUT}s) — "
                    "inspection skipped to preserve latency SLA."
                ),
                confidence=0.0,
                recommends_block=False,
            ))
            return fast_result



    # ── Config helper ────────────────────────────────────────────────

    def _get_conf_threshold(self) -> float:
        """
        Single source of truth for the confidence threshold.
        Reads nested classifier.confidence_threshold first (settings.yaml),
        then the flat phantom_confidence_threshold key (legacy/DB config),
        then falls back to 0.70.
        """
        _clf = self.config.get("classifier", {})
        return float(
            _clf.get("confidence_threshold",
                     self.config.get("phantom_confidence_threshold", 0.70))
        )

    def _fuse_decision(
        self,
        phantom_is_threat: bool,
        phantom_confidence: float,
        causal_density: float,
        legacy_action_str: str,
        phantom_class: str = "",
    ) -> InspectionAction:
        """
        Conservative fusion: BLOCK only when PHANTOM and legacy agree,
        OR when PHANTOM has high confidence AND causal density is elevated.

        Conservative-BLOCK design ensures near-zero false positives in
        inline NGFW mode. Tune via config:
          ids_ips.phantom_confidence_threshold  (default 0.70)
          ids_ips.causal_density_threshold      (default 0.50)
          ids_ips.require_legacy_confirm        (default False)
          ids_ips.classifier.class_thresholds   (per-class overrides)
        """
        _clf = self.config.get("classifier", {})
        conf_threshold    = self._get_conf_threshold()
        density_threshold = _clf.get("causal_density_threshold",
                            self.config.get("causal_density_threshold", 0.50))
        require_legacy    = self.config.get("require_legacy_confirm", False)

        # FIX: Per-class confidence threshold overrides.
        # Some classes (encrypted_c2) trigger on legitimate management traffic.
        # class_thresholds lets us demand higher confidence for noisy classes.
        class_thresholds = _clf.get("class_thresholds", {})
        if phantom_class and phantom_class in class_thresholds:
            class_conf = class_thresholds[phantom_class]
            if class_conf > conf_threshold:
                logger.debug(
                    "[PHANTOM] Using per-class threshold %.2f for '%s' (global=%.2f)",
                    class_conf, phantom_class, conf_threshold
                )
                conf_threshold = class_conf

        legacy_blocks = legacy_action_str in ("BLOCK", "DROP", "DECEIVE")

        if phantom_is_threat and phantom_confidence >= conf_threshold:
            if require_legacy and not legacy_blocks:
                # Soft mode: only warn, don't block
                return InspectionAction.LOG_ONLY
            return InspectionAction.BLOCK

        if (causal_density >= density_threshold and
                phantom_is_threat and
                phantom_confidence >= 0.50):
            return InspectionAction.BLOCK

        if legacy_blocks:
            return InspectionAction.BLOCK

        return InspectionAction.ALLOW


    # ── Stats ─────────────────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        stats: Dict[str, Any] = {
            "total_inspected":     self._total_inspected,
            "total_blocked":       self._total_blocked,
            "total_phantom_threats": self._total_phantom_threats,
            "phantom_backend":     self._phantom.backend if self._phantom else "none",
            "sbe_available":       _SBE_AVAILABLE,
            "ctgb_available":      _CTGB_AVAILABLE,
            "model_available":     _MODEL_AVAILABLE,
        }
        if self._sbe:
            stats["sbe_cache"] = self._sbe.stats()
        if self._ctgb:
            stats["ctgb"] = self._ctgb.stats()
        return stats
