"""
Enterprise bunyanx v2.0 - DNS Security Plugin (Unified, Cached + DART)

Uses the centralized DNSEngine for zero-DB-access per-packet inspection.
All rule matching and config reads happen against in-memory caches.

DART-DNS integration (v2.1):
  Layer 1 — LexicalAnalyzer       (replaces legacy DGADetector for DGA)
  Layer 2 — TemporalResonanceDetector  (replaces simple counter)
  Layer 3 — GraphResonanceEngine   (new: cross-host coordination)
  Fusion  — DARTFusionEngine       (triangulation + XAI evidence)

Legacy DGADetector and DNSTunnelingDetector are kept as fast-path pre-filters
(they still run first; DART runs as a confirming second pass).
"""

import time
import logging
import threading
from collections import defaultdict, deque
import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Tuple

from system.events.bus import EventBus
from system.events.topics import Topics

from system.core.framework.plugin_base import (
    InspectorPlugin,
    InspectionContext,
    InspectionFinding,
    InspectionResult,
    InspectionAction,
)
from modules.dns_security.engine.dns_engine import DNSEngine
from modules.dns_security.models import ActionEnum, DARTAlert
from .legacy.dga_detector import DGADetector
from .legacy.tunneling_detector import DNSTunnelingDetector
from .dart.lexical import LexicalAnalyzer
from .dart.temporal import TemporalResonanceDetector
from .dart.graph import GraphResonanceEngine
from .dart.fusion import DARTFusionEngine
from modules.web_filter.policy.engine import WebFilterEngine
from system.policy.schema import Action as WebFilterAction
from system.database.database import SessionLocal

# ── Module-scoped observability (logging / metrics / tracing) ─────────────────
from modules.dns_security.monitoring import dns_logger, dns_metrics, dns_tracer

logger = logging.getLogger(__name__)

# ── Background eviction interval (seconds) ───────────────────────────────────
_EVICTION_INTERVAL = 300  # 5 minutes

# ---------------------------------------------------------------------------
# Threat Intel Domain Set
#
# ⚠️  IMPORTANT — PRODUCTION TODO:
# This is a SEED/PLACEHOLDER set of 3 example domains for development only.
# In production, this must be populated from a live threat-intel feed via
# `feed_url` in `DNSModuleConfig`. Implement `_load_threat_intel_feed()` below
# and schedule it to run at module startup + every `refresh_interval_hours`.
#
# Recommended feeds:
#   - URLhaus  : https://urlhaus-api.abuse.ch/v1/urls/recent/
#   - OpenPhish: https://openphish.com/feed.txt
#   - Bambenek : http://osint.bambenekconsulting.com/feeds/dga-feed.txt
# ---------------------------------------------------------------------------
_THREAT_INTEL_SEED: frozenset = frozenset({
    "malware-c2.example.com",   # placeholder
    "botnet-gate.xyz",          # placeholder
    "dnscat.evil.tk",           # placeholder
})

# Runtime-mutable set — updated by feed loader at startup
THREAT_INTEL_DOMAINS: frozenset = _THREAT_INTEL_SEED


def _load_threat_intel_feed(feed_url: str, timeout: int = 10) -> frozenset:
    """
    Load threat-intel domains from a remote plaintext feed (one domain per line).

    TODO: Call this at startup and schedule via APScheduler/asyncio every
    `refresh_interval_hours` hours (from DNSModuleConfig).

    Returns the loaded set, or the existing THREAT_INTEL_DOMAINS on failure.
    """
    try:
        import requests  # optional dependency
        response = requests.get(feed_url, timeout=timeout)
        response.raise_for_status()
        domains = frozenset(
            line.strip().lower()
            for line in response.text.splitlines()
            if line.strip() and not line.startswith("#")
        )
        logger.info(f"Threat intel feed loaded: {len(domains)} domains from {feed_url}")
        return domains
    except Exception as e:
        logger.warning(f"Failed to load threat intel feed from {feed_url}: {e}. Using seed list.")
        return THREAT_INTEL_DOMAINS


class DNSSecurityPlugin(InspectorPlugin):
    """
    Unified DNS Security Plugin — Priority 20 (runs early in pipeline).

    All per-packet decisions are made against in-memory caches via DNSEngine.
    No database connection is opened per packet.
    """

    def __init__(self, config: dict = None, block_on_match: bool = True):
        super().__init__(name="dns_security", priority=20)
        self._config = config or {}
        self.block_on_match = block_on_match
        self.engine = DNSEngine()

        # WebFilter integration for DNS Sinkholing
        self.web_filter_engine = WebFilterEngine()

        # Sinkhole IP: config > engine default
        self.sinkhole_ip = (
            self._config.get('sinkhole_ip')
            or self.engine.sinkhole_ip
        )

        # DNS intercept port (for get_netfilter_rules)
        self._intercept_port: int = int(self._config.get('intercept_port', 5353))

        # ── Bounded thread pool for async DB writes ────────────────────────────
        self._stats_pool = ThreadPoolExecutor(
            max_workers=2, thread_name_prefix="dns_stats"
        )

        # ── DART-DNS Engines (tuned from settings.yaml) ──────────────────────
        dart_conf = self._config.get('dart', {})
        self._dart_lexical  = LexicalAnalyzer()
        self._dart_temporal = TemporalResonanceDetector(
            high_freq_window=int(dart_conf.get('high_freq_window', 120)),
            min_queries=int(dart_conf.get('min_queries', 5)),
        )
        self._dart_graph   = GraphResonanceEngine(
            window_size=int(dart_conf.get('window_size', 30)),
            min_hosts_for_alert=int(dart_conf.get('min_hosts_for_alert', 3)),
        )
        self._dart_fusion  = DARTFusionEngine(
            w1=float(dart_conf.get('weight_lexical',  0.50)),
            w2=float(dart_conf.get('weight_temporal', 0.30)),
            w3=float(dart_conf.get('weight_graph',    0.20)),
            theta_fusion=float(dart_conf.get('theta_fusion', 0.55)),
            theta_s1=float(dart_conf.get('theta_s1', 0.60)),
            theta_s2=float(dart_conf.get('theta_s2', 0.45)),
            theta_s3=float(dart_conf.get('theta_s3', 0.45)),
            min_layers_confirm=int(dart_conf.get('min_layers_confirm', 1)),
        )

        # ── Rate limiter: O(1) deque per source IP ─────────────────────────────
        self._query_counts: Dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
        self._state_lock = threading.Lock()

        # ── Background eviction + threat intel ───────────────────────────────
        self._start_eviction_timer()
        self._threat_intel_lock = threading.Lock()
        self._schedule_threat_intel_refresh()

    # ------------------------------------------------------------------
    # Network Orchestration Rules
    # ------------------------------------------------------------------

    def get_netfilter_rules(self) -> Dict[str, list]:
        """Provide OS-level DNS interception rules to the NetworkRuleOrchestrator.

        intercept_port is read from settings.yaml (dns_security.intercept_port).
        """
        rules = {
            'prerouting': [],
            'input': []
        }

        intercept_port = self._intercept_port   # from settings.yaml
        lan_ifaces = []
        try:
            from system.networking.appliance.interface_manager import InterfaceManager
            from system.config.config_manager import ConfigManager
            config = ConfigManager.instance().get_all()
            iface_mgr = InterfaceManager(config)
            lan = iface_mgr.get_role_device("lan")
            if lan:
                lan_ifaces.append(lan)
        except Exception as e:
            logger.warning("Failed to load DNS intercept LAN iface: %s", e)

        rules['input'].append(f"# Allow DNS Intercept Port {intercept_port}")
        rules['input'].append(f"udp dport {intercept_port} accept")
        rules['input'].append(f"tcp dport {intercept_port} accept")

        if lan_ifaces:
            rules['prerouting'].append("# [DNS INTERCEPT: port 53 → internal proxy]")
            for lan in lan_ifaces:
                rules['prerouting'].append(
                    f'iifname "{lan}" meta nfproto ipv4 udp dport 53 redirect to :{intercept_port}'
                )
                rules['prerouting'].append(
                    f'iifname "{lan}" meta nfproto ipv4 tcp dport 53 redirect to :{intercept_port}'
                )

        return rules

    # ------------------------------------------------------------------
    # Background memory eviction (prevents unbounded growth)
    # ------------------------------------------------------------------

    def _start_eviction_timer(self):
        """Daemon thread that periodically prunes stale in-memory state."""
        def _evict():
            while True:
                time.sleep(_EVICTION_INTERVAL)
                try:
                    # Prune rate-limiter entries older than 60s
                    now = time.time()
                    with self._state_lock:
                        stale_ips = [
                            ip for ip, timestamps in self._query_counts.items()
                            if all(now - t > 60.0 for t in timestamps)
                        ]
                        for ip in stale_ips:
                            del self._query_counts[ip]
                    if stale_ips:
                        logger.debug(f"Evicted {len(stale_ips)} stale rate-limiter entries.")

                    # Prune DART temporal state
                    self._dart_temporal.clear_state()

                    # Prune DART graph state
                    self._dart_graph.evict_stale()

                except Exception as e:
                    logger.warning(f"Eviction cycle error: {e}")

        t = threading.Thread(target=_evict, daemon=True, name="dns_eviction")
        t.start()

    def _schedule_threat_intel_refresh(self):
        """SEC-1 FIX: Load threat intel at startup and refresh periodically."""
        global THREAT_INTEL_DOMAINS

        def _refresh_loop():
            global THREAT_INTEL_DOMAINS
            # Initial load
            feed_url = getattr(self.engine, "feed_url", "") or ""
            refresh_hours = getattr(self.engine, "refresh_interval_hours", 6) or 6
            if feed_url:
                loaded = _load_threat_intel_feed(feed_url)
                with self._threat_intel_lock:
                    THREAT_INTEL_DOMAINS = loaded
            else:
                logger.warning(
                    "⚠️  Threat intel feed_url not configured. "
                    "Using placeholder seed list of 3 domains. "
                    "Set feed_url in DNS Security config to enable real threat coverage."
                )
            # Periodic refresh loop
            while True:
                time.sleep(refresh_hours * 3600)
                try:
                    feed_url = getattr(self.engine, "feed_url", "") or ""
                    if feed_url:
                        loaded = _load_threat_intel_feed(feed_url)
                        with self._threat_intel_lock:
                            THREAT_INTEL_DOMAINS = loaded
                        logger.info(f"✅ Threat intel feed refreshed: {len(THREAT_INTEL_DOMAINS)} domains")
                except Exception as exc:
                    logger.warning(f"Threat intel refresh failed: {exc}")

        t = threading.Thread(target=_refresh_loop, daemon=True, name="dns_threat_intel_refresh")
        t.start()

    # ------------------------------------------------------------------
    # Plugin contract
    # ------------------------------------------------------------------

    def can_inspect(self, context: InspectionContext) -> bool:
        return (
            context.protocol == "dns"
            or context.dns is not None           # Phase 10: typed DnsInfo present
            or context.metadata.get("is_dns", False)
            or (context.protocol == "UDP" and context.dst_port == 53)
        )

    # ------------------------------------------------------------------
    # Main inspection flow (no DB access here)
    # ------------------------------------------------------------------

    def inspect(self, context: InspectionContext, data: bytes = b"") -> InspectionResult:
        findings: List[InspectionFinding] = []
        action = InspectionAction.ALLOW

        if not self.engine.is_active:
            return InspectionResult(action=action, findings=findings)

        # Phase 10: prefer typed DnsInfo fields; fall back to metadata
        if context.dns is not None:
            domain = (context.dns.query_name or "").lower().strip()
            qtype  = context.dns.query_type or "A"
        else:
            domain = context.metadata.get("domain", "").lower().strip()
            qtype  = context.metadata.get("query_type", "A")

        if not domain:
            return InspectionResult(action=action, findings=findings)

        # ── 0. DNS Steering (Redirection) ──────────────────────────
        # Check if this domain should be steered to a specific IP
        steer_rule = self.engine.match_steering_rules(domain, context.src_ip)
        if steer_rule:
            return InspectionResult(
                action=InspectionAction.REDIRECT,
                metadata={"redirect_ip": steer_rule.redirect_ip},
                findings=[InspectionFinding(
                    plugin_name=self.name,
                    severity="INFO",
                    category="DNS_STEERED",
                    description=f"Domain steered to {steer_rule.redirect_ip} for policy '{steer_rule.name}'",
                    confidence=1.0,
                    metadata={"rule_name": steer_rule.name, "target_ip": steer_rule.redirect_ip}
                )]
            )

        # ── 1. Rate Limiting ────────────────────────────────────────
        if self.engine.enable_rate_limiting:
            rl_finding = self._check_rate_limit(context.src_ip)
            if rl_finding:
                findings.append(rl_finding)

        # ── 2. Custom Filter Rules (matched from in-memory cache) ───
        matched_rule = self.engine.match_filter_rules(domain)
        if matched_rule is not None:
            # Update stats via bounded thread pool (not thread-per-hit)
            self._stats_pool.submit(self.engine.update_rule_stats, matched_rule.id)

            if matched_rule.action == ActionEnum.ALLOW:
                return InspectionResult(action=InspectionAction.ALLOW, findings=[])

            # BUG-6 FIX: Handle MONITOR action — log finding but don't block.
            if matched_rule.action == ActionEnum.MONITOR:
                findings.append(InspectionFinding(
                    plugin_name=self.name,
                    severity="INFO",
                    category="DNS_FILTER_MONITOR",
                    description=f"Domain matched MONITOR rule '{matched_rule.domain_pattern}': {domain}",
                    confidence=1.0,
                ))
                # Don't return — let pipeline continue (log-only observation)
            else:
                # BLOCK or REDIRECT → Redirect to Sinkhole IP
                return InspectionResult(
                    action=InspectionAction.REDIRECT,
                    metadata={"redirect_ip": self.sinkhole_ip},
                    findings=[InspectionFinding(
                        plugin_name=self.name,
                        severity="CRITICAL",
                        category="DNS_FILTER",
                        description=f"Domain matched DNS filter rule '{matched_rule.domain_pattern}': {domain}",
                        confidence=1.0,
                        metadata={"sinkhole_ip": self.sinkhole_ip}
                    )]
                )

        # ── 2.5 Web Filter Integration (DNS Sinkhole) ───────────────
        # FAIL-2 FIX: Wrap WebFilterEngine.evaluate() in try/except.
        # An unhandled exception here would crash the entire inspection pipeline
        # (fail-closed would block ALL DNS traffic). Gracefully fall through instead.
        try:
            webfilter_action, _ = self.web_filter_engine.evaluate(url=domain, domain=domain)
            if webfilter_action in (WebFilterAction.BLOCK, WebFilterAction.REJECT):
                return InspectionResult(
                    action=InspectionAction.REDIRECT,
                    metadata={"redirect_ip": self.sinkhole_ip},
                    findings=[InspectionFinding(
                        plugin_name=self.name,
                        severity="CRITICAL",
                        category="DNS_WEB_FILTER_SINKHOLE",
                        description=f"Unified DNS Sinkhole: Domain '{domain}' blocked by Web Filter Policy.",
                        confidence=1.0,
                        metadata={"sinkhole_ip": self.sinkhole_ip}
                    )]
                )
        except Exception as wfe:
            logger.error(
                f"WebFilterEngine.evaluate() raised an exception for domain '{domain}': {wfe}. "
                "Falling through to next check to avoid pipeline crash.",
                exc_info=True,
            )

        # ── 3. Threat Intel ────────────────────────────────────────
        if self.engine.enable_threat_intel:
            ti_finding = self._check_threat_intel(domain)
            if ti_finding:
                findings.append(ti_finding)
                if self.block_on_match:
                    action = InspectionAction.BLOCK
                    # LOG-1 FIX: Emit structured audit log for threat intel block
                    dns_logger.log_block(
                        domain=domain,
                        src_ip=context.src_ip,
                        category=ti_finding.category,
                        severity=ti_finding.severity,
                        confidence=ti_finding.confidence,
                    )

        # ── 4. Suspicious TLD ──────────────────────────────────────
        if self.engine.enable_tld_blocking:
            tld_finding = self._check_suspicious_tld(domain)
            if tld_finding:
                findings.append(tld_finding)
                if self.block_on_match:
                    action = InspectionAction.BLOCK

        # ── 5. DGA Detection (Shannon Entropy) ─────────────────────
        if self.engine.enable_dga_detection and DGADetector.is_dga(
            domain, self.engine.dga_entropy_threshold
        ):
            findings.append(InspectionFinding(
                plugin_name=self.name,
                severity="HIGH",
                category="DGA_DETECTED",
                description=f"High-entropy domain detected (possible DGA): {domain}",
                confidence=0.90,
            ))
            if self.block_on_match:
                action = InspectionAction.BLOCK

        # ── 6. DNS Tunneling (legacy structural heuristics) ────────────────
        # BUG-1 FIX: Pass tunneling_query_threshold from config to the detector.
        # Previously this config field was stored/displayed but IGNORED by the detector.
        if self.engine.enable_tunneling_detection:
            tunnel_threshold = getattr(self.engine, "tunneling_query_threshold", 150) or 150
            if DNSTunnelingDetector.is_tunneling(
                domain, qtype, max_total_length=tunnel_threshold
            ):
                findings.append(InspectionFinding(
                    plugin_name=self.name,
                    severity="CRITICAL",
                    category="DNS_TUNNELING",
                    description=f"DNS tunneling characteristics detected: {domain}",
                    confidence=0.95,
                ))
                if self.block_on_match:
                    action = InspectionAction.BLOCK

        # ── 7. DART-DNS Triangulation (v2.1) ───────────────────────────────
        # Respects enable_dart_detection config toggle
        if self.engine.enable_dart_detection:
            self._run_dart_pipeline(domain, context, findings)
            # Check if DART flagged malicious
            if findings and findings[-1].category == "DART_MALICIOUS":
                if self.block_on_match:
                    action = InspectionAction.BLOCK

        # ── Final query telemetry ──────────────────────────────────────────
        dns_metrics.record_query(action=action.name, protocol="UDP")
        if action == InspectionAction.BLOCK and findings:
            top = findings[-1]   # most recent / most severe
            dns_metrics.record_block(category=top.category, severity=top.severity)
            dns_logger.log_block(
                domain=domain,
                src_ip=context.src_ip,
                category=top.category,
                severity=top.severity,
                confidence=top.confidence,
            )
            # Fire global event for Audio/SSE and cross-process dispatchers
            payload = {
                "domain": domain,
                "src_ip": context.src_ip,
                "category": top.category,
                "severity": top.severity,
                "action": action.name
            }
            try:
                EventBus.publish_from_thread(Topics.DNS_THREAT, payload)
            except Exception as e:
                logger.debug("Failed to dispatch DNS live event: %s", e)

        return InspectionResult(action=action, findings=findings)

    # ------------------------------------------------------------------
    # DART Pipeline (extracted for clarity + config gating)
    # ------------------------------------------------------------------

    def _run_dart_pipeline(
        self,
        domain: str,
        context: InspectionContext,
        findings: List[InspectionFinding],
    ):
        """Run the full DART-DNS triangulation pipeline."""
        with dns_tracer.dart_pipeline(domain, context.src_ip):

            # Layer 1 — Lexical
            t0 = time.perf_counter()
            with dns_tracer.span("dart.lexical"):
                s1_score, s1_comps = self._dart_lexical.analyze(domain)
            dns_metrics.record_dart_layer_latency("lexical", time.perf_counter() - t0)

            # Layer 2 — Temporal
            t0 = time.perf_counter()
            with dns_tracer.span("dart.temporal"):
                s2_sig = self._dart_temporal.analyze(context.src_ip, domain)
            dns_metrics.record_dart_layer_latency("temporal", time.perf_counter() - t0)

            # Layer 3 — Graph
            t0 = time.perf_counter()
            with dns_tracer.span("dart.graph"):
                s3_sig = self._dart_graph.analyze(context.src_ip, domain)
            dns_metrics.record_dart_layer_latency("graph", time.perf_counter() - t0)

            # Fusion
            t0 = time.perf_counter()
            with dns_tracer.span("dart.fusion"):
                dart_dec = self._dart_fusion.fuse(
                    domain=domain,
                    s1_score=s1_score,
                    s1_components=s1_comps,
                    s2_score=s2_sig.score,
                    s2_info={
                        "cv": s2_sig.cv,
                        "mean_interval": s2_sig.mean_interval,
                        "variance": s2_sig.variance,
                        "query_count": s2_sig.query_count,
                    },
                    s3_score=s3_sig.score,
                    s3_info={"unique_hosts": s3_sig.unique_hosts},
                )
            dns_metrics.record_dart_layer_latency("fusion", time.perf_counter() - t0)

            # Metrics + Structured log
            dns_metrics.record_dart_decision(
                is_malicious=dart_dec.is_malicious,
                resonance_score=dart_dec.resonance_score,
                layers_fired=dart_dec.layers_triggered,
            )
            dns_logger.log_dart_decision(
                domain=domain,
                src_ip=context.src_ip,
                dart_decision=dart_dec,
                s1_score=s1_score,
                s2_score=s2_sig.score,
                s3_score=s3_sig.score,
            )

            if dart_dec.is_malicious:
                severity = "CRITICAL" if dart_dec.resonance_score >= 0.80 else "HIGH"
                findings.append(InspectionFinding(
                    plugin_name=self.name,
                    severity=severity,
                    category="DART_MALICIOUS",
                    description=(
                        f"DART confirmed malicious domain: {domain} "
                        f"(R={dart_dec.resonance_score}, "
                        f"layers_fired={dart_dec.layers_triggered})"
                    ),
                    confidence=dart_dec.resonance_score,
                    metadata={"evidence": dart_dec.evidence},
                ))

                # Persist DART alert to DB for SOC review + predictive_ai
                self._stats_pool.submit(
                    self._persist_dart_alert,
                    domain, context.src_ip, dart_dec,
                    s1_score, s2_sig.score, s3_sig.score,
                )

    # ------------------------------------------------------------------
    # DART Alert persistence (runs in bounded thread pool)
    # ------------------------------------------------------------------

    @staticmethod
    def _persist_dart_alert(
        domain: str, src_ip: str, dart_dec, s1: float, s2: float, s3: float
    ):
        """Write DART malicious decision to the dart_alerts DB table."""
        try:
            with SessionLocal() as db:
                alert = DARTAlert(
                    domain=domain,
                    src_ip=src_ip,
                    resonance_score=dart_dec.resonance_score,
                    layers_fired=dart_dec.layers_triggered,
                    s1_score=s1,
                    s2_score=s2,
                    s3_score=s3,
                    verdict=True,
                    evidence=dart_dec.evidence,
                    reviewed=False,
                )
                db.add(alert)
                db.commit()
        except Exception as e:
            logger.warning(f"Failed to persist DART alert for {domain}: {e}")

    # ------------------------------------------------------------------
    # Internal helpers (stateful, no DB access)
    # ------------------------------------------------------------------

    def _check_rate_limit(self, src_ip: str):
        """PERF-3 FIX: Optimized rate limiter using deque.
        Simply appends current timestamp and counts recent entries.
        deque maxlen auto-evicts oldest, reducing lock contention.
        """
        now = time.time()
        limit = self.engine.rate_limit_per_minute
        with self._state_lock:
            dq = self._query_counts[src_ip]
            dq.append(now)
            # Count entries within the last 60 seconds
            cutoff = now - 60.0
            count = sum(1 for t in dq if t >= cutoff)

        if count > limit:
            return InspectionFinding(
                plugin_name=self.name,
                severity="MEDIUM",
                category="DNS_RATE_LIMIT",
                description=f"Excessive DNS queries from {src_ip}: {count} in 60 s (limit {limit})",
                confidence=0.90,
            )
        return None

    def _check_threat_intel(self, domain: str):
        if domain in THREAT_INTEL_DOMAINS:
            return InspectionFinding(
                plugin_name=self.name,
                severity="CRITICAL",
                category="THREAT_INTEL",
                description=f"Domain matches threat-intel feed: {domain}",
                confidence=0.98,
            )
        # Parent-domain suffix match
        parts = domain.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in THREAT_INTEL_DOMAINS:
                return InspectionFinding(
                    plugin_name=self.name,
                    severity="HIGH",
                    category="THREAT_INTEL",
                    description=f"Domain {domain} is a subdomain of threat-intel entry {parent}",
                    confidence=0.90,
                )
        return None

    def _check_suspicious_tld(self, domain: str):
        for tld in self.engine.suspicious_tlds:
            if domain.endswith(tld):
                return InspectionFinding(
                    plugin_name=self.name,
                    severity="MEDIUM",
                    category="SUSPICIOUS_TLD",
                    description=f"Suspicious TLD '{tld}' in domain: {domain}",
                    confidence=0.75,
                )
        return None
