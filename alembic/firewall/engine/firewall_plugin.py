"""
Enterprise bunyanx — Firewall Inspector Plugin

Bridges the bunyanx inspection pipeline to the full firewall policy engine:
  UnifiedEvaluator (GeoIP → ACL → App Control) + StateTracker

Priority: HIGHEST — the firewall is the first line of defence.
ESTABLISHED connections bypass the evaluator for performance.

Improvements:
  - CircuitBreaker wraps evaluation to prevent pipeline-wide failure
  - StateTracker.start_cleanup_task() prevents unbounded memory growth
  - get_stats() exposes live state table + circuit breaker health
"""

from __future__ import annotations

import logging
import threading
import time
import asyncio
from typing import Optional, Dict

from system.events.bus import EventBus
from system.events.topics import Topics
from system.core.framework.plugin_base import (
    InspectorPlugin, InspectionContext, InspectionResult,
    InspectionFinding, InspectionAction, PluginPriority,
)
from system.core.circuit_breaker import breaker_registry
from modules.firewall.engine.state_tracker import TCPState
from modules.firewall.config.validator import validate_firewall_config

logger = logging.getLogger(__name__)


class FirewallPlugin(InspectorPlugin):
    """
    Stateful Next-Gen Firewall plugin.

    Pipeline per packet:
    1. StateTracker — ESTABLISHED connections are allowed instantly.
    2. UnifiedEvaluator — GeoIP → ACL (L3/4) → AppControl (L7).
    3. StateTracker update — record new ALLOW'd connections.
    """

    PLUGIN_NAME = "firewall"

    def __init__(
        self,
        db_manager=None,
        config=None,
        logger: Optional[logging.Logger] = None,
    ):
        super().__init__(
            name=self.PLUGIN_NAME,
            priority=PluginPriority.HIGHEST,
            logger=logger or logging.getLogger(__name__),
        )
        self.db_manager = db_manager
        self.config = config or {}

        # M9: Validate config schema at startup — fail fast on bad values
        try:
            self._validated_config = validate_firewall_config(self.config)
        except ValueError as cfg_err:
            self.logger.error("FirewallPlugin: INVALID CONFIG — %s", cfg_err)
            self._validated_config = None  # Will use raw defaults

        self._is_monitor_mode = str(self.config.get("mode", "enforce")).lower() == "monitor"
        self._state_tracker = None
        self._evaluator = None
        self._eval_session = None      # DB session for evaluator — closed on reload
        self._eval_lock = threading.Lock()  # protects lazy-init of _evaluator

        # CircuitBreaker: if evaluation fails repeatedly, fail-open to avoid
        # blocking the entire inspection pipeline.
        self._breaker = breaker_registry.get_or_create(
            "firewall",
            fail_threshold=10,
            timeout_s=30.0,
            fail_mode="closed",    # fail-closed = block traffic when breaker OPEN
        )

        try:
            from modules.firewall.engine.state_tracker import StateTracker
            tracker_timeout = int(self.config.get("state_timeout_seconds", 300))
            tracker_capacity = int(self.config.get("max_active_connections", 100000))
            self._state_tracker = StateTracker(timeout_seconds=tracker_timeout, max_capacity=tracker_capacity)
            # StateTracker capacity is now enforced to prevent memory exhaustion DoS
            self.logger.info(f"FirewallPlugin: StateTracker initialized (Timeout: {tracker_timeout}s)")
        except Exception as exc:
            self.logger.warning("FirewallPlugin: StateTracker init failed: %s", exc)


    def get_netfilter_rules(self) -> Dict[str, list]:
        """Build nftables INPUT and FORWARD rules from settings.yaml.

        ════════════════════════════════════════════════════════════════
         SINGLE SOURCE OF TRUTH FOR ALL PORT CONFIGURATION
         ────────────────────────────────────────────────────────────────
         To open / close / change a port on this firewall:
           → Edit modules/firewall/config/settings.yaml only.
           → Restart the system — changes are applied automatically.

         Port sections in settings.yaml:
           management_ports  = INPUT ports always open (SSH, HTTPS, mgmt UI)
           dev_ports         = INPUT ports open when dev_ports_enabled: true
           custom_ports      = any port, any protocol, input or forward direction

         This method is called by the NetfilterManager and produces the
         full nftables ruleset. No other place in the codebase should
         insert port-open rules independently.
        ════════════════════════════════════════════════════════════════
        """
        rules: Dict[str, list] = {'input': [], 'forward': []}

        # ── INPUT: stateful shortcut ──────────────────────────────────────────
        rules['input'].extend([
            "# [FIREWALL BASE INPUT]",
            "ct state established,related accept",
            'iif "lo" accept',
            'ip protocol icmp accept',
            'iifname "wg0" accept',
        ])

        # ── INPUT: management ports (always open) ─────────────────────────────
        mgmt_ports = [
            int(p) for p in self.config.get('management_ports', [])
        ]
        if mgmt_ports:
            port_list = ', '.join(str(p) for p in sorted(mgmt_ports))
            rules['input'].append(f"# Management ports: always allowed")
            rules['input'].append(f"tcp dport {{ {port_list} }} accept")

        # ── INPUT: dev/proxy ports (when enabled) ─────────────────────────────
        dev_enabled = self.config.get('dev_ports_enabled', False)
        dev_ports = [
            int(p) for p in self.config.get('dev_ports', [])
        ] if dev_enabled else []
        if dev_ports:
            port_list = ', '.join(str(p) for p in sorted(dev_ports))
            rules['input'].append(f"# Dev/proxy ports (dev_ports_enabled=true)")
            rules['input'].append(f"tcp dport {{ {port_list} }} accept")

        # ── INPUT: dynamic custom ports from settings.yaml ─────────────────────
        custom_ports = self.config.get("custom_ports", [])
        for cp in custom_ports:
            cp_enabled = cp.get("enabled", True)
            if not cp_enabled:
                continue
            
            cp_dir = str(cp.get("direction", "input")).lower()
            if cp_dir in ("input", "both"):
                cp_name = cp.get("name", "CustomPort")
                cp_port = int(cp.get("port", 0))
                cp_proto = str(cp.get("protocol", "tcp")).lower()
                
                if cp_port > 0:
                    protos = ["tcp", "udp"] if cp_proto == "both" else [cp_proto]
                    for pr in protos:
                        rules['input'].append(f"# Custom Port: {cp_name} ({cp_dir})")
                        rules['input'].append(f"{pr} dport {cp_port} accept")

        # ── Resolve interface names dynamically ───────────────────────────────
        lan_iface, wan_iface = None, None
        try:
            from system.networking.appliance.interface_manager import InterfaceManager
            iface_mgr = InterfaceManager(self.config)
            lan_iface = iface_mgr.get_role_device("lan")
            wan_iface = iface_mgr.get_role_device("wan")
        except Exception:
            pass

        # ── FORWARD chain ─────────────────────────────────────────────────────
        rules['forward'].append("# [FIREWALL FORWARD]")

        # 1. Always allow return/established traffic in FORWARD
        rules['forward'].append("ct state established,related accept")

        # 2. LAN → WAN (outbound internet access)
        if lan_iface and wan_iface:
            rules['forward'].append(f"# LAN -> WAN outbound")
            rules['forward'].append(f'iifname "{lan_iface}" oifname "{wan_iface}" accept')

        # 3. LAN → LAN (firewall-initiated traffic to LAN servers, e.g. 10.10.0.50)
        if lan_iface:
            rules['forward'].append(f"# LAN -> LAN (intra-LAN and firewall-to-server)")
            rules['forward'].append(f'iifname "{lan_iface}" oifname "{lan_iface}" accept')
            rules['forward'].append(f"# VPN (wg0) -> LAN forwarding")
            rules['forward'].append(f'iifname "wg0" oifname "{lan_iface}" accept')

        if wan_iface:
            rules['forward'].append(f"# VPN (wg0) -> WAN forwarding")
            rules['forward'].append(f'iifname "wg0" oifname "{wan_iface}" accept')

        # 4. WAN → LAN inbound services (all configured forward/both ports)
        inbound_tcp_ports = list(mgmt_ports) + list(dev_ports)
        inbound_udp_ports = []
        
        # 5. Process Custom Ports for FORWARD dynamically from settings.yaml
        for cp in custom_ports:
            if not cp.get("enabled", True):
                continue
            cp_dir = str(cp.get("direction", "input")).lower()
            if cp_dir in ("forward", "both"):
                cp_port = int(cp.get("port", 0))
                cp_proto = str(cp.get("protocol", "tcp")).lower()
                if cp_port > 0:
                    if cp_proto in ("tcp", "both") and cp_port not in inbound_tcp_ports:
                        inbound_tcp_ports.append(cp_port)
                    if cp_proto in ("udp", "both") and cp_port not in inbound_udp_ports:
                        inbound_udp_ports.append(cp_port)
                        
        if wan_iface and lan_iface:
            if inbound_tcp_ports:
                port_list = ', '.join(str(p) for p in sorted(set(inbound_tcp_ports)))
                rules['forward'].append(f"# WAN -> LAN inbound TCP services")
                rules['forward'].append(
                    f'iifname "{wan_iface}" oifname "{lan_iface}" '
                    f'tcp dport {{ {port_list} }} accept'
                )
            if inbound_udp_ports:
                port_list = ', '.join(str(p) for p in sorted(set(inbound_udp_ports)))
                rules['forward'].append(f"# WAN -> LAN inbound UDP services")
                rules['forward'].append(
                    f'iifname "{wan_iface}" oifname "{lan_iface}" '
                    f'udp dport {{ {port_list} }} accept'
                )

        return rules




    def can_inspect(self, context: InspectionContext) -> bool:
        return context.protocol in ("TCP", "UDP", "ICMP")

    async def initialize(self):
        """Called by ModuleManager after registration — start background tasks."""
        if self._state_tracker and hasattr(self._state_tracker, 'start_cleanup_task'):
            await self._state_tracker.start_cleanup_task(interval_s=60)
            self.logger.info("FirewallPlugin: StateTracker cleanup task started")

    def inspect(
        self,
        context: InspectionContext,
        data: bytes = b"",
    ) -> InspectionResult:
        start = time.time()
        result = InspectionResult(action=InspectionAction.ALLOW)

        src_ip   = context.src_ip or "0.0.0.0"
        dst_ip   = context.dst_ip or "0.0.0.0"
        src_port = context.src_port or 0
        dst_port = context.dst_port or 0
        proto    = context.protocol or "any"

        # 1. Stateful shortcut — established connections bypass deep evaluation
        # Phase 10: tcp_flags may be in context.metadata (legacy) or derived
        # from context.http.method for HTTP/HTTPS traffic.
        tcp_flags = context.metadata.get("tcp_flags", "") if context.metadata else ""
        if self._state_tracker:
            conn_state = self._state_tracker.get_or_update_state(
                src_ip, src_port, dst_ip, dst_port, proto, tcp_flags=tcp_flags
            )
            if conn_state == TCPState.ESTABLISHED:
                result.processing_time_ms = (time.time() - start) * 1000
                return result   # fast path

        # 2. Circuit Breaker gate — if evaluator has failed too many times,
        #    block all traffic immediately (fail_mode=closed) without retrying.
        if self._breaker.is_open():
            self.logger.warning("FirewallPlugin: CircuitBreaker OPEN — blocking traffic (fail-closed)")
            result.action = InspectionAction.BLOCK
            result.findings.append(InspectionFinding(
                plugin_name=self.name,
                severity="CRITICAL",
                category="Firewall",
                description="Circuit breaker tripped — evaluator unavailable (fail-closed)",
                confidence=1.0,
                recommends_block=True,
                metadata={"circuit_state": "OPEN"},
            ))
            result.processing_time_ms = (time.time() - start) * 1000
            return result

        # 3. Full policy evaluation with circuit breaker tracking
        try:
            decision = self._evaluate(context, src_ip, dst_ip, src_port, dst_port, proto)
            self._breaker._on_success()
        except Exception as exc:
            self._breaker._on_failure(exc)
            self.logger.error("FirewallPlugin evaluation error: %s", exc, exc_info=True)
            # SECURITY: Fail-closed — block traffic when evaluator crashes.
            # An attacker MUST NOT be able to bypass the firewall by crashing the evaluator.
            result.action = InspectionAction.BLOCK
            result.findings.append(InspectionFinding(
                plugin_name=self.name,
                severity="CRITICAL",
                category="Firewall",
                description=f"Evaluation failure (fail-closed): {exc}",
                confidence=1.0,
                recommends_block=True,
                metadata={"error": str(exc)},
            ))
            result.processing_time_ms = (time.time() - start) * 1000
            return result

        action_str = decision.get("action", "ALLOW").upper()

        if action_str in ("DROP", "BLOCK", "REJECT"):
            is_monitor = self._is_monitor_mode
            
            if is_monitor:
                result.action = InspectionAction.LOG_ONLY
            else:
                result.action = InspectionAction.BLOCK
                
            result.findings.append(InspectionFinding(
                plugin_name=self.name,
                severity="HIGH",
                category="Firewall",
                description=decision.get("reason", "Blocked by firewall policy"),
                confidence=decision.get("confidence", 1.0),
                recommends_block=not is_monitor,
                metadata={
                    "rule":     decision.get("rule_name", ""),
                    "src_ip":   src_ip,
                    "dst_ip":   dst_ip,
                    "dst_port": dst_port,
                    "proto":    proto,
                }
            ))
            
            try:
                # ── IMPORTANT: Only publish RESPONSE_BLOCK for EXPLICIT rule matches ──
                # Do NOT publish for Default-DROP (rule_name="Default-DROP" or "ACLEngine").
                #
                # Why: IPBlocklistManager subscribes to RESPONSE_BLOCK and auto-blocks
                # the src_ip. If we publish for every Default-DROP, then ANY new IP that
                # connects (e.g. the reverse-proxy health-check to 10.10.0.50) gets
                # added to the blocklist → backends marked UNHEALTHY → all traffic stops.
                #
                # Only explicit admin rules, WAF blocks, and DLP violations should
                # trigger auto-blocking via this event.
                _rule_name = decision.get("rule_name", "") or ""
                _is_default_drop = _rule_name in ("", "Default-DROP", "ACLEngine", "Default-ALLOW")
                if not _is_default_drop:
                    EventBus.publish_from_thread(Topics.RESPONSE_BLOCK, {
                        "src_ip":    src_ip,
                        "dst_ip":    dst_ip,
                        "proto":     proto,
                        "rule_name": _rule_name,
                        "reason":    decision.get("reason", ""),
                        "severity":  "HIGH",
                        "description": f"Firewall blocked {src_ip} → {dst_ip}",
                    })
            except Exception as e:
                self.logger.debug("Failed to dispatch FW event: %s", e)
                
        elif action_str == "LOG":
            result.action = InspectionAction.LOG_ONLY

        # 3. Update state table for allowed connections only
        if result.action == InspectionAction.ALLOW and self._state_tracker:
            self._state_tracker.get_or_update_state(
                src_ip, src_port, dst_ip, dst_port, proto, tcp_flags=tcp_flags
            )

        result.metadata["firewall"] = {
            "action":    action_str,
            "rule_name": decision.get("rule_name", ""),
            "reason":    decision.get("reason", ""),
        }
        result.processing_time_ms = (time.time() - start) * 1000
        return result

    # ── Private helpers ───────────────────────────────────────────────────────

    def _get_configured_service_ports(self) -> set:
        """Collect all configured service ports from settings.yaml."""
        ports = set()
        for p in self.config.get("management_ports", []):
            try:
                ports.add(int(p))
            except (ValueError, TypeError):
                pass
        if self.config.get("dev_ports_enabled", False):
            for p in self.config.get("dev_ports", []):
                try:
                    ports.add(int(p))
                except (ValueError, TypeError):
                    pass
        for cp in self.config.get("custom_ports", []):
            if cp.get("enabled", True):
                try:
                    p = int(cp.get("port", 0))
                    if p > 0:
                        ports.add(p)
                except (ValueError, TypeError):
                    pass
        return ports

    def _evaluate(self, context, src_ip, dst_ip, src_port, dst_port, proto) -> dict:
        """Run UnifiedEvaluator, lazy-initializing DB session if needed.

        Config-Driven Default Policy Override:
          If the evaluator returns a DEFAULT DROP (no explicit rule matched in DB)
          AND:
            1. The source IP is whitelisted in ip_whitelist.yaml (IPWhitelistManager), OR
            2. The target port is a configured service/VIP port in settings.yaml, OR
            3. The traffic has active VIP metadata or HTTP context attached,
          we permit the traffic through the L3 firewall layer so it enters deep
          inspection (WAF, IDS/IPS, Malware AV, DLP).

          Explicit admin BLOCK rules in DB are ALWAYS strictly enforced.
        """
        ctx_dict = {
            "src_ip":    src_ip,
            "dst_ip":    dst_ip,
            "src_port":  src_port,
            "dst_port":  dst_port,
            "protocol":  proto,
            "interface": getattr(context, "interface", "any"),
            "app_id":    (context.metadata or {}).get("app_id"),
            "domain":    (context.metadata or {}).get("domain"),
        }
        decision = self._get_evaluator().evaluate(ctx_dict)

        # ── Config-Driven default-DROP override ────────────────────────────────
        if decision.get("action", "ALLOW").upper() in ("BLOCK", "DROP", "REJECT"):
            rule_name = decision.get("rule_name") or ""
            is_default_drop = (not rule_name or rule_name in ("ACLEngine", "Default-DROP"))
            if is_default_drop and src_ip and src_ip not in ("0.0.0.0", ""):
                try:
                    from modules.firewall.engine.ip_whitelist_manager import get_whitelist_manager
                    is_whitelisted = get_whitelist_manager().is_whitelisted(src_ip)
                    configured_ports = self._get_configured_service_ports()
                    is_service_port = int(dst_port or 0) in configured_ports or bool((context.metadata or {}).get("vip_name"))
                    
                    if is_whitelisted or is_service_port:
                        reason = "Whitelisted Network / Host" if is_whitelisted else "Configured Service / VIP Port"
                        self.logger.debug(
                            "FirewallPlugin: Default-DROP bypassed for src=%s dst_port=%s (reason=%s)",
                            src_ip, dst_port, reason
                        )
                        return {
                            "action":     "ALLOW",
                            "confidence": 1.0,
                            "reason":     f"Config-Driven Allow: {reason} (bypassed for deep inspection)",
                            "rule_name":  "Config_Service_Bypass",
                        }
                except Exception as _ex:
                    self.logger.debug("FirewallPlugin: whitelist lookup error: %s", _ex)

        return decision


    def _get_evaluator(self):
        """Lazy-load UnifiedEvaluator with a DB session from db_manager.
        
        Thread-safe via _eval_lock to prevent concurrent lazy-init from
        creating multiple evaluator instances.
        """
        if self._evaluator is not None:
            return self._evaluator
        with self._eval_lock:
            # Double-checked locking
            if self._evaluator is not None:
                return self._evaluator
            try:
                from modules.firewall.engine.evaluator import UnifiedEvaluator
                db_session = None
                if self.db_manager:
                    db_session = self.db_manager.sync_session()
                    self._eval_session = db_session  # track for cleanup
                self._evaluator = UnifiedEvaluator(db_session, config=self.config)
                self.logger.info("FirewallPlugin: UnifiedEvaluator loaded with %d rules",
                                 len(self._evaluator.acl_engine.rules))
            except Exception as exc:
                self.logger.error("FirewallPlugin: Failed to load UnifiedEvaluator: %s", exc)
                # Secure fallback — block all (fail-closed)
                class _PassThrough:
                    def evaluate(self, ctx):
                        return {"action": "DROP", "confidence": 1.0,
                                "reason": "Evaluator unavailable - Fail Closed", "rule_name": "System_Fail_Closed"}
                self._evaluator = _PassThrough()
        return self._evaluator

    def reload_rules(self):
        """Hot-reload rules from DB (call after rule changes via API)."""
        with self._eval_lock:
            # Close the old DB session to prevent leaks
            if self._eval_session is not None:
                try:
                    self._eval_session.close()
                except Exception as exc:
                    self.logger.debug("FirewallPlugin: session close error on reload: %s", exc)
                self._eval_session = None
            self._evaluator = None   # force re-init on next packet
        self.logger.info("FirewallPlugin: rules reload scheduled")

    def get_stats(self) -> dict:
        """Return live state table stats + circuit breaker health."""
        state_stats = (
            self._state_tracker.get_stats()
            if self._state_tracker else {"active_connections": 0}
        )
        breaker_stats = self._breaker.stats
        return {
            **state_stats,
            "circuit_breaker": {
                "state": breaker_stats.current_state.value,
                "consecutive_failures": breaker_stats.consecutive_failures,
                "error_rate": round(breaker_stats.error_rate, 3),
            },
        }
