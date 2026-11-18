#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════
SSL Policy Engine - Inspection Decision Maker
═══════════════════════════════════════════════════════════════════

Determines whether to inspect or bypass SSL/TLS connections based on:
- Domain bypass lists (wildcard patterns, pre-compiled at init)
- IP / CIDR bypass lists
- Certificate pinning detection
- Application identification
- User/group policies

Author: Enterprise Security Team
"""

import asyncio
import ipaddress
import logging
import re
from pathlib import Path
from typing import Dict, Any, List, Optional, Pattern
from enum import Enum

logger = logging.getLogger(__name__)

# Path to this module's own config file (relative to project root)
_MODULE_CONFIG = Path(__file__).parent.parent / "config" / "ssl.yaml"


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------
def _load_module_config() -> Dict[str, Any]:
    """
    Load ssl.yaml from the module's config directory.
    Returns the 'ssl_inspection' block, or an empty dict if unavailable.
    """
    try:
        import yaml  # type: ignore
        with open(_MODULE_CONFIG, "r") as f:
            data = yaml.safe_load(f) or {}
        return data.get("ssl_inspection", {})
    except FileNotFoundError:
        logger.debug("ssl.yaml not found — using base.yaml values only")
        return {}
    except Exception as exc:
        logger.warning("Could not load ssl.yaml: %s", exc)
        return {}


# ---------------------------------------------------------------------------
# Domain pattern compiler  (H1 fix: safe wildcard → regex, no injection)
# ---------------------------------------------------------------------------
def _compile_domain_pattern(pattern: str) -> Pattern[str]:
    """
    Convert a domain pattern (possibly containing '*') to a compiled regex.

    Security rules:
    - All regex metacharacters in the pattern are escaped FIRST.
    - Only '*' has special meaning: it is replaced with '[^.]*'
      (matches any sub-label but NOT dots — prevents '*.com' matching 'evil.foo.com').
    - Match is case-insensitive and anchored at both ends.
    """
    escaped = re.escape(pattern)
    # re.escape turns '*' → r'\*'; replace that literal with [^.]* (no dot crossing)
    safe_regex = escaped.replace(r"\*", r"[^.]*")
    return re.compile(f"^{safe_regex}$", re.IGNORECASE)


# ---------------------------------------------------------------------------
# CIDR / IP helper  (H6 fix: proper subnet matching)
# ---------------------------------------------------------------------------
# Union type for both IPv4 and IPv6 networks
_IPNetwork = (ipaddress.IPv4Network, ipaddress.IPv6Network)


def _build_ip_networks(raw_list: List[str]):
    """
    Parse a list of IP strings / CIDR ranges into IPv4Network or IPv6Network objects.
    Invalid entries are logged and skipped.
    """
    networks = []
    for entry in raw_list:
        if not entry:
            continue
        entry_str = str(entry).strip()
        if entry_str in ("*", "any", "all"):
            networks.append(ipaddress.ip_network("0.0.0.0/0"))
            networks.append(ipaddress.ip_network("::/0"))
            continue
        try:
            # ip_network handles both IPv4 and IPv6
            # strict=False allows host bits (192.168.1.5/24 → 192.168.1.0/24)
            networks.append(ipaddress.ip_network(entry_str, strict=False))
        except ValueError:
            logger.warning("Invalid IP/CIDR in bypass_ips — skipping: %s", entry_str)
    return networks


def _ip_in_networks(ip: str, networks: list) -> bool:
    """Return True if *ip* belongs to any network in *networks* (IPv4 or IPv6)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in networks)


# ---------------------------------------------------------------------------
# SSL action enum
# ---------------------------------------------------------------------------
class SSLAction(Enum):
    """Possible outcomes of the SSL policy decision."""
    INSPECT = "inspect"    # Full MITM interception
    BYPASS  = "bypass"     # Pass-through without decryption
    BLOCK   = "block"      # Drop the connection
    MONITOR = "monitor"    # Log only, no interception


# ---------------------------------------------------------------------------
# Policy engine
# ---------------------------------------------------------------------------
class SSLPolicyEngine:
    """
    SSL Policy Engine

    Makes decisions about SSL/TLS inspection for each connection.

    Fixes applied vs previous version:
    * H1  — Domain wildcard regex is safe (no injection via pattern metacharacters).
    * H5  — asyncio tasks are tracked and given error callbacks.
    * H6  — IP bypass supports CIDR ranges via ipaddress module.
    * M3  — Domain / pinned patterns are pre-compiled once at __init__ time.
    * M5  — block_expired_certs and block_legacy_tls are read and enforced.
    * M4  — Structured log fields for AI/SIEM consumption.
    """

    def __init__(self, config: dict, ebpf_manager=None, event_sink=None):
        self.config       = config
        self.ebpf_manager = ebpf_manager
        self.event_sink   = event_sink

        # Smart-merge: mod_ssl (ssl.yaml) is the single source of truth for defaults.
        # base_ssl overrides scalars; lists in mod_ssl are preserved unless explicitly overridden with non-empty lists.
        base_ssl = config.get('ssl_inspection', {})
        mod_ssl  = _load_module_config()
        self.ssl_config = dict(mod_ssl)
        for k, v in base_ssl.items():
            if isinstance(v, list) and not v and k in mod_ssl and mod_ssl[k]:
                continue
            self.ssl_config[k] = v

        # Global switch
        self.enabled: bool = self.ssl_config.get('enabled', True)

        # ── Bypass lists ────────────────────────────────────────────────
        raw_bypass_domains: List[str] = self.ssl_config.get('bypass_domains', [])
        raw_bypass_ips:     List[str] = self.ssl_config.get('bypass_ips', [])

        # M3: Pre-compile domain patterns once (H1: safe regex)
        self._bypass_domain_patterns: List[Pattern[str]] = [
            _compile_domain_pattern(p) for p in raw_bypass_domains
        ]
        self._bypass_domain_raw = raw_bypass_domains  # kept for dynamic add/remove

        # H6: Pre-parse IP bypass list into networks for CIDR support
        self._bypass_networks: List[ipaddress.IPv4Network] = _build_ip_networks(raw_bypass_ips)
        self._bypass_ips_raw = raw_bypass_ips  # kept for dynamic add/remove

        self.bypass_categories: List[str] = self.ssl_config.get('bypass_categories', [])

        # ── Certificate pinning ─────────────────────────────────────────
        self.detect_pinning: bool = self.ssl_config.get('detect_pinning', True)
        try:
            self.pinning_action = SSLAction(self.ssl_config.get('pinning_action', 'bypass'))
        except ValueError:
            logger.warning("Invalid pinning_action in config — defaulting to BYPASS")
            self.pinning_action = SSLAction.BYPASS

        _default_pinned = [
            '*.apple.com', '*.icloud.com',
            '*.google.com', '*.googleapis.com',
            'api.twitter.com', 'api.facebook.com',
            '*.whatsapp.net', '*.whatsapp.com',
            '*.banking.app',
        ]
        raw_pinned: List[str] = self.ssl_config.get('pinned_domains', _default_pinned)

        # M3: Pre-compile pinned domain patterns
        self._pinned_patterns: List[Pattern[str]] = [
            _compile_domain_pattern(p) for p in raw_pinned
        ]
        self._pinned_raw = raw_pinned

        # ── Security hardening flags (M5) ───────────────────────────────
        sec = self.ssl_config.get('security', {})
        self.block_expired_certs: bool = sec.get('block_expired_certs', True)
        self.block_legacy_tls:    bool = sec.get('block_legacy_tls',    True)

        # ── Statistics ──────────────────────────────────────────────────
        self.stats: Dict[str, int] = {
            'total_decisions': 0,
            'inspected':  0,
            'bypassed':   0,
            'blocked':    0,
            'monitored':  0,
        }

        # H5: Track background tasks to prevent silent GC
        self._bg_tasks: set = set()

        # Database policy cache initialization
        self._db_bypass_domains = []
        self._db_bypass_ips = []
        self._db_block_domains = []
        self._db_block_ips = []
        self._db_decrypt_domains = []
        self._db_decrypt_ips = []
        self._db_wildcard_bypass = False
        self._db_wildcard_block = False
        self._db_wildcard_decrypt = False

        # Load initial policies from DB
        self._load_policies_from_db()

        # Start background loop
        try:
            self._create_tracked_task(
                self._refresh_db_policies_loop(),
                name="ssl_db_policy_refresh"
            )
        except Exception as exc:
            logger.debug("Could not start DB policy refresh loop: %s", exc)

        logger.info(
            "ssl_policy_init enabled=%s bypass_domains=%d bypass_ips=%d",
            self.enabled,
            len(self._bypass_domain_patterns),
            len(self._bypass_networks),
        )

    # ------------------------------------------------------------------
    # Main decision method
    # ------------------------------------------------------------------
    def decide(
        self,
        client_ip: str,
        target_host: Optional[str],
        target_port: int = 443,
        **kwargs,
    ) -> SSLAction:
        """
        Decide whether to inspect, bypass, block, or monitor an SSL connection.

        Args:
            client_ip:   Source IP address.
            target_host: Target hostname (may be None if only IP is known).
            target_port: Target port (default 443).
            **kwargs:    Optional context — category, username, tls_version, cert_expired.

        Returns:
            SSLAction enum value.
        """
        self.stats['total_decisions'] += 1

        # Step 1: Global enable check
        if not self.enabled:
            return self._record_action(SSLAction.BYPASS, client_ip, target_host)

        # Step 1.5: Database-driven policies check
        db_action = self._decide_db_policy(client_ip, target_host)
        if db_action:
            return self._record_action(db_action, client_ip, target_host)

        # Step 2: IP / CIDR bypass (H6)
        if _ip_in_networks(client_ip, self._bypass_networks):
            logger.debug("ssl_bypass reason=ip client=%s", client_ip)
            return self._record_action(SSLAction.BYPASS, client_ip, target_host)

        # Step 3: Domain bypass (pre-compiled patterns, H1+M3)
        if target_host and self._is_bypassed_domain(target_host):
            logger.debug("ssl_bypass reason=domain host=%s", target_host)
            return self._record_action(SSLAction.BYPASS, client_ip, target_host)

        # Step 4: Category bypass
        category = kwargs.get('category')
        if category and category in self.bypass_categories:
            logger.debug("ssl_bypass reason=category category=%s", category)
            return self._record_action(SSLAction.BYPASS, client_ip, target_host)

        # Step 5: Block expired upstream certificate (M5)
        if self.block_expired_certs and kwargs.get('cert_expired', False):
            logger.warning(
                "ssl_block reason=expired_cert host=%s client=%s",
                target_host, client_ip,
            )
            return self._record_action(SSLAction.BLOCK, client_ip, target_host)

        # Step 6: Block legacy TLS versions (M5)
        if self.block_legacy_tls:
            tls_version = kwargs.get('tls_version', '')
            if tls_version in ('TLSv1', 'TLSv1.0', 'TLSv1.1', 'SSLv3', 'SSLv2'):
                logger.warning(
                    "ssl_block reason=legacy_tls tls_version=%s host=%s client=%s",
                    tls_version, target_host, client_ip,
                )
                return self._record_action(SSLAction.BLOCK, client_ip, target_host)

        # Step 7: Certificate pinning detection
        if self.detect_pinning and self._detect_pinning(target_host):
            logger.info(
                "ssl_pinning_detected host=%s action=%s",
                target_host, self.pinning_action.value,
            )
            return self._record_action(self.pinning_action, client_ip, target_host)

        # Step 8: User / group policy (future: LDAP/AD integration)
        username = kwargs.get('username')
        if username:
            action = self._check_user_policy(username, target_host)
            if action:
                return self._record_action(action, client_ip, target_host)

        # Default: inspect
        logger.debug("ssl_inspect host=%s client=%s", target_host, client_ip)
        return self._record_action(SSLAction.INSPECT, client_ip, target_host)

    # ------------------------------------------------------------------
    # Domain matching helpers (H1 + M3)
    # ------------------------------------------------------------------
    def _is_bypassed_domain(self, domain: str) -> bool:
        """Check if *domain* matches any pre-compiled bypass pattern."""
        return any(pat.match(domain) for pat in self._bypass_domain_patterns)

    def _detect_pinning(self, target_host: Optional[str]) -> bool:
        """Check if *target_host* matches any pre-compiled pinned-domain pattern."""
        if not target_host:
            return False
        return any(pat.match(target_host) for pat in self._pinned_patterns)

    # ------------------------------------------------------------------
    # User policy (stub)
    # ------------------------------------------------------------------
    def _check_user_policy(
        self, username: str, target_host: Optional[str]
    ) -> Optional[SSLAction]:
        """
        User/group-based SSL policy (LDAP/AD integration planned).
        Returns an SSLAction or None to fall through to the default.
        """
        # Example: return SSLAction.MONITOR for privileged users
        return None

    # ------------------------------------------------------------------
    # Action recorder  (H5: tracked asyncio tasks)
    # ------------------------------------------------------------------
    def _record_action(
        self,
        action: SSLAction,
        client_ip: Optional[str] = None,
        target_host: Optional[str] = None,
    ) -> SSLAction:
        """
        Update statistics and push side-effects (eBPF offload, telemetry).

        H5 fix: background tasks are stored in self._bg_tasks and given
                 a done-callback that logs any unhandled exception.
        """
        # Update counters
        counter_map = {
            SSLAction.INSPECT: 'inspected',
            SSLAction.BYPASS:  'bypassed',
            SSLAction.BLOCK:   'blocked',
            SSLAction.MONITOR: 'monitored',
        }
        self.stats[counter_map.get(action, 'inspected')] += 1

        # ── eBPF fast-path offload ───────────────────────────────────────
        if self.ebpf_manager and target_host:
            if action == SSLAction.BYPASS and hasattr(self.ebpf_manager, 'add_allowed_domain'):
                self._create_tracked_task(
                    self.ebpf_manager.add_allowed_domain(target_host),
                    name=f"ebpf_allow_{target_host}",
                )
            elif action == SSLAction.BLOCK and hasattr(self.ebpf_manager, 'add_blocked_domain'):
                self._create_tracked_task(
                    self.ebpf_manager.add_blocked_domain(target_host),
                    name=f"ebpf_block_{target_host}",
                )

        # ── Telemetry event ──────────────────────────────────────────────
        if self.event_sink and client_ip and target_host:
            self._create_tracked_task(
                self._push_telemetry(action, client_ip, target_host),
                name=f"ssl_telemetry_{target_host}",
            )

        return action

    def _create_tracked_task(self, coro, *, name: str) -> None:
        """
        H5 fix: schedule a coroutine as a tracked asyncio task.
        - Stores the task reference to prevent GC.
        - Attaches a done-callback that logs any unhandled exception.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # No running event loop (e.g., called from a sync test)
            logger.debug("No event loop — skipping background task: %s", name)
            coro.close()
            return

        try:
            task = loop.create_task(coro)
            task.set_name(name)

            def _on_done(t: asyncio.Task) -> None:
                self._bg_tasks.discard(t)  # type: ignore[attr-defined]
                exc = t.exception() if not t.cancelled() else None
                if exc:
                    logger.warning("Background task %s failed: %s", name, exc)

            task.add_done_callback(_on_done)
            # Use a set for O(1) discard
            if isinstance(self._bg_tasks, set):
                self._bg_tasks.add(task)
            elif isinstance(self._bg_tasks, list):
                self._bg_tasks.append(task)
        except Exception as exc:
            logger.warning("Failed to create background task %s: %s", name, exc)

    async def _push_telemetry(
        self, action: SSLAction, client_ip: str, target_host: str
    ) -> None:
        """Submit a telemetry event to the unified event sink."""
        try:
            from system.telemetry.events.event_schema import (
                create_event_from_proxy, EventVerdict,
            )
            verdict_map = {
                SSLAction.INSPECT: EventVerdict.ALLOW,
                SSLAction.BYPASS:  EventVerdict.LOG_ONLY,
                SSLAction.BLOCK:   EventVerdict.DROP,
                SSLAction.MONITOR: EventVerdict.ALLOW,
            }
            evt = create_event_from_proxy(
                src_ip=client_ip, dst_ip=target_host,
                src_port=0, dst_port=443,
                protocol="TLS",
                bytes_count=0, packets_count=0,
                verdict=verdict_map.get(action, EventVerdict.ALLOW),
                reason=f"SSL Policy: {action.value}",
            )
            await self.event_sink.submit_event(evt)
        except Exception as exc:
            logger.debug("SSL telemetry push failed: %s", exc)

    # ------------------------------------------------------------------
    # Dynamic bypass list management
    # ------------------------------------------------------------------
    def add_bypass_domain(self, domain: str) -> None:
        """Dynamically add a domain to the bypass list (thread-safe append)."""
        if domain not in self._bypass_domain_raw:
            self._bypass_domain_raw.append(domain)
            self._bypass_domain_patterns.append(_compile_domain_pattern(domain))
            logger.info("ssl_bypass_added domain=%s", domain)

    def remove_bypass_domain(self, domain: str) -> None:
        """Remove a domain from the bypass list."""
        if domain in self._bypass_domain_raw:
            idx = self._bypass_domain_raw.index(domain)
            self._bypass_domain_raw.pop(idx)
            self._bypass_domain_patterns.pop(idx)
            logger.info("ssl_bypass_removed domain=%s", domain)

    def add_bypass_ip(self, ip: str) -> None:
        """Add an IP or CIDR to the bypass list."""
        nets = _build_ip_networks([ip])
        if nets and ip not in self._bypass_ips_raw:
            self._bypass_ips_raw.append(ip)
            self._bypass_networks.extend(nets)
            logger.info("ssl_bypass_added ip=%s", ip)

    def remove_bypass_ip(self, ip: str) -> None:
        """Remove an IP or CIDR from the bypass list."""
        if ip in self._bypass_ips_raw:
            self._bypass_ips_raw.remove(ip)
            self._bypass_networks = _build_ip_networks(self._bypass_ips_raw)
            logger.info("ssl_bypass_removed ip=%s", ip)

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------
    def get_statistics(self) -> dict:
        """Return a snapshot of the policy decision counters."""
        return dict(self.stats)

    def _load_policies_from_db(self) -> None:
        """Query and cache active policies from the database."""
        try:
            from system.database.database import SessionLocal
            from modules.ssl_inspection.models import SSLPolicy
        except ImportError:
            # Under some test environments, DB might not be available
            return

        try:
            with SessionLocal() as session:
                db_policies = session.query(SSLPolicy).filter(SSLPolicy.enabled == True).all()

                bypass_domains = []
                bypass_ips = []
                block_domains = []
                block_ips = []
                decrypt_domains = []
                decrypt_ips = []

                for policy in db_policies:
                    # policy.action can be: DECRYPT, BYPASS, BLOCK
                    domains = [d.strip() for d in policy.target_domains.split(',') if d.strip()]
                    ips = [ip.strip() for ip in policy.source_ips.split(',') if ip.strip()]

                    if policy.action == "BYPASS":
                        bypass_domains.extend(domains)
                        bypass_ips.extend(ips)
                    elif policy.action == "BLOCK":
                        block_domains.extend(domains)
                        block_ips.extend(ips)
                    elif policy.action == "DECRYPT":
                        decrypt_domains.extend(domains)
                        decrypt_ips.extend(ips)

                # Pre-compile the regexes
                self._db_bypass_domains = [_compile_domain_pattern(d) for d in bypass_domains if d != "*"]
                self._db_bypass_ips = _build_ip_networks(bypass_ips)
                self._db_block_domains = [_compile_domain_pattern(d) for d in block_domains if d != "*"]
                self._db_block_ips = _build_ip_networks(block_ips)
                self._db_decrypt_domains = [_compile_domain_pattern(d) for d in decrypt_domains if d != "*"]
                self._db_decrypt_ips = _build_ip_networks(decrypt_ips)

                # Check if there is a wildcard (*) match for actions
                self._db_wildcard_bypass = "*" in bypass_domains or "*" in bypass_ips
                self._db_wildcard_block = "*" in block_domains or "*" in block_ips
                self._db_wildcard_decrypt = "*" in decrypt_domains or "*" in decrypt_ips
        except Exception as exc:
            logger.debug("Database policy sync skipped or failed: %s", exc)

    async def _refresh_db_policies_loop(self) -> None:
        """Background task to periodically refresh policies from database."""
        while True:
            try:
                self._load_policies_from_db()
            except Exception as exc:
                logger.debug("Failed in refresh db policies loop: %s", exc)
            await asyncio.sleep(10.0)

    def _decide_db_policy(self, client_ip: str, target_host: Optional[str]) -> Optional[SSLAction]:
        """Evaluate database-driven bypass, block, and decrypt policies."""
        # 1. Bypass rules
        if self._db_wildcard_bypass:
            logger.debug("ssl_db_bypass reason=wildcard client=%s", client_ip)
            return SSLAction.BYPASS
        if target_host and any(pat.match(target_host) for pat in self._db_bypass_domains):
            logger.debug("ssl_db_bypass reason=domain host=%s", target_host)
            return SSLAction.BYPASS
        if _ip_in_networks(client_ip, self._db_bypass_ips):
            logger.debug("ssl_db_bypass reason=ip client=%s", client_ip)
            return SSLAction.BYPASS

        # 2. Block rules
        if self._db_wildcard_block:
            logger.warning("ssl_db_block reason=wildcard client=%s", client_ip)
            return SSLAction.BLOCK
        if target_host and any(pat.match(target_host) for pat in self._db_block_domains):
            logger.warning("ssl_db_block reason=domain host=%s", target_host)
            return SSLAction.BLOCK
        if _ip_in_networks(client_ip, self._db_block_ips):
            logger.warning("ssl_db_block reason=ip client=%s", client_ip)
            return SSLAction.BLOCK

        # 3. Decrypt (INSPECT) rules
        if self._db_wildcard_decrypt:
            logger.debug("ssl_db_inspect reason=wildcard client=%s", client_ip)
            return SSLAction.INSPECT
        if target_host and any(pat.match(target_host) for pat in self._db_decrypt_domains):
            logger.debug("ssl_db_inspect reason=domain host=%s", target_host)
            return SSLAction.INSPECT
        if _ip_in_networks(client_ip, self._db_decrypt_ips):
            logger.debug("ssl_db_inspect reason=ip client=%s", client_ip)
            return SSLAction.INSPECT

        return None
