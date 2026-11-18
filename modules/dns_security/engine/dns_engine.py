"""
Enterprise bunyanx v2.0 - DNS Security Engine (Centralized Cache)

Loads rules and config from DB once into RAM. The plugin layer uses this
engine for all per-packet decisions without touching the database.
"""

import re
import fnmatch
import logging
import threading
import ipaddress
import yaml
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any
from pathlib import Path

from system.database.database import SessionLocal
from modules.dns_security.models import (
    DNSFilterRule, DNSModuleConfig, FilterType, ActionEnum, DNSQueryLog
)

logger = logging.getLogger(__name__)

import os

# ── ReDoS Protection Constants ────────────────────────────────────────────────
MAX_REGEX_LEN = 500
_REGEX_MATCH_TIMEOUT = 0.05  # seconds (50 ms max per regex match)
# Patterns known to cause catastrophic backtracking
_DANGEROUS_REGEX_PATTERNS = re.compile(
    r'\(.*[\+\*].*\)[\+\*]'   # nested quantifiers like (a+)+, (.*)*
    r'|'
    r'\(.*\|.*\)[\+\*]'       # alternation with quantifier like (a|b)+
)
# PERF-1 FIX: Increase from 1 worker to min(4, cpu_count).
# A single worker creates a global serial bottleneck capping regex evaluation.
_REGEX_EXECUTOR = ThreadPoolExecutor(
    max_workers=min(4, os.cpu_count() or 2),
    thread_name_prefix="regex_guard",
)


def _safe_regex_search(pattern: re.Pattern, text: str) -> bool:
    """Execute regex with timeout protection against ReDoS."""
    try:
        future = _REGEX_EXECUTOR.submit(pattern.search, text)
        result = future.result(timeout=_REGEX_MATCH_TIMEOUT)
        return result is not None
    except FuturesTimeout:
        logger.warning(f"ReDoS protection: regex timed out on input len={len(text)}")
        return False
    except Exception:
        return False


@dataclass
class CachedConfig:
    """Plain dataclass copy of DB config — avoids detached ORM issues."""
    is_active: bool = True
    enable_dga_detection: bool = True
    enable_tunneling_detection: bool = True
    enable_threat_intel: bool = True
    enable_rate_limiting: bool = True
    enable_tld_blocking: bool = True
    enable_dart_detection: bool = True
    dga_entropy_threshold: float = 3.8
    tunneling_query_threshold: int = 150
    rate_limit_per_minute: int = 100
    suspicious_tlds: str = ".tk,.ml,.ga,.cf,.gq,.xyz,.top,.win,.bid,.onion"
    sinkhole_ip: str = "10.10.0.1"
    feed_url: str = ""
    refresh_interval_hours: int = 6
    dnssec_validation: bool = True
    inspect_doh: bool = True
    inspect_dot: bool = True


@dataclass
class CachedFilterRule:
    id: int
    domain_pattern: str
    filter_type: FilterType
    action: ActionEnum
    description: str
    _compiled_regex: Optional[re.Pattern] = None  # for REGEX type only


@dataclass
class SteeringRule:
    """DNS Steering (Redirection) rule"""
    name: str
    domain_pattern: str
    redirect_ip: str
    source_ips: List[str] = None
    _networks: List[ipaddress.IPv4Network] = None


# ── Resolve base.yaml path at module load time ───────────────────────────────
_MODULE_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _MODULE_DIR.parents[2]  # enterprise_ngfw/
_BASE_YAML_PATH = _PROJECT_ROOT / "system" / "config" / "base.yaml"


class DNSEngine:
    """
    Singleton centralized DNS Engine.
    All config and filter rules are loaded once from the DB into RAM.
    Call `.reload()` to refresh after mutations from the API.

    Uses copy-on-write for rules: readers never acquire a lock.
    Only `.reload()` holds the lock while building new lists, then atomically
    swaps the references (safe under Python GIL).
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(DNSEngine, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        default_tld_str = ".tk,.ml,.ga,.cf,.gq,.xyz,.top,.win,.bid,.onion"
        self._rules: List[CachedFilterRule] = []
        self._exact_index: Dict[str, CachedFilterRule] = {}  # PERF-2: O(1) exact-match index
        self._steering_rules: List[SteeringRule] = []
        self._config: CachedConfig = CachedConfig(suspicious_tlds=default_tld_str)
        self._suspicious_tlds: Set[str] = {t.strip() for t in default_tld_str.split(",") if t.strip()}
        self._reload_lock = threading.RLock()
        self._db_failure_count = 0  # FAIL-4: circuit breaker counter
        self._log_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="dns_query_log")
        # FAIL-3 FIX: Don't crash if DB is unavailable at startup.
        # Use default config and retry on next reload().

        try:
            self.reload()
        except Exception as e:
            logger.error(
                f"❌ DNSEngine: DB unavailable at startup ({e}). "
                "Using default config. Will retry on next reload() call."
            )
        self._initialized = True

    def reload(self):
        """
        Reload config and rules from DB into RAM. Thread-safe (holds RLock).
        Includes exponential backoff retries on DB failure (FAIL-4).
        """
        import time as _time
        max_retries = 3
        for attempt in range(max_retries):
            try:
                self._do_reload()
                self._db_failure_count = 0  # reset on success
                return
            except Exception as e:
                self._db_failure_count += 1
                if attempt < max_retries - 1:
                    backoff = 0.5 * (2 ** attempt)
                    logger.warning(
                        f"DNSEngine reload attempt {attempt+1}/{max_retries} failed: {e}. "
                        f"Retrying in {backoff}s..."
                    )
                    _time.sleep(backoff)
                else:
                    logger.error(
                        f"❌ DNSEngine reload FAILED after {max_retries} attempts: {e}. "
                        f"Using stale in-memory data. Consecutive failures: {self._db_failure_count}."
                    )
                    if self._db_failure_count >= 5:
                        logger.critical(
                            "🚨 CIRCUIT BREAKER: 5+ consecutive DB failures. "
                            "DNSEngine running on stale data. Check database connectivity."
                        )

    def _do_reload(self):
        with self._reload_lock:
            with SessionLocal() as db:
                from system.database.database import Base
                import modules.dns_security.models
                try:
                    Base.metadata.create_all(bind=db.get_bind())
                except Exception:
                    pass

                # Load config
                conf = db.query(DNSModuleConfig).first()
                if not conf:
                    conf = DNSModuleConfig()
                    db.add(conf)
                    db.commit()
                    db.refresh(conf)

                # Copy ORM values to plain dataclass (avoids detached session issues)
                cached_config = CachedConfig(
                    is_active=bool(conf.is_active) if conf.is_active is not None else True,
                    enable_dga_detection=bool(conf.enable_dga_detection) if conf.enable_dga_detection is not None else True,
                    enable_tunneling_detection=bool(conf.enable_tunneling_detection) if conf.enable_tunneling_detection is not None else True,
                    enable_threat_intel=bool(conf.enable_threat_intel) if conf.enable_threat_intel is not None else True,
                    enable_rate_limiting=bool(conf.enable_rate_limiting) if conf.enable_rate_limiting is not None else True,
                    enable_tld_blocking=bool(conf.enable_tld_blocking) if conf.enable_tld_blocking is not None else True,
                    enable_dart_detection=bool(conf.enable_dart_detection) if conf.enable_dart_detection is not None else True,
                    dga_entropy_threshold=float(conf.dga_entropy_threshold) if conf.dga_entropy_threshold is not None else 3.8,
                    tunneling_query_threshold=int(conf.tunneling_query_threshold) if conf.tunneling_query_threshold is not None else 150,
                    rate_limit_per_minute=int(conf.rate_limit_per_minute) if conf.rate_limit_per_minute is not None else 100,
                    suspicious_tlds=conf.suspicious_tlds or ".tk,.ml,.ga,.cf,.gq,.xyz,.top,.win,.bid,.onion",
                    sinkhole_ip=getattr(conf, 'sinkhole_ip', None) or "10.10.0.1",
                    feed_url=getattr(conf, 'feed_url', None) or "",
                    refresh_interval_hours=getattr(conf, 'refresh_interval_hours', None) or 6,
                    dnssec_validation=bool(getattr(conf, 'dnssec_validation', True)),
                    inspect_doh=bool(getattr(conf, 'inspect_doh', True)),
                    inspect_dot=bool(getattr(conf, 'inspect_dot', True)),
                )

                # Pre-parse TLDs
                suspicious_tlds = {
                    t.strip()
                    for t in cached_config.suspicious_tlds.split(",")
                    if t.strip()
                }

                # Load filter rules with ReDoS protection
                db_rules = db.query(DNSFilterRule).filter(DNSFilterRule.enabled == True).all()
                cached = []
                for r in db_rules:
                    compiled = None
                    if r.filter_type == FilterType.REGEX:
                        pattern_str = r.domain_pattern.lower()
                        # ReDoS guard: reject overlong patterns
                        if len(pattern_str) > MAX_REGEX_LEN:
                            logger.warning(
                                f"DNS rule #{r.id}: regex too long ({len(pattern_str)} chars, "
                                f"max {MAX_REGEX_LEN}). Skipped."
                            )
                            continue
                        # ReDoS guard: reject known catastrophic patterns
                        if _DANGEROUS_REGEX_PATTERNS.search(pattern_str):
                            logger.warning(
                                f"DNS rule #{r.id}: regex contains dangerous nested quantifiers. "
                                f"Skipped to prevent ReDoS."
                            )
                            continue
                        try:
                            compiled = re.compile(pattern_str, re.IGNORECASE)
                        except re.error as e:
                            logger.warning(f"Invalid regex in DNS rule #{r.id}: {e}")
                            continue

                    cached.append(CachedFilterRule(
                        id=r.id,
                        domain_pattern=r.domain_pattern.lower(),
                        filter_type=r.filter_type,
                        action=r.action,
                        description=r.description or r.domain_pattern,
                        _compiled_regex=compiled
                    ))

                # Load whitelist_domains from settings.yaml as ALLOW rules
                try:
                    settings_path = _PROJECT_ROOT / "modules" / "dns_security" / "config" / "settings.yaml"
                    if settings_path.exists():
                        with open(settings_path, 'r', encoding="utf-8") as f:
                            settings_data = yaml.safe_load(f) or {}
                        wl_domains = settings_data.get('dns_security', {}).get('whitelist_domains', [])
                        for i, pat in enumerate(wl_domains):
                            pat = str(pat).strip().lower()
                            if not pat:
                                continue
                            ftype = FilterType.WILDCARD if "*" in pat else FilterType.EXACT
                            cached.append(CachedFilterRule(
                                id=-(i + 1),
                                domain_pattern=pat,
                                filter_type=ftype,
                                action=ActionEnum.ALLOW,
                                description=f"Settings Whitelist: {pat}",
                            ))
                except Exception as wle:
                    logger.debug(f"Failed to load whitelist_domains from settings.yaml: {wle}")

                # Load steering rules from DB or config fallback
                steering_rules = self._load_steering_rules(db_session=db)

            # ── Atomic swap (copy-on-write) — no lock needed for readers ──
            # PERF-2 FIX: Build O(1) index for EXACT rules; keep WILDCARD/REGEX in list.
            exact_idx = {}
            non_exact = []
            for r in cached:
                if r.filter_type == FilterType.EXACT:
                    exact_idx[r.domain_pattern] = r
                else:
                    non_exact.append(r)

            self._config = cached_config
            self._suspicious_tlds = suspicious_tlds
            self._rules = non_exact          # only WILDCARD + REGEX (linear scan)
            self._exact_index = exact_idx    # O(1) dict lookup
            self._steering_rules = steering_rules

            logger.info(
                f"DNSEngine reloaded — {len(self._rules)} filter rules, "
                f"{len(self._steering_rules)} steering rules, "
                f"{len(self._suspicious_tlds)} suspicious TLDs cached."
            )

    # ─────────────────────────────────────────────────────────────
    # Config accessors (no DB access, no lock needed)
    # ─────────────────────────────────────────────────────────────

    def _load_steering_rules(self, db_session=None) -> List[SteeringRule]:
        """Loads professional DNS steering rules from DB (with fallback to settings.yaml / base.yaml)."""
        try:
            loaded_rules = []

            # 1. Try loading from DB first
            if db_session is not None:
                try:
                    from modules.dns_security.models import DNSSteeringRule
                    db_steering = db_session.query(DNSSteeringRule).filter(DNSSteeringRule.enabled == True).all()
                    if db_steering:
                        for r in db_steering:
                            networks = []
                            src_ips = r.source_ips or []
                            if isinstance(src_ips, str):
                                import json
                                try:
                                    src_ips = json.loads(src_ips)
                                except Exception:
                                    src_ips = [s.strip() for s in src_ips.split(",") if s.strip()]
                            for cidr in src_ips:
                                try:
                                    networks.append(ipaddress.ip_network(cidr))
                                except ValueError:
                                    logger.warning(f"Invalid CIDR in DB steering rule '{r.name}': {cidr}")
                            
                            loaded_rules.append(SteeringRule(
                                name=r.name,
                                domain_pattern=r.domain_pattern.lower(),
                                redirect_ip=r.redirect_ip,
                                source_ips=src_ips,
                                _networks=networks,
                            ))
                        return loaded_rules
                except Exception as _dbe:
                    logger.debug(f"DB steering rules load exception (falling back to YAML): {_dbe}")

            # 2. Fallback to settings.yaml / base.yaml if DB contains no rules
            settings_path = _PROJECT_ROOT / "modules" / "dns_security" / "config" / "settings.yaml"
            steering_conf = None
            
            if settings_path.exists():
                with open(settings_path, 'r', encoding="utf-8") as f:
                    settings_data = yaml.safe_load(f) or {}
                steering_conf = settings_data.get('steering', {})

            if not steering_conf and _BASE_YAML_PATH.exists():
                with open(_BASE_YAML_PATH, 'r', encoding="utf-8") as f:
                    full_config = yaml.safe_load(f) or {}
                steering_conf = full_config.get('modules', {}).get('dns_security', {}).get('steering', {})

            if not steering_conf or not steering_conf.get('enabled', False):
                return []
            
            rules_raw = steering_conf.get('rules', [])
            for r in rules_raw:
                networks = []
                if r.get('source_ips'):
                    for cidr in r['source_ips']:
                        try:
                            networks.append(ipaddress.ip_network(cidr))
                        except ValueError:
                            logger.warning(f"Invalid CIDR in steering rule '{r.get('name')}': {cidr}")
                
                loaded_rules.append(SteeringRule(
                    name=r.get('name', 'Unnamed'),
                    domain_pattern=r.get('domain_pattern', '').lower(),
                    redirect_ip=r.get('redirect_ip'),
                    source_ips=r.get('source_ips', []),
                    _networks=networks
                ))
            return loaded_rules
        except Exception as e:
            logger.error(f"Error loading steering rules: {e}")
            return []

    @property
    def is_active(self) -> bool:
        return self._config.is_active

    @property
    def enable_dga_detection(self) -> bool:
        return self._config.enable_dga_detection

    @property
    def enable_tunneling_detection(self) -> bool:
        return self._config.enable_tunneling_detection

    @property
    def enable_threat_intel(self) -> bool:
        return self._config.enable_threat_intel

    @property
    def enable_rate_limiting(self) -> bool:
        return self._config.enable_rate_limiting

    @property
    def enable_tld_blocking(self) -> bool:
        return self._config.enable_tld_blocking

    @property
    def enable_dart_detection(self) -> bool:
        return self._config.enable_dart_detection

    @property
    def dga_entropy_threshold(self) -> float:
        return self._config.dga_entropy_threshold

    @property
    def tunneling_query_threshold(self) -> int:
        return self._config.tunneling_query_threshold

    @property
    def rate_limit_per_minute(self) -> int:
        return self._config.rate_limit_per_minute

    @property
    def sinkhole_ip(self) -> str:
        return self._config.sinkhole_ip

    @property
    def feed_url(self) -> str:
        return self._config.feed_url

    @property
    def refresh_interval_hours(self) -> int:
        return self._config.refresh_interval_hours

    @property
    def suspicious_tlds(self) -> Set[str]:
        return self._suspicious_tlds

    # ─────────────────────────────────────────────────────────────
    # Domain filter rule matching (no DB access, no lock — copy-on-write)
    # ─────────────────────────────────────────────────────────────

    def match_filter_rules(self, domain: str) -> Optional[CachedFilterRule]:
        """
        Returns the first matching cached rule or None.
        Lock-free: reads immutable snapshots (atomic ref under GIL).

        PERF-2 FIX: EXACT rules are checked via O(1) dict lookup first.
        Only WILDCARD/REGEX rules fall through to the linear scan.
        """
        domain = domain.lower()

        # O(1) exact match
        exact_hit = self._exact_index.get(domain)
        if exact_hit is not None:
            return exact_hit

        # Linear scan for WILDCARD and REGEX rules only
        rules = self._rules  # snapshot (contains only non-EXACT rules)
        for rule in rules:
            if rule.filter_type == FilterType.WILDCARD:
                if fnmatch.fnmatchcase(domain, rule.domain_pattern):
                    return rule
            elif rule.filter_type == FilterType.REGEX and rule._compiled_regex:
                if _safe_regex_search(rule._compiled_regex, domain):
                    return rule
        return None

    def match_steering_rules(self, domain: str, src_ip: str) -> Optional[SteeringRule]:
        """
        Matches a domain against professional steering rules with CIDR scoping.
        Lock-free: reads an immutable snapshot of self._steering_rules.
        """
        domain = domain.lower()
        try:
            client_ip = ipaddress.ip_address(src_ip)
        except ValueError:
            return None

        steering_rules = self._steering_rules  # snapshot
        for rule in steering_rules:
            # 1. Match Domain (Wildcard support)
            if fnmatch.fnmatchcase(domain, rule.domain_pattern):
                # 2. Match Source IP (Scoping)
                if not rule._networks:
                    # Global rule (no source restriction)
                    return rule
                
                for network in rule._networks:
                    if client_ip in network:
                        return rule
        return None

    def update_rule_stats(self, rule_id: int):
        """Async-safe hit count update. Opens brief DB session outside inspect loop."""
        from datetime import datetime
        try:
            with SessionLocal() as db:
                db_rule = db.query(DNSFilterRule).filter(DNSFilterRule.id == rule_id).first()
                if db_rule:
                    db_rule.blocked_count = (db_rule.blocked_count or 0) + 1
                    db_rule.last_triggered = datetime.utcnow()
                    db.commit()
        except Exception as e:
            logger.warning(f"Failed to update DNS rule stats for rule #{rule_id}: {e}")

    def log_query_event(
        self,
        client_ip: str,
        domain: str,
        query_type: str = "A",
        action: str = "ALLOW",
        category: str = "CLEAN",
        reason: Optional[str] = None,
        confidence: float = 0.0,
        response_ip: Optional[str] = None,
        latency_ms: float = 0.0,
    ):
        """Non-blocking asynchronous logging of DNS queries and security actions."""
        if not self._log_pool:
            return
        try:
            self._log_pool.submit(
                self._persist_query_log,
                client_ip,
                domain,
                query_type,
                action,
                category,
                reason,
                confidence,
                response_ip,
                latency_ms,
            )
        except Exception as e:
            logger.debug(f"Failed to submit DNS query log task: {e}")

    @staticmethod
    def _persist_query_log(
        client_ip: str,
        domain: str,
        query_type: str,
        action: str,
        category: str,
        reason: Optional[str],
        confidence: float,
        response_ip: Optional[str],
        latency_ms: float,
    ):
        try:
            with SessionLocal() as db:
                entry = DNSQueryLog(
                    client_ip=client_ip or "0.0.0.0",
                    domain=(domain or "").lower().strip(),
                    query_type=query_type or "A",
                    action=action or "ALLOW",
                    category=category or "CLEAN",
                    reason=reason or "",
                    confidence=float(confidence or 0.0),
                    response_ip=response_ip,
                    latency_ms=float(latency_ms or 0.0),
                )
                db.add(entry)
                db.commit()
        except Exception as e:
            logger.debug(f"Failed to persist DNS query log to DB: {e}")

