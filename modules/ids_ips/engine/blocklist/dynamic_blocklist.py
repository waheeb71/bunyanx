"""
Dynamic Threat Reputation Blocklist
====================================
Thread-safe singleton that auto-blocks suspicious dst domains after
reaching the detection threshold.

Flow
----
  1st-2nd detection : full ML pipeline runs, counter increments
  3rd detection     : domain auto-added to blocklist + saved to JSON
  4th+ detection    : INSTANT BLOCK (< 1ms, no ML at all)

Config keys (from settings.yaml - dynamic_blocklist section)
-------------------------------------------------------------
  enabled             : bool  - enable/disable the whole feature
  detection_threshold : int   - detections before auto-block (default 3)
  persist_path        : str   - JSON file path (relative to project root)
  auto_expire_hours   : float - 0 = permanent, 24 = expire after 24h
  max_entries         : int   - max blocked domains
  check_dst_domain    : bool  - block suspicious dst domains (True)
  check_src_ip        : bool  - block suspicious src IPs (False)
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class DynamicBlocklist:
    """Thread-safe dynamic threat reputation blocklist (Singleton)."""

    _instance: Optional["DynamicBlocklist"] = None
    _class_lock = threading.Lock()

    @classmethod
    def instance(cls) -> "DynamicBlocklist":
        if cls._instance is None:
            with cls._class_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def __init__(self) -> None:
        self._rw_lock = threading.RLock()
        self._blocked: Dict[str, float] = {}   # domain -> expiry timestamp
        self._counter: Counter = Counter()     # domain -> detection count
        # Config defaults
        self._enabled: bool = True
        self._threshold: int = 3
        self._expire_seconds: float = 86400.0
        self._max_entries: int = 10_000
        self._persist_path: str = ""
        self._check_dst: bool = True
        self._check_src: bool = False
        self._dynamic_whitelist: set = set()
        self._load_dns_security_whitelist()

    def _load_dns_security_whitelist(self, base_dir: str = "") -> None:
        """Dynamically load whitelist_domains from modules/dns_security/config/settings.yaml."""
        try:
            import yaml
            from pathlib import Path
            cfg_path = Path(base_dir or ".").resolve() / "modules" / "dns_security" / "config" / "settings.yaml"
            if cfg_path.exists():
                with open(cfg_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                dns_sec = data.get("dns_security", {})
                raw_wl = dns_sec.get("whitelist_domains", [])
                for d in raw_wl:
                    if isinstance(d, str) and d.strip():
                        self._dynamic_whitelist.add(d.strip().lower())
                logger.debug("[Blocklist] Loaded %d dynamic whitelist domains from dns_security settings.yaml", len(self._dynamic_whitelist))
        except Exception as exc:
            logger.debug("[Blocklist] Could not load dns_security whitelist: %s", exc)

    def add_whitelisted_domain(self, domain: str) -> None:
        """Dynamically add a domain or wildcard pattern to the safe whitelist."""
        if domain and isinstance(domain, str):
            with self._rw_lock:
                self._dynamic_whitelist.add(domain.strip().lower())

    def configure(self, full_config: dict, base_dir: str = "") -> None:
        """Apply dynamic_blocklist section from settings.yaml."""
        bl = full_config.get("dynamic_blocklist", {})
        self._enabled        = bl.get("enabled", True)
        self._threshold      = int(bl.get("detection_threshold", 3))
        expire_h             = float(bl.get("auto_expire_hours", 24))
        self._expire_seconds = expire_h * 3600.0 if expire_h > 0 else 0.0
        self._max_entries    = int(bl.get("max_entries", 10_000))
        self._check_dst      = bl.get("check_dst_domain", True)
        self._check_src      = bl.get("check_src_ip", False)
        persist              = bl.get("persist_path", "data/threat_blocklist.json")
        if base_dir and not os.path.isabs(persist):
            self._persist_path = os.path.join(base_dir, persist)
        else:
            self._persist_path = persist
        
        # Load dns_security whitelist_domains directly or from full_config
        dns_sec_wl = full_config.get("dns_security", {}).get("whitelist_domains", [])
        if dns_sec_wl:
            for d in dns_sec_wl:
                if isinstance(d, str) and d.strip():
                    self._dynamic_whitelist.add(d.strip().lower())
        else:
            self._load_dns_security_whitelist(base_dir)

        self._load()
        logger.info(
            "[Blocklist] Configured | enabled=%s threshold=%d expire=%.0fh "
            "persist=%s | loaded=%d blocked | whitelisted=%d domains",
            self._enabled, self._threshold, expire_h,
            self._persist_path, len(self._blocked), len(self._dynamic_whitelist)
        )

    # Internal network prefixes & protected firewall WAN/LAN IPs that must NEVER be blocked
    _SAFE_PREFIXES = (
        "10.10.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
        "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
        "127.", "169.254.", "::1", "fc00:", "fd",
    )
    _PROTECTED_SYSTEM_IPS = {"192.168.1.33", "10.10.0.1", "10.10.0.50", "127.0.0.1", "::1"}
    # Domains that should NEVER be auto-blocked (legitimate services)
    _SAFE_DOMAIN_SUFFIXES = (
        "microsoft.com", "windows.com", "windowsupdate.com",
        "office.com", "live.com", "msftconnecttest.com",
        "google.com", "googleapis.com", "gstatic.com",
        "cloudflare.com", "akamaiedge.net",
    )

    def _is_safe_to_block(self, target: str) -> bool:
        """Return True if target is an internal IP or trusted domain that must never be blocked."""
        t = target.lower().strip()
        # Block protected system IPs (WAN interface 192.168.1.33, LAN gateway, backend server)
        if t in self._PROTECTED_SYSTEM_IPS or t in ("localhost", "127.0.0.1", "::1", "firewall_ip"):
            return True
        # Block internal IPs
        if any(t.startswith(pfx) for pfx in self._SAFE_PREFIXES):
            return True
        # Block trusted domain suffixes
        if any(t == s or t.endswith("." + s) for s in self._SAFE_DOMAIN_SUFFIXES):
            return True
        # Check dynamic whitelist domains from dns_security settings.yaml
        for pattern in self._dynamic_whitelist:
            p = pattern.strip().lower()
            if p.startswith("*."):
                sfx = p[2:]
                if t == sfx or t.endswith("." + sfx):
                    return True
            elif p.startswith("."):
                sfx = p[1:]
                if t == sfx or t.endswith("." + sfx):
                    return True
            elif t == p:
                return True
        return False

    def is_blocked(self, target: str) -> bool:
        """O(1) lookup — returns True if target is actively blocked."""
        if not self._enabled or not target:
            return False
        if self._is_safe_to_block(target):
            return False
        with self._rw_lock:
            if target not in self._blocked:
                return False
            expiry = self._blocked[target]
            if expiry > 0.0 and time.time() > expiry:
                del self._blocked[target]
                logger.info("[Blocklist] Expired + removed: %s", target)
                return False
            return True

    def record_detection(self, target: str) -> bool:
        """Increment counter; auto-block when threshold is reached.

        Returns True if this call triggered a new block.
        """
        if not self._enabled or not target:
            return False
        # Never count internal IPs or trusted domains toward blocklist
        if self._is_safe_to_block(target):
            logger.debug("[Blocklist] Skipped safe/internal target: %s", target)
            return False
        with self._rw_lock:
            if target in self._blocked:
                self._counter[target + ":hits"] += 1
                return False
            self._counter[target] += 1
            count = self._counter[target]
            logger.info("[Blocklist] Detection %d/%d for %s", count, self._threshold, target)
            if count >= self._threshold:
                return self._add_block(target)
            return False

    def unblock(self, target: str) -> bool:
        """Remove target from blocklist and clear its detection counters."""
        if not target:
            return False
        with self._rw_lock:
            removed = False
            if target in self._blocked:
                del self._blocked[target]
                removed = True
            self._counter.pop(target, None)
            self._counter.pop(target + ":hits", None)
            if removed:
                logger.info("[Blocklist] Manual UNBLOCKED: %s", target)
                self._save_locked()
            return removed

    def stats(self) -> dict:
        with self._rw_lock:
            return {
                "enabled":       self._enabled,
                "threshold":     self._threshold,
                "blocked_count": len(self._blocked),
                "pending_count": sum(1 for k in self._counter if not k.endswith(":hits")),
                "total_hits":    sum(v for k, v in self._counter.items() if k.endswith(":hits")),
            }

    def blocked_entries(self) -> list:
        now = time.time()
        with self._rw_lock:
            result = []
            for domain, expiry in list(self._blocked.items()):
                if expiry > 0 and now > expiry:
                    continue
                result.append({
                    "domain": domain,
                    "expiry": datetime.fromtimestamp(expiry, tz=timezone.utc).isoformat()
                              if expiry > 0 else "permanent",
                    "hits":   self._counter.get(domain + ":hits", 0),
                })
            return result

    def _add_block(self, target: str) -> bool:
        """Add target to blocklist. Must be called under self._rw_lock."""
        if len(self._blocked) >= self._max_entries:
            logger.warning("[Blocklist] Max entries reached, cannot add %s", target)
            return False
        expiry = (time.time() + self._expire_seconds) if self._expire_seconds > 0 else 0.0
        self._blocked[target] = expiry
        detections = self._counter.pop(target, self._threshold)
        expire_str = (
            datetime.fromtimestamp(expiry, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            if expiry > 0 else "permanent"
        )
        logger.warning(
            "[Blocklist] AUTO-BLOCKED: %s | detections=%d | expires=%s",
            target, detections, expire_str,
        )
        self._save_locked()
        return True

    def _load(self) -> None:
        if not self._persist_path or not os.path.exists(self._persist_path):
            return
        try:
            with open(self._persist_path, encoding="utf-8") as fh:
                data = json.load(fh)
            now = time.time()
            # Load blocked entries — skip expired AND safe/internal targets
            self._blocked = {
                d: exp for d, exp in data.get("blocked", {}).items()
                if (exp == 0 or exp > now) and not self._is_safe_to_block(d)
            }
            # Load counters — skip safe/internal targets
            self._counter = Counter({
                k: v for k, v in data.get("counter", {}).items()
                if not self._is_safe_to_block(k.split(":")[0])
            })
            purged = len(data.get("blocked", {})) - len(self._blocked)
            if purged:
                logger.warning(
                    "[Blocklist] Purged %d safe/internal entries from blocklist on load",
                    purged,
                )
                self._save_locked()  # persist clean state immediately
            logger.info("[Blocklist] Loaded %d blocked domains from %s",
                        len(self._blocked), self._persist_path)
        except Exception as exc:
            logger.error("[Blocklist] Load failed %s: %s", self._persist_path, exc)

    def _save_locked(self) -> None:
        """Atomically write state to JSON. Must be called under self._rw_lock."""
        if not self._persist_path:
            return
        try:
            persist_dir = os.path.dirname(self._persist_path)
            if persist_dir:
                os.makedirs(persist_dir, exist_ok=True)
            payload = {
                "saved_at": datetime.now(tz=timezone.utc).isoformat(),
                "blocked":  dict(self._blocked),
                "counter":  dict(self._counter),
            }
            tmp = self._persist_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, ensure_ascii=False)
            os.replace(tmp, self._persist_path)
        except Exception as exc:
            logger.error("[Blocklist] Save failed %s: %s", self._persist_path, exc)
