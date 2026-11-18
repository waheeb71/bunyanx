"""
Identity Correlation Cache — BunyanX NGFW
==========================================
Thread-safe IP → User mapping cache.  All identity sources (LDAP, RADIUS,
VPN, Captive Portal) write here; IdentityManager.resolve() reads from here.

Design goals:
  - O(1) lookup per packet (RLock + dict)
  - Configurable TTL per entry (RADIUS = short, LDAP sync = longer)
  - Background cleanup thread (removes expired entries)
  - Hard cap on entries (evict oldest when full — LRU-like)
  - Fully observable: exposes stats for monitoring/API
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class UserEntry:
    """
    A resolved user identity bound to an IP address.

    Fields
    ------
    username      canonical login name  (e.g. "alice.hassan" or "CORP\\alice")
    display_name  human-readable name   (e.g. "Alice Hassan")
    email         primary email address
    groups        AD/LDAP group CNs     (e.g. ["Finance", "VPN-Users"])
    role          mapped NGFW role      ("admin" | "operator" | "viewer" | "user")
    department    OU / department       (e.g. "Finance")
    source        how we learned this   ("ldap_sync" | "radius" | "vpn" | "captive" | "manual")
    src_ip        the IP address key    (kept for reference)
    created_at    Unix timestamp of first binding
    expires_at    Unix timestamp after which the entry is stale (0 = never)
    last_seen     Unix timestamp of last traffic observation (refreshed on read)
    """
    username:     str
    display_name: str             = ""
    email:        str             = ""
    groups:       List[str]       = field(default_factory=list)
    role:         str             = "user"
    department:   str             = ""
    source:       str             = "unknown"
    src_ip:       str             = ""
    created_at:   float           = field(default_factory=time.time)
    expires_at:   float           = 0.0          # 0 = never expires
    last_seen:    float           = field(default_factory=time.time)

    # ── convenience ──────────────────────────────────────────────────────────

    @property
    def is_expired(self) -> bool:
        return self.expires_at > 0 and time.time() > self.expires_at

    @property
    def is_authenticated(self) -> bool:
        return bool(self.username) and self.username not in ("anonymous", "unknown")

    def touch(self) -> None:
        """Refresh last_seen timestamp (called on every lookup hit)."""
        self.last_seen = time.time()

    def to_dict(self) -> dict:
        return {
            "username":     self.username,
            "display_name": self.display_name,
            "email":        self.email,
            "groups":       self.groups,
            "role":         self.role,
            "department":   self.department,
            "source":       self.source,
            "src_ip":       self.src_ip,
            "created_at":   self.created_at,
            "expires_at":   self.expires_at,
            "last_seen":    self.last_seen,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Cache
# ─────────────────────────────────────────────────────────────────────────────

class IdentityCache:
    """
    Thread-safe IP → UserEntry mapping.

    Singleton — use `IdentityCache.instance()`.

    Parameters (from identity_correlation.yaml → cache section)
    -----------------------------------------------------------
    default_ttl_seconds  TTL used when caller does not specify (default 1800 s)
    max_entries          Evict oldest entry when this limit is reached (default 100 000)
    cleanup_interval_s   How often the background cleanup thread runs (default 60 s)
    touch_on_read        If True, refresh last_seen on every lookup (default True)
    """

    _singleton: Optional["IdentityCache"] = None
    _singleton_lock: threading.Lock = threading.Lock()

    def __init__(
        self,
        default_ttl_seconds: int   = 1800,
        max_entries:         int   = 100_000,
        cleanup_interval_s:  int   = 60,
        touch_on_read:       bool  = True,
    ):
        self._default_ttl      = default_ttl_seconds
        self._max_entries      = max_entries
        self._cleanup_interval = cleanup_interval_s
        self._touch_on_read    = touch_on_read

        # Main store:  ip → UserEntry
        self._store: Dict[str, UserEntry] = {}
        self._lock  = threading.RLock()

        # Stats
        self._hits   = 0
        self._misses = 0
        self._sets   = 0
        self._evicts = 0

        # Background cleanup thread
        self._stop_event = threading.Event()
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            name="identity-cache-cleanup",
            daemon=True,
        )
        self._cleanup_thread.start()
        logger.info(
            "[IdentityCache] Started — ttl=%ds max=%d cleanup_interval=%ds",
            self._default_ttl, self._max_entries, self._cleanup_interval,
        )

    # ── Singleton ─────────────────────────────────────────────────────────────

    @classmethod
    def instance(cls, **kwargs) -> "IdentityCache":
        """Return (or create) the global singleton instance."""
        if cls._singleton is None:
            with cls._singleton_lock:
                if cls._singleton is None:
                    cls._singleton = cls(**kwargs)
        return cls._singleton

    @classmethod
    def configure(cls, cfg: dict) -> "IdentityCache":
        """
        Create/reconfigure the singleton from a config dict
        (identity_correlation.yaml → cache section).
        """
        cache_cfg = cfg.get("cache", {})
        return cls.instance(
            default_ttl_seconds = cache_cfg.get("default_ttl_seconds", 1800),
            max_entries         = cache_cfg.get("max_entries",          100_000),
            cleanup_interval_s  = cache_cfg.get("cleanup_interval_s",  60),
            touch_on_read       = cache_cfg.get("touch_on_read",        True),
        )

    # ── Core CRUD ─────────────────────────────────────────────────────────────

    def set(
        self,
        ip:          str,
        username:    str,
        *,
        display_name: str       = "",
        email:        str       = "",
        groups:       List[str] = None,
        role:         str       = "user",
        department:   str       = "",
        source:       str       = "unknown",
        ttl:          int       = None,
    ) -> UserEntry:
        """
        Bind an IP address to a user identity.

        Args
        ----
        ip        Source IP (e.g. "10.0.0.5")
        username  Canonical login name
        ttl       Override default TTL in seconds (None = use default)

        Returns the created/updated UserEntry.
        """
        ttl_s     = ttl if ttl is not None else self._default_ttl
        expires   = time.time() + ttl_s if ttl_s > 0 else 0.0

        entry = UserEntry(
            username     = username,
            display_name = display_name or username,
            email        = email,
            groups       = groups or [],
            role         = role,
            department   = department,
            source       = source,
            src_ip       = ip,
            expires_at   = expires,
        )

        with self._lock:
            # Evict oldest if at capacity
            if ip not in self._store and len(self._store) >= self._max_entries:
                self._evict_oldest()
            self._store[ip] = entry
            self._sets += 1

        logger.debug(
            "[IdentityCache] SET %s → %s (src=%s ttl=%ds)",
            ip, username, source, ttl_s,
        )
        return entry

    def get(self, ip: str) -> Optional[UserEntry]:
        """
        Look up identity for an IP.

        Returns None if not found or expired.
        Refreshes last_seen if touch_on_read=True.
        """
        with self._lock:
            entry = self._store.get(ip)
            if entry is None:
                self._misses += 1
                return None
            if entry.is_expired:
                del self._store[ip]
                self._misses += 1
                return None
            self._hits += 1
            if self._touch_on_read:
                entry.touch()
            return entry

    def invalidate(self, ip: str) -> bool:
        """
        Remove a single IP binding (e.g. RADIUS Accounting-Stop / VPN logout).

        Returns True if an entry was removed.
        """
        with self._lock:
            if ip in self._store:
                del self._store[ip]
                logger.debug("[IdentityCache] INVALIDATE %s", ip)
                return True
            return False

    def invalidate_user(self, username: str) -> int:
        """
        Remove ALL bindings for a given username (e.g. account disabled in AD).

        Returns the number of entries removed.
        """
        with self._lock:
            to_del = [ip for ip, e in self._store.items()
                      if e.username == username]
            for ip in to_del:
                del self._store[ip]
        if to_del:
            logger.info(
                "[IdentityCache] Invalidated %d entries for user '%s'",
                len(to_del), username,
            )
        return len(to_del)

    def bulk_set(self, entries: Dict[str, UserEntry]) -> int:
        """
        Atomic bulk update (used by LDAP sync).
        Existing entries for the same IPs are overwritten.
        Returns number of entries written.
        """
        with self._lock:
            for ip, entry in entries.items():
                if ip not in self._store and len(self._store) >= self._max_entries:
                    self._evict_oldest()
                self._store[ip] = entry
                self._sets += 1
        logger.debug("[IdentityCache] bulk_set: %d entries", len(entries))
        return len(entries)

    def clear(self) -> None:
        """Remove all entries (e.g. on config reload)."""
        with self._lock:
            self._store.clear()
        logger.warning("[IdentityCache] All entries cleared")

    # ── Introspection / API ───────────────────────────────────────────────────

    def all_entries(self) -> List[dict]:
        """Return all non-expired entries as dicts (for the API/dashboard)."""
        now = time.time()
        with self._lock:
            return [
                e.to_dict()
                for e in self._store.values()
                if e.expires_at == 0 or e.expires_at > now
            ]

    def stats(self) -> dict:
        """Return cache performance counters."""
        with self._lock:
            total = self._hits + self._misses
            return {
                "total_entries": len(self._store),
                "hits":          self._hits,
                "misses":        self._misses,
                "sets":          self._sets,
                "evictions":     self._evicts,
                "hit_rate":      round(self._hits / total, 4) if total else 0.0,
            }

    def lookup_user(self, username: str) -> List[str]:
        """Return all IPs currently bound to a username."""
        with self._lock:
            return [ip for ip, e in self._store.items()
                    if e.username == username and not e.is_expired]

    # ── Background cleanup ────────────────────────────────────────────────────

    def _cleanup_loop(self) -> None:
        """Daemon thread: remove expired entries periodically."""
        while not self._stop_event.wait(timeout=self._cleanup_interval):
            self._remove_expired()

    def _remove_expired(self) -> int:
        """Sweep the store and remove all expired entries."""
        now = time.time()
        with self._lock:
            expired = [
                ip for ip, e in self._store.items()
                if e.expires_at > 0 and now > e.expires_at
            ]
            for ip in expired:
                del self._store[ip]
        if expired:
            logger.debug("[IdentityCache] Cleanup removed %d expired entries", len(expired))
        return len(expired)

    def _evict_oldest(self) -> None:
        """Evict the entry with the oldest last_seen (called under lock)."""
        if not self._store:
            return
        oldest_ip = min(self._store, key=lambda ip: self._store[ip].last_seen)
        del self._store[oldest_ip]
        self._evicts += 1
        logger.debug("[IdentityCache] Evicted oldest entry: %s", oldest_ip)

    def stop(self) -> None:
        """Cleanly stop the background cleanup thread."""
        self._stop_event.set()


# ─────────────────────────────────────────────────────────────────────────────
# Module-level singleton accessor
# ─────────────────────────────────────────────────────────────────────────────

def get_identity_cache() -> IdentityCache:
    """Convenience accessor for the global identity cache."""
    return IdentityCache.instance()
