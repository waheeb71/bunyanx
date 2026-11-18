"""
Enterprise bunyanx NGFW — Category Engine
============================================

Content category-based blocking using a two-level architecture:

  Layer 1 — LRU+TTL In-Memory Cache
      Fast O(1) lookups for recently-seen domains.
      Bounded by `max_size` to prevent unbounded memory growth.
      Entries expire after `ttl_seconds` to pick up policy changes.

  Layer 2 — Database-Backed Classification
      Three-pass matching strategy:
        1. Exact domain match         (e.g. "evil.com")
        2. Suffix/parent domain match (e.g. "ads.evil.com" → "evil.com")
        3. Glob wildcard match        (e.g. "*.evil.com")

  Thread Safety
      All mutable state is protected by an RLock so the engine
      can be shared across asyncio worker threads safely.

Academic Reference:
    LRU algorithm after Sleator & Tarjan (1985).
    Glob matching via stdlib fnmatch (Unix shell wildcard semantics).
"""

import fnmatch
import logging
import threading
import time
import os
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from system.database.database import SessionLocal
from modules.web_filter.models import WebFilterCategory, WebFilterDomain
from modules.web_filter.config.loader import config
from .holo_filter import HoloFilter

logger = logging.getLogger(__name__)

# ─── Public dataclass ────────────────────────────────────────────────────────

@dataclass
class CategoryMatch:
    """Result of a domain classification lookup."""
    domain: str
    categories: List[str]
    confidence: float = 1.0
    cached: bool = False        # True when served from in-memory cache
    matched_pattern: str = ""   # The pattern that triggered the match
    risk_score: float = 0.0     # For AI predictions
    ai_reason: str = ""         # For explainability
    ai_action: str = ""         # Recommended action band


# ─── Bounded LRU+TTL Cache ───────────────────────────────────────────────────

class _LRUCache:
    """
    Thread-safe LRU cache with per-entry TTL.

    Parameters
    ----------
    max_size    : Maximum number of entries. Oldest entry evicted on overflow.
    ttl_seconds : Per-entry time-to-live (seconds).  0 means no expiry.
    """

    def __init__(self, max_size: int = 50_000, ttl_seconds: int = 300):
        self.max_size    = max(1, max_size)
        self.ttl_seconds = ttl_seconds
        self._store: OrderedDict[str, Tuple[CategoryMatch, float]] = OrderedDict()
        self._lock = threading.RLock()

    # Internal helpers --------------------------------------------------------

    def _is_expired(self, ts: float) -> bool:
        if self.ttl_seconds <= 0:
            return False
        return (time.monotonic() - ts) > self.ttl_seconds

    # Public interface --------------------------------------------------------

    def get(self, key: str) -> Optional[CategoryMatch]:
        with self._lock:
            if key not in self._store:
                return None
            match, ts = self._store[key]
            if self._is_expired(ts):
                del self._store[key]
                return None
            # Move to end (most recently used)
            self._store.move_to_end(key)
            match.cached = True
            return match

    def put(self, key: str, match: CategoryMatch) -> None:
        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
            self._store[key] = (match, time.monotonic())
            # Evict oldest entry if over capacity
            while len(self._store) > self.max_size:
                evicted_key, _ = self._store.popitem(last=False)
                logger.debug(f"[CategoryEngine] LRU evict: {evicted_key}")

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    def __len__(self) -> int:
        return len(self._store)

    @property
    def stats(self) -> dict:
        with self._lock:
            now = time.monotonic()
            live = sum(
                1 for _, ts in self._store.values()
                if not self._is_expired(ts)
            )
            return {
                "total_entries": len(self._store),
                "live_entries":  live,
                "max_size":      self.max_size,
                "ttl_seconds":   self.ttl_seconds,
            }


# ─── Category Engine ─────────────────────────────────────────────────────────

class CategoryEngine:
    """
    Domain classification engine with LRU+TTL caching.

    Architecture
    ------------
    The engine maintains three in-memory dictionaries rebuilt from the DB on
    every `reload()` call:

        _exact_domains    : {domain_pattern: category_name}
        _wildcard_domains : {glob_pattern:   category_name}  (ordered by specificity)
        _category_actions : {category_name:  action_str}
        _category_risks   : {category_name:  risk_score}

    A bounded LRU+TTL cache sits in front of all three passes so that repeated
    lookups for the same domain cost O(1) instead of O(D+W) where D is the
    number of exact domains and W is the number of wildcard patterns.
    """

    def __init__(self, max_cache_size: int = None, cache_ttl: int = None):
        # Fetch configurations centrally
        self.cfg = config
        cache_cfg = self.cfg.cache
        ai_cfg = self.cfg.holofilter
        
        limit = max_cache_size if max_cache_size is not None else cache_cfg.get("max_size", 50000)
        ttl = cache_ttl if cache_ttl is not None else cache_cfg.get("ttl_seconds", 300)
        
        self._exact_domains:    Dict[str, str] = {}
        self._wildcard_domains: Dict[str, str] = {}
        self._category_actions: Dict[str, str] = {}
        self._category_risks:   Dict[str, int] = {}
        self._lock = threading.RLock()

        self._cache = _LRUCache(max_size=limit, ttl_seconds=ttl)
        model_path = os.path.join(os.path.dirname(__file__), "..", "evaluation", "datasets", "offline_hv.npz")
        if os.path.exists(os.path.join(os.path.dirname(__file__), "..", "evaluation", "offline_hv.npz")):
            model_path = os.path.join(os.path.dirname(__file__), "..", "evaluation", "offline_hv.npz")
            
        self.model_path = model_path
        self.model_mtime = os.path.getmtime(model_path) if os.path.exists(model_path) else 0.0
        self.last_model_check = 0.0
        
        self.holo = HoloFilter(model_path=model_path, config=ai_cfg)
        self.reload()

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def reload(self) -> None:
        """
        Reload the classification tables from the database.

        Clears the in-memory cache so that stale classifications are not
        served after an admin updates a category action or adds a new domain.
        """
        with self._lock:
            try:
                with SessionLocal() as db:
                    from system.database.database import Base
                    import modules.web_filter.models
                    try:
                        Base.metadata.create_all(bind=db.get_bind())
                    except Exception:
                        pass

                    cats = db.query(WebFilterCategory).all()
                    self._category_actions = {c.name.lower().strip(): c.action     for c in cats}
                    self._category_risks   = {c.name.lower().strip(): c.risk_score for c in cats}

                    domains = db.query(WebFilterDomain).all()
                    self._exact_domains.clear()
                    self._wildcard_domains.clear()

                    for d in domains:
                        pattern = d.domain_pattern.lower().strip()
                        cat_name = (d.category_name or "").lower().strip()
                        if "*" in pattern or "?" in pattern:
                            self._wildcard_domains[pattern] = cat_name
                        else:
                            self._exact_domains[pattern] = cat_name
            except Exception as exc:
                logger.warning(f"[CategoryEngine] Database load warning: {exc} — using built-in security fallbacks.")

            # Invalidate the entire cache — policy may have changed
            self._cache.clear()

        logger.info(
            f"[CategoryEngine] Reloaded: "
            f"{len(self._exact_domains)} exact, "
            f"{len(self._wildcard_domains)} wildcard domains, "
            f"{len(self._category_actions)} categories."
        )

    # ── Classification ────────────────────────────────────────────────────────

    def categorize(self, domain: str) -> CategoryMatch:
        """
        Classify a domain using the three-pass matching strategy.

        Returns a :class:`CategoryMatch` with `categories` containing
        the matched category name(s), or ``["UNRATED"]`` when no rule
        applies.

        The result is stored in the LRU+TTL cache so repeated lookups
        are served in O(1) without hitting the classification tables.
        """
        domain = domain.lower().strip()

        # Check if the model file has been updated
        import time
        now = time.time()
        if now - getattr(self, "last_model_check", 0.0) > 5.0:
            self.last_model_check = now
            if os.path.exists(self.model_path):
                mtime = os.path.getmtime(self.model_path)
                if mtime > getattr(self, "model_mtime", 0.0):
                    logger.info(f"[CategoryEngine] Re-loading updated HoloFilter model from {self.model_path}")
                    self.holo = HoloFilter(model_path=self.model_path, config=self.cfg.holofilter)
                    self.model_mtime = mtime

        # ── Pass 0: Cache hit ─────────────────────────────────────
        cached = self._cache.get(domain)
        if cached is not None:
            logger.debug(f"[CategoryEngine] Cache hit: {domain}")
            return cached

        with self._lock:
            result = self._classify(domain)

        self._cache.put(domain, result)
        return result

    def _classify(self, domain: str) -> CategoryMatch:
        """Internal classification — caller must hold self._lock."""

        # Pass 1 — Exact match
        if domain in self._exact_domains:
            cat = self._exact_domains[domain]
            return CategoryMatch(
                domain=domain,
                categories=[cat] if cat else ["UNRATED"],
                matched_pattern=domain,
            )

        # Pass 2 — Parent-domain suffix match
        #   "ads.tracker.evil.com" → try "tracker.evil.com" → "evil.com"
        parts = domain.split(".")
        for i in range(1, len(parts) - 1):
            candidate = ".".join(parts[i:])
            if candidate in self._exact_domains:
                cat = self._exact_domains[candidate]
                return CategoryMatch(
                    domain=domain,
                    categories=[cat] if cat else ["UNRATED"],
                    matched_pattern=candidate,
                )

        # Pass 3 — Wildcard (glob) match
        for pattern, cat in self._wildcard_domains.items():
            if fnmatch.fnmatch(domain, pattern):
                return CategoryMatch(
                    domain=domain,
                    categories=[cat] if cat else ["UNRATED"],
                    matched_pattern=pattern,
                )
                
        # Pass 4 — HoloFilter Machine Learning (Zero Latency)
        if getattr(self, 'cfg', config).holofilter.get("enabled", True) and self.holo.ready:
            h_res = self.holo.evaluate(domain)
            if h_res["action"] != "ALLOW":
                cat_name = f"AI_{h_res['action']}"
                return CategoryMatch(
                    domain=domain,
                    categories=[cat_name],
                    confidence=h_res["risk"],
                    matched_pattern="HDC_Model",
                    risk_score=h_res["risk"] * 100.0,
                    ai_reason=h_res["reason"],
                    ai_action=h_res["action"]
                )

        return CategoryMatch(domain=domain, categories=["UNRATED"])

    # ── Query helpers ─────────────────────────────────────────────────────────

    def get_category_action(self, category_name: str) -> str:
        """Return the configured action string for a category, default ALLOW."""
        if not category_name:
            return "ALLOW"
        category_name = category_name.lower().strip()
        if category_name.startswith("ai_"):
            return category_name.replace("ai_", "").upper()

        default_dangerous = {
            "hacking": "BLOCK",
            "malware": "BLOCK",
            "phishing": "BLOCK",
            "botnet": "BLOCK",
            "ransomware": "BLOCK",
            "c2": "BLOCK",
            "adult": "BLOCK",
            "gambling": "BLOCK"
        }
        return self._category_actions.get(category_name, default_dangerous.get(category_name, "ALLOW"))

    def get_category_risk(self, category_name: str) -> int:
        """Return the risk score (0-100) for a category, default 0."""
        if not category_name:
            return 0
        category_name = category_name.lower().strip()
        if category_name.startswith("ai_"):
            return 85

        default_risks = {
            "hacking": 90,
            "malware": 100,
            "phishing": 100,
            "botnet": 100,
            "ransomware": 100,
            "c2": 100,
            "adult": 80,
            "gambling": 70
        }
        return self._category_risks.get(category_name, default_risks.get(category_name, 0))

    def is_high_risk(self, domain: str, threshold: int = 70) -> bool:
        """Convenience: returns True if the domain's risk score ≥ threshold."""
        match = self.categorize(domain)
        return any(
            self.get_category_risk(c) >= threshold
            for c in match.categories
            if c != "UNRATED"
        )

    # ── Introspection ─────────────────────────────────────────────────────────

    @property
    def cache_stats(self) -> dict:
        """Return current LRU cache metrics for monitoring."""
        return self._cache.stats
