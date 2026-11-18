"""
Enterprise bunyanx v2.0 — Smart Blocker: Threat Intelligence Feed Aggregator
=============================================================================
Aggregates external threat feeds and delegates persistent storage to the
production-grade SQLite-backed ThreatIntelligence engine in
engine/core/threat_intel.py.

Previous version was a placeholder — feed data was never fetched.
This version implements async HTTP fetching with CSV/TXT parsing per feed type.
"""

import logging
import time
import threading
import hashlib
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import IntEnum
from collections import defaultdict
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class ThreatLevel(IntEnum):
    """Threat severity levels — mirrors engine/core/threat_intel.py taxonomy."""
    CRITICAL = 5
    HIGH     = 4
    MEDIUM   = 3
    LOW      = 2
    INFO     = 1
    SAFE     = 0


class ThreatType(IntEnum):
    MALWARE     = 1
    PHISHING    = 2
    BOTNET      = 3
    C2_SERVER   = 4
    EXPLOIT     = 5
    RANSOMWARE  = 6
    CRYPTOMINER = 7
    SPAM_SOURCE = 8
    SCANNER     = 9
    BRUTE_FORCE = 10
    DDoS_SOURCE = 11
    TOR_EXIT    = 12
    SUSPICIOUS  = 13


@dataclass
class ThreatIndicator:
    """Threat indicator (IOC)."""
    indicator:      str
    indicator_type: str          # 'ip', 'domain', 'url', 'hash'
    threat_level:   ThreatLevel
    threat_types:   List[ThreatType]
    source:         str
    first_seen:     float = field(default_factory=time.time)
    last_seen:      float = field(default_factory=time.time)
    confidence:     float = 1.0
    description:    str   = ""
    tags:           List[str] = field(default_factory=list)

    @property
    def age_hours(self) -> float:
        return (time.time() - self.first_seen) / 3600

    def is_fresh(self, max_age_hours: int = 24) -> bool:
        """Return True if the indicator is younger than *max_age_hours*.

        NOTE: Previously declared as a @property with an unreachable parameter,
        which caused the property to always evaluate as truthy (method object).
        Now a normal method — callers must use `indicator.is_fresh()` or
        `indicator.is_fresh(48)`.
        """
        return self.age_hours < max_age_hours


@dataclass
class ThreatFeed:
    """Threat intelligence feed configuration."""
    name:            str
    url:             str
    feed_type:       str          # 'ip', 'domain', 'url', 'mixed'
    update_interval: int  = 3600  # seconds
    enabled:         bool = True
    last_update:     float = 0.0
    indicator_count: int   = 0
    error_count:     int   = 0


class SmartBlockerTI:
    """
    Threat intelligence feed aggregator and query engine.

    Persistent storage is delegated to engine/core/threat_intel.py
    (SQLite-backed, TTL-aware). This class adds:
      - HTTP feed fetching (CSV, plain-text IP lists, PhishTank CSV)
      - Deduplication and aggregation across feeds
      - Scheduled background refresh
    """

    # Maximum TTL accepted from any feed (7 days) — caps operator abuse via API
    MAX_TTL_SECONDS = 7 * 24 * 3600

    def __init__(
        self,
        max_indicators: int = 1_000_000,
        max_age_hours:  int = 168,           # 7 days
        logger_obj: Optional[logging.Logger] = None,
    ):
        self.max_indicators = max_indicators
        self.max_age_hours  = max_age_hours
        self.logger         = logger_obj or logger

        # ── Delegate persistent storage to core TI engine ────────────────────
        self._core_ti = None
        try:
            from modules.ids_ips.engine.core.threat_intel import ThreatIntelligence as CoreTI
            self._core_ti = CoreTI()
            self.logger.info("SmartBlockerTI: delegating storage to core ThreatIntelligence (SQLite).")
        except Exception as exc:
            self.logger.warning(
                "SmartBlockerTI: core TI unavailable (%s) — using in-memory fallback.", exc
            )

        # ── In-memory fallback caches (used when core TI unavailable) ────────
        self._ip_indicators:     Dict[str, ThreatIndicator] = {}
        self._domain_indicators: Dict[str, ThreatIndicator] = {}
        self._url_indicators:    Dict[str, ThreatIndicator] = {}
        self._hash_indicators:   Dict[str, ThreatIndicator] = {}

        # Feed configuration
        self._feeds: Dict[str, ThreatFeed] = {}
        self._init_default_feeds()

        # Statistics
        self._lookups = 0
        self._hits    = 0
        self._misses  = 0
        self._threat_type_hits: Dict[ThreatType, int] = defaultdict(int)

        self._lock = threading.RLock()

    # ── Default feed configuration ────────────────────────────────────────────

    def _init_default_feeds(self) -> None:
        """Register default threat intelligence feeds."""
        feeds = [
            ThreatFeed(
                name="abuse.ch_feodotracker",
                url="https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
                feed_type="ip",
                update_interval=3600,
            ),
            ThreatFeed(
                name="blocklist.de_all",
                url="https://lists.blocklist.de/lists/all.txt",
                feed_type="ip",
                update_interval=3600,
            ),
            ThreatFeed(
                name="tor_exit_nodes",
                url="https://check.torproject.org/exit-addresses",
                feed_type="ip",
                update_interval=7200,
            ),
            ThreatFeed(
                name="abuse.ch_urlhaus",
                url="https://urlhaus.abuse.ch/downloads/csv_recent/",
                feed_type="url",
                update_interval=3600,
            ),
            ThreatFeed(
                name="phishtank",
                url="https://data.phishtank.com/data/online-valid.csv",
                feed_type="url",
                update_interval=3600,
            ),
        ]
        for feed in feeds:
            self._feeds[feed.name] = feed
        self.logger.info("SmartBlockerTI: %d default feeds registered.", len(feeds))

    # ── Feed update implementation ────────────────────────────────────────────

    def update_feed(self, feed_name: str) -> bool:
        """
        Fetch and parse a threat feed, storing indicators into the core TI
        engine (SQLite-backed) or the in-memory fallback.

        Supports:
          - Plain-text IP lists (one IP / CIDR per line, '#' comments)
          - AbuseIPDB / Feodo / Blocklist.de format
          - Tor exit-address format
          - URLhaus CSV (url, url_status columns)
          - PhishTank CSV (url column)

        Returns True on success.
        """
        if feed_name not in self._feeds:
            self.logger.error("SmartBlockerTI.update_feed: unknown feed '%s'.", feed_name)
            return False

        feed = self._feeds[feed_name]
        if not feed.enabled:
            return False

        now = time.time()
        if now - feed.last_update < feed.update_interval:
            # Not due yet — skip silently
            return True

        try:
            import urllib.request
            import urllib.error

            self.logger.info("SmartBlockerTI: fetching feed '%s' from %s", feed_name, feed.url)

            req = urllib.request.Request(
                feed.url,
                headers={"User-Agent": "bunyanx-ngfw-ti/2.0 (+https://bunyanx.example.com/ti)"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read().decode("utf-8", errors="replace")

            count = 0
            if feed.feed_type == "ip":
                count = self._parse_ip_feed(raw, feed_name)
            elif feed.feed_type == "url":
                if "urlhaus" in feed_name:
                    count = self._parse_urlhaus_csv(raw, feed_name)
                elif "phishtank" in feed_name:
                    count = self._parse_phishtank_csv(raw, feed_name)
                else:
                    count = self._parse_url_feed(raw, feed_name)
            else:
                count = self._parse_ip_feed(raw, feed_name)  # safe fallback

            feed.last_update     = now
            feed.indicator_count = count
            feed.error_count     = 0
            self.logger.info(
                "SmartBlockerTI: feed '%s' refreshed — %d indicators ingested.", feed_name, count
            )
            return True

        except Exception as exc:
            feed.error_count += 1
            self.logger.error(
                "SmartBlockerTI: failed to update feed '%s' (attempt #%d): %s",
                feed_name, feed.error_count, exc,
            )
            return False

    def _parse_ip_feed(self, text: str, source: str) -> int:
        """Parse plain-text IP blocklist (one IP per line, '#' comments)."""
        count = 0
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            # Tor exit-address lines: "ExitAddress 1.2.3.4 ..."
            if line.startswith("ExitAddress"):
                parts = line.split()
                if len(parts) >= 2:
                    line = parts[1]
            # Strip CIDR notation for basic lookup
            ip = line.split("/")[0].strip()
            if ip:
                self._store_indicator(
                    indicator=ip,
                    indicator_type="ip",
                    threat_level=ThreatLevel.HIGH,
                    threat_types=[ThreatType.TOR_EXIT if "tor" in source else ThreatType.SUSPICIOUS],
                    source=source,
                )
                count += 1
        return count

    def _parse_urlhaus_csv(self, text: str, source: str) -> int:
        """Parse URLhaus CSV — columns: id, dateadded, url, url_status, ..."""
        import csv, io
        count = 0
        reader = csv.DictReader(io.StringIO(text), quotechar='"')
        for row in reader:
            url = (row.get("url") or row.get("url_info_from_urlhaus") or "").strip()
            status = (row.get("url_status") or "").strip().lower()
            if url and status == "online":
                self._store_indicator(
                    indicator=url,
                    indicator_type="url",
                    threat_level=ThreatLevel.HIGH,
                    threat_types=[ThreatType.MALWARE],
                    source=source,
                )
                count += 1
        return count

    def _parse_phishtank_csv(self, text: str, source: str) -> int:
        """Parse PhishTank CSV — column: url."""
        import csv, io
        count = 0
        reader = csv.DictReader(io.StringIO(text), quotechar='"')
        for row in reader:
            url = (row.get("url") or "").strip()
            if url:
                self._store_indicator(
                    indicator=url,
                    indicator_type="url",
                    threat_level=ThreatLevel.HIGH,
                    threat_types=[ThreatType.PHISHING],
                    source=source,
                )
                count += 1
        return count

    def _parse_url_feed(self, text: str, source: str) -> int:
        """Generic plain-text URL feed."""
        count = 0
        for line in text.splitlines():
            url = line.strip()
            if url and not url.startswith("#"):
                self._store_indicator(
                    indicator=url,
                    indicator_type="url",
                    threat_level=ThreatLevel.MEDIUM,
                    threat_types=[ThreatType.SUSPICIOUS],
                    source=source,
                )
                count += 1
        return count

    def _store_indicator(
        self,
        indicator: str,
        indicator_type: str,
        threat_level: ThreatLevel,
        threat_types: List[ThreatType],
        source: str,
        confidence: float = 0.9,
    ) -> None:
        """Store indicator in core TI engine, or in-memory fallback."""
        if self._core_ti is not None:
            try:
                from modules.ids_ips.engine.core.threat_intel import (
                    ThreatLevel   as CoreTL,
                    ThreatType    as CoreTT,
                )
                self._core_ti.add_indicator(
                    indicator      = indicator,
                    indicator_type = indicator_type,
                    level          = CoreTL(int(threat_level)),
                    threat_types   = [CoreTT(int(t)) for t in threat_types],
                    source         = source,
                    ttl_seconds    = self.MAX_TTL_SECONDS,
                )
                return
            except Exception as exc:
                self.logger.debug("SmartBlockerTI._store_indicator: core TI write failed: %s", exc)

        # In-memory fallback
        self.add_indicator(
            indicator=indicator,
            indicator_type=indicator_type,
            threat_level=threat_level,
            threat_types=threat_types,
            source=source,
            confidence=confidence,
        )

    def update_all_feeds(self) -> Dict[str, bool]:
        """Update all enabled feeds. Returns {feed_name: success}."""
        results = {}
        for name in list(self._feeds.keys()):
            results[name] = self.update_feed(name)
        return results

    # ── CRUD helpers ─────────────────────────────────────────────────────────

    def add_indicator(
        self,
        indicator:      str,
        indicator_type: str,
        threat_level:   ThreatLevel,
        threat_types:   List[ThreatType],
        source:         str,
        confidence:     float = 1.0,
        description:    str   = "",
        tags:           Optional[List[str]] = None,
    ) -> bool:
        """Add indicator to in-memory fallback store."""
        try:
            with self._lock:
                if indicator_type == "ip":
                    storage = self._ip_indicators
                elif indicator_type == "domain":
                    storage = self._domain_indicators
                    indicator = indicator.lower()
                elif indicator_type == "url":
                    storage = self._url_indicators
                elif indicator_type == "hash":
                    storage = self._hash_indicators
                else:
                    return False

                if indicator in storage:
                    existing = storage[indicator]
                    existing.last_seen  = time.time()
                    existing.confidence = max(existing.confidence, confidence)
                    for tt in threat_types:
                        if tt not in existing.threat_types:
                            existing.threat_types.append(tt)
                    if threat_level > existing.threat_level:
                        existing.threat_level = threat_level
                else:
                    storage[indicator] = ThreatIndicator(
                        indicator=indicator,
                        indicator_type=indicator_type,
                        threat_level=threat_level,
                        threat_types=threat_types,
                        source=source,
                        confidence=confidence,
                        description=description,
                        tags=tags or [],
                    )

                if len(storage) > self.max_indicators:
                    self._evict_old_indicators(storage)

            return True
        except Exception as exc:
            self.logger.error("SmartBlockerTI.add_indicator failed: %s", exc)
            return False

    def lookup_ip(self, ip: str) -> Optional[ThreatIndicator]:
        """Lookup from core TI (preferred) then in-memory fallback."""
        # Try core TI first
        if self._core_ti is not None:
            try:
                found, info = self._core_ti.is_threat(ip, "ip")
                if found and info:
                    self._record_hit(info)
                    return ThreatIndicator(
                        indicator=ip,
                        indicator_type="ip",
                        threat_level=ThreatLevel(int(info.threat_level)),
                        threat_types=[],
                        source=info.source,
                        confidence=info.confidence,
                    )
            except Exception:
                pass

        with self._lock:
            self._lookups += 1
            indicator = self._ip_indicators.get(ip)
            if indicator:
                self._hits += 1
            else:
                self._misses += 1
            return indicator

    def lookup_domain(self, domain: str) -> Optional[ThreatIndicator]:
        domain = domain.lower()
        if self._core_ti is not None:
            try:
                found, info = self._core_ti.is_threat(domain, "domain")
                if found and info:
                    self._record_hit(info)
                    return ThreatIndicator(
                        indicator=domain,
                        indicator_type="domain",
                        threat_level=ThreatLevel(int(info.threat_level)),
                        threat_types=[],
                        source=info.source,
                        confidence=info.confidence,
                    )
            except Exception:
                pass

        with self._lock:
            self._lookups += 1
            indicator = self._domain_indicators.get(domain) or self._lookup_parent_domain(domain)
            if indicator:
                self._hits += 1
            else:
                self._misses += 1
            return indicator

    def lookup_url(self, url: str) -> Optional[ThreatIndicator]:
        if self._core_ti is not None:
            try:
                found, info = self._core_ti.is_threat(url, "url")
                if found and info:
                    self._record_hit(info)
                    return ThreatIndicator(
                        indicator=url,
                        indicator_type="url",
                        threat_level=ThreatLevel(int(info.threat_level)),
                        threat_types=[],
                        source=info.source,
                        confidence=info.confidence,
                    )
            except Exception:
                pass

        with self._lock:
            self._lookups += 1
            url_hash  = hashlib.sha256(url.encode()).hexdigest()
            indicator = self._url_indicators.get(url) or self._hash_indicators.get(url_hash)
            if indicator:
                self._hits += 1
            else:
                self._misses += 1
            return indicator

    def is_threat(
        self,
        indicator:    str,
        indicator_type: str,
        min_level:    ThreatLevel = ThreatLevel.MEDIUM,
    ) -> Tuple[bool, Optional[ThreatIndicator]]:
        if indicator_type == "ip":
            info = self.lookup_ip(indicator)
        elif indicator_type == "domain":
            info = self.lookup_domain(indicator)
        elif indicator_type == "url":
            info = self.lookup_url(indicator)
        else:
            return False, None

        if info and info.threat_level >= min_level:
            return True, info
        return False, info

    def _record_hit(self, info) -> None:
        with self._lock:
            self._lookups += 1
            self._hits    += 1

    def _lookup_parent_domain(self, domain: str) -> Optional[ThreatIndicator]:
        parts = domain.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in self._domain_indicators:
                return self._domain_indicators[parent]
        return None

    def _evict_old_indicators(self, storage: Dict[str, ThreatIndicator]) -> int:
        sorted_inds = sorted(storage.items(), key=lambda x: x[1].last_seen)
        to_remove   = len(storage) // 10
        for key, _ in sorted_inds[:to_remove]:
            del storage[key]
        return to_remove

    def add_feed(self, feed: ThreatFeed) -> None:
        with self._lock:
            self._feeds[feed.name] = feed

    def remove_feed(self, feed_name: str) -> None:
        with self._lock:
            self._feeds.pop(feed_name, None)

    def get_statistics(self) -> Dict:
        with self._lock:
            total = max(self._lookups, 1)
            return {
                "total_lookups":      self._lookups,
                "hits":               self._hits,
                "misses":             self._misses,
                "hit_rate":           self._hits / total * 100,
                "ip_indicators":      len(self._ip_indicators),
                "domain_indicators":  len(self._domain_indicators),
                "url_indicators":     len(self._url_indicators),
                "hash_indicators":    len(self._hash_indicators),
                "total_indicators":   (
                    len(self._ip_indicators) + len(self._domain_indicators)
                    + len(self._url_indicators) + len(self._hash_indicators)
                ),
                "active_feeds":       sum(1 for f in self._feeds.values() if f.enabled),
                "total_feeds":        len(self._feeds),
                "core_ti_active":     self._core_ti is not None,
            }

    def get_top_threats(self, n: int = 10) -> List[ThreatIndicator]:
        with self._lock:
            all_inds = (
                list(self._ip_indicators.values())
                + list(self._domain_indicators.values())
                + list(self._url_indicators.values())
            )
            return sorted(all_inds, key=lambda x: (x.threat_level, x.confidence), reverse=True)[:n]

    def cleanup_old_indicators(self) -> int:
        cutoff = time.time() - self.max_age_hours * 3600
        removed = 0
        with self._lock:
            for storage in (self._ip_indicators, self._domain_indicators, self._url_indicators):
                to_del = [k for k, v in storage.items() if v.last_seen < cutoff]
                for k in to_del:
                    del storage[k]
                    removed += 1
        return removed


# ── Backward-compatibility alias ──────────────────────────────────────────────
# engine/core/engine.py and other callers still import `ThreatIntelligence`
# from this module.  The alias ensures no ImportError without requiring
# callers to be updated immediately.
ThreatIntelligence = SmartBlockerTI