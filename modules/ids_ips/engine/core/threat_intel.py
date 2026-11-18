"""
Enterprise bunyanx — Threat Intelligence Engine
===================================================
Persistent, TTL-aware aggregator for IP, domain, and URL threat indicators.

Features
--------
* SQLite-backed storage — survives process restarts
* Per-indicator TTL (default 24 h, configurable)
* Hourly background cleanup of expired indicators
* CSV loader  (AbuseIPDB, Feodo Tracker, custom lists)
* MISP JSON loader (standard MISP attribute export)
* Thread-safe read/write via RLock
* In-memory hot cache (dict) for O(1) lookup after initial load

DB file is stored next to this module at:
    <ids_ips_dir>/data/threat_intel.db

Usage
-----
    ti = ThreatIntelligence()
    ti.load_from_csv("/feeds/abuseipdb_blocklist.csv", indicator_col="ip")
    found, info = ti.is_threat("1.2.3.4", "ip")
"""

from __future__ import annotations

import csv
import json
import logging
import os
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Threat taxonomy
# ---------------------------------------------------------------------------

class ThreatLevel(IntEnum):
    CRITICAL = 5
    HIGH     = 4
    MEDIUM   = 3
    LOW      = 2
    INFO     = 1
    SAFE     = 0


class ThreatType(IntEnum):
    MALWARE      = 1
    PHISHING     = 2
    BOTNET       = 3
    C2_SERVER    = 4
    EXPLOIT      = 5
    RANSOMWARE   = 6
    CRYPTOMINER  = 7
    SPAM_SOURCE  = 8
    SCANNER      = 9
    BRUTE_FORCE  = 10
    DDOS_SOURCE  = 11
    TOR_EXIT     = 12
    SUSPICIOUS   = 13


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ThreatIndicator:
    indicator:      str
    indicator_type: str          # "ip" | "domain" | "url"
    threat_level:   ThreatLevel
    threat_types:   List[ThreatType]
    source:         str
    first_seen:     float = field(default_factory=time.time)
    last_seen:      float = field(default_factory=time.time)
    confidence:     float = 1.0
    expires_at:     float = field(default_factory=lambda: time.time() + 86400)

    # Convenience
    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def to_row(self) -> tuple:
        """SQLite INSERT tuple."""
        return (
            self.indicator,
            self.indicator_type,
            int(self.threat_level),
            json.dumps([int(t) for t in self.threat_types]),
            self.source,
            self.first_seen,
            self.last_seen,
            self.confidence,
            self.expires_at,
        )

    @staticmethod
    def from_row(row: tuple) -> "ThreatIndicator":
        """Reconstruct from SQLite SELECT row."""
        (indicator, itype, level, types_json,
         source, first_seen, last_seen, confidence, expires_at) = row
        return ThreatIndicator(
            indicator      = indicator,
            indicator_type = itype,
            threat_level   = ThreatLevel(level),
            threat_types   = [ThreatType(t) for t in json.loads(types_json)],
            source         = source,
            first_seen     = first_seen,
            last_seen      = last_seen,
            confidence     = confidence,
            expires_at     = expires_at,
        )


# ---------------------------------------------------------------------------
# SQLite schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS threat_indicators (
    indicator      TEXT NOT NULL,
    indicator_type TEXT NOT NULL,
    threat_level   INTEGER NOT NULL,
    threat_types   TEXT NOT NULL,        -- JSON array of ThreatType int values
    source         TEXT NOT NULL,
    first_seen     REAL NOT NULL,
    last_seen      REAL NOT NULL,
    confidence     REAL NOT NULL DEFAULT 1.0,
    expires_at     REAL NOT NULL,
    PRIMARY KEY (indicator, indicator_type)
);
CREATE INDEX IF NOT EXISTS idx_expires_at ON threat_indicators(expires_at);
CREATE INDEX IF NOT EXISTS idx_type       ON threat_indicators(indicator_type);
"""


# ---------------------------------------------------------------------------
# ThreatIntelligence engine
# ---------------------------------------------------------------------------

class ThreatIntelligence:
    """
    Persistent, TTL-aware threat intelligence aggregator.

    Parameters
    ----------
    db_path  : path to the SQLite database file
               (default: <module_dir>/../../data/threat_intel.db)
    default_ttl_seconds : TTL applied to new indicators (default 86 400 = 24 h)
    cleanup_interval_s  : background cleanup timer interval (default 3 600 = 1 h)
    """

    _DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "threat_intel.db"

    def __init__(
        self,
        db_path: Optional[str] = None,
        default_ttl_seconds: int = 86_400,
        cleanup_interval_s: int = 3_600,
    ) -> None:
        self._db_path = Path(db_path) if db_path else self._DEFAULT_DB_PATH
        self._ttl = default_ttl_seconds
        self._cleanup_interval = cleanup_interval_s
        self._lock = threading.RLock()

        # In-memory hot cache: (indicator, type) → ThreatIndicator
        self._cache: Dict[Tuple[str, str], ThreatIndicator] = {}

        # Ensure parent directory exists
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

        self._init_db()
        self._load_into_cache()
        self._start_cleanup_timer()

        # Register singleton with API layer
        try:
            from modules.ids_ips.api.router import register_threat_intel
            register_threat_intel(self)
        except Exception as e:
            logger.warning("ThreatIntelligence: failed to register with API router: %s", e)

        logger.info(
            "ThreatIntelligence: loaded %d indicators from %s",
            len(self._cache),
            self._db_path,
        )

    # ------------------------------------------------------------------
    # DB initialisation
    # ------------------------------------------------------------------

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL;")   # concurrent reads + writes
        conn.execute("PRAGMA synchronous=NORMAL;") # safe + fast
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.executescript(_SCHEMA)

    def _load_into_cache(self) -> None:
        """Load all non-expired rows from DB into the hot cache."""
        now = time.time()
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT indicator, indicator_type, threat_level, threat_types, "
                "source, first_seen, last_seen, confidence, expires_at "
                "FROM threat_indicators WHERE expires_at > ?",
                (now,),
            )
            with self._lock:
                self._cache.clear()
                for row in cursor.fetchall():
                    ti = ThreatIndicator.from_row(row)
                    self._cache[(ti.indicator, ti.indicator_type)] = ti

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_indicator(
        self,
        indicator: str,
        indicator_type: str,
        level: ThreatLevel,
        threat_types: List[ThreatType],
        source: str,
        confidence: float = 1.0,
        ttl_seconds: Optional[int] = None,
    ) -> None:
        """
        Add (or update) a threat indicator.

        If the indicator already exists, its `last_seen` and `expires_at`
        are refreshed and the worst-case `threat_level` is preserved.
        """
        ttl = ttl_seconds if ttl_seconds is not None else self._ttl
        now = time.time()
        key = (indicator, indicator_type)

        with self._lock:
            existing = self._cache.get(key)
            if existing:
                # Update: keep maximum threat_level, refresh timestamps
                merged_level = ThreatLevel(max(int(existing.threat_level), int(level)))
                merged_types = list(set(existing.threat_types) | set(threat_types))
                ti = ThreatIndicator(
                    indicator      = indicator,
                    indicator_type = indicator_type,
                    threat_level   = merged_level,
                    threat_types   = merged_types,
                    source         = source,
                    first_seen     = existing.first_seen,
                    last_seen      = now,
                    confidence     = max(existing.confidence, confidence),
                    expires_at     = now + ttl,
                )
            else:
                ti = ThreatIndicator(
                    indicator      = indicator,
                    indicator_type = indicator_type,
                    threat_level   = level,
                    threat_types   = threat_types,
                    source         = source,
                    first_seen     = now,
                    last_seen      = now,
                    confidence     = confidence,
                    expires_at     = now + ttl,
                )
            self._cache[key] = ti

        # Persist to DB (UPSERT)
        self._upsert(ti)

    def is_threat(
        self, indicator: str, indicator_type: str
    ) -> Tuple[bool, Optional[ThreatIndicator]]:
        """
        O(1) lookup in the hot cache.

        Returns
        -------
        (True, ThreatIndicator)  if found and not expired
        (False, None)            otherwise
        """
        key = (indicator, indicator_type)
        with self._lock:
            ti = self._cache.get(key)

        if ti is None:
            return False, None
        if ti.is_expired:
            # Lazy eviction from cache
            with self._lock:
                self._cache.pop(key, None)
            return False, None
        return True, ti

    def remove_indicator(self, indicator: str, indicator_type: str) -> None:
        """Manually remove an indicator from cache and DB."""
        key = (indicator, indicator_type)
        with self._lock:
            self._cache.pop(key, None)
            with self._get_connection() as conn:
                conn.execute(
                    "DELETE FROM threat_indicators WHERE indicator=? AND indicator_type=?",
                    (indicator, indicator_type),
                )

    def count(self) -> dict:
        """Return indicator counts by type."""
        with self._lock:
            by_type: Dict[str, int] = {}
            for (_, itype) in self._cache:
                by_type[itype] = by_type.get(itype, 0) + 1
        return by_type

    # ------------------------------------------------------------------
    # Feed loaders
    # ------------------------------------------------------------------

    def load_from_csv(
        self,
        path: str,
        indicator_col: str = "ip",
        indicator_type: str = "ip",
        level: ThreatLevel = ThreatLevel.HIGH,
        source: str = "csv_feed",
        ttl_seconds: Optional[int] = None,
        skip_rows: int = 0,
    ) -> int:
        """
        Load threat indicators from a CSV file.

        Supports AbuseIPDB export format (column "ip") and generic
        single-column lists.

        Parameters
        ----------
        path           : path to the CSV file
        indicator_col  : column name containing the indicator value
        indicator_type : "ip", "domain", or "url"
        level          : default ThreatLevel
        source         : label stored with each indicator
        skip_rows      : skip this many header rows before the CSV header

        Returns number of indicators successfully added.
        """
        loaded = 0
        try:
            with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
                for _ in range(skip_rows):
                    next(fh)
                reader = csv.DictReader(fh)
                for row in reader:
                    val = row.get(indicator_col, "").strip()
                    if not val or val.startswith("#"):
                        continue
                    self.add_indicator(
                        indicator      = val,
                        indicator_type = indicator_type,
                        level          = level,
                        threat_types   = [ThreatType.SUSPICIOUS],
                        source         = source,
                        ttl_seconds    = ttl_seconds,
                    )
                    loaded += 1
        except FileNotFoundError:
            logger.warning("Threat Intel CSV not found: %s", path)
        except Exception as exc:
            logger.error("Error loading CSV feed %s: %s", path, exc)

        logger.info("ThreatIntel: loaded %d indicators from CSV %s", loaded, path)
        return loaded

    def load_from_misp_json(
        self,
        path: str,
        source: str = "misp",
        ttl_seconds: Optional[int] = None,
    ) -> int:
        """
        Load indicators from a MISP attribute-export JSON file.

        Expected format (standard MISP export):
            {"Attribute": [{"type": "ip-dst", "value": "1.2.3.4", ...}, ...]}

        Supports types: ip-dst, ip-src, domain, url, hostname
        """
        _MISP_TYPE_MAP = {
            "ip-dst":   ("ip",     ThreatLevel.HIGH),
            "ip-src":   ("ip",     ThreatLevel.MEDIUM),
            "domain":   ("domain", ThreatLevel.HIGH),
            "hostname": ("domain", ThreatLevel.MEDIUM),
            "url":      ("url",    ThreatLevel.HIGH),
        }
        loaded = 0
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            attributes = data.get("Attribute", [])
            for attr in attributes:
                misp_type = attr.get("type", "")
                val = attr.get("value", "").strip()
                if not val or misp_type not in _MISP_TYPE_MAP:
                    continue
                itype, level = _MISP_TYPE_MAP[misp_type]
                self.add_indicator(
                    indicator      = val,
                    indicator_type = itype,
                    level          = level,
                    threat_types   = [ThreatType.SUSPICIOUS],
                    source         = source,
                    ttl_seconds    = ttl_seconds,
                )
                loaded += 1
        except FileNotFoundError:
            logger.warning("MISP JSON not found: %s", path)
        except Exception as exc:
            logger.error("Error loading MISP JSON %s: %s", path, exc)

        logger.info("ThreatIntel: loaded %d MISP indicators from %s", loaded, path)
        return loaded

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _upsert(self, ti: ThreatIndicator) -> None:
        """Write or update a single indicator in the DB."""
        with self._lock:
            try:
                with self._get_connection() as conn:
                    conn.execute(
                        """
                        INSERT INTO threat_indicators
                            (indicator, indicator_type, threat_level, threat_types,
                             source, first_seen, last_seen, confidence, expires_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(indicator, indicator_type) DO UPDATE SET
                            threat_level = MAX(threat_level, excluded.threat_level),
                            threat_types = excluded.threat_types,
                            last_seen    = excluded.last_seen,
                            confidence   = MAX(confidence, excluded.confidence),
                            expires_at   = excluded.expires_at
                        """,
                        ti.to_row(),
                    )
            except Exception as exc:
                logger.error("ThreatIntel DB upsert failed: %s", exc)

    def cleanup_expired(self) -> int:
        """
        Remove expired indicators from both cache and DB.

        Called automatically by the background timer but can also be
        invoked manually.

        Returns the number of indicators removed.
        """
        now = time.time()
        removed = 0

        with self._lock:
            # Cache cleanup
            expired_keys = [
                k for k, ti in self._cache.items() if ti.expires_at <= now
            ]
            for k in expired_keys:
                del self._cache[k]
                removed += 1

            # DB cleanup
            try:
                with self._get_connection() as conn:
                    cursor = conn.execute(
                        "DELETE FROM threat_indicators WHERE expires_at <= ?", (now,)
                    )
                    removed = max(removed, cursor.rowcount)
            except Exception as exc:
                logger.error("ThreatIntel cleanup DB error: %s", exc)

        if removed:
            logger.info("ThreatIntel: removed %d expired indicators", removed)
        return removed

    def _start_cleanup_timer(self) -> None:
        """Launch a daemon thread that runs cleanup every hour."""
        def _loop():
            while True:
                time.sleep(self._cleanup_interval)
                try:
                    self.cleanup_expired()
                except Exception as exc:
                    logger.error("ThreatIntel cleanup error: %s", exc)

        t = threading.Thread(target=_loop, daemon=True, name="ThreatIntelCleanup")
        t.start()
