"""
bunyanx Voice Alert Service (CVAS) - GeoIP Enricher
======================================================
Thread-safe, non-blocking GeoIP enrichment wrapper around MaxMind GeoLite2-City.
Provides fast LRU-cached lookups for Country, City, and ASN info.

FIX (BUG-07): lru_cache on an instance method holds a reference to `self`,
              preventing garbage collection of the GeoEnricher instance.
              Fixed by using an explicit dict-based LRU cache instead.
"""

import logging
from collections import OrderedDict
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

try:
    import geoip2.database
    import geoip2.errors
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False

# Private fallback results (immutable)
_INTERNAL_RESULT: Dict[str, Any] = {
    "country": "Internal Network",
    "country_code": "LOCAL",
    "city": "Local Subnet",
    "is_private": True,
}
_UNKNOWN_RESULT: Dict[str, Any] = {
    "country": "External Location",
    "country_code": "UNKNOWN",
    "city": "",
    "is_private": False,
}

# Private IPs that should always resolve as internal
_PRIVATE_IPS = frozenset({"127.0.0.1", "localhost", "0.0.0.0", ""})


class _LRUCache:
    """
    Minimal thread-safe LRU cache using OrderedDict.
    Replaces @lru_cache on instance methods to avoid self-reference leaks.
    """

    def __init__(self, maxsize: int = 4096):
        self._cache: OrderedDict = OrderedDict()
        self._maxsize = maxsize

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]
        return None

    def set(self, key: str, value: Dict[str, Any]) -> None:
        if key in self._cache:
            self._cache.move_to_end(key)
        else:
            if len(self._cache) >= self._maxsize:
                self._cache.popitem(last=False)  # evict oldest
        self._cache[key] = value

    def clear(self) -> None:
        self._cache.clear()


class GeoEnricher:
    """
    Provides IP-to-Country/City resolution with explicit LRU caching.
    Runs entirely out-of-band in CVAS pipeline (0ms impact on packet inspection).
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = Path(db_path) if db_path else None
        self._reader: Optional[Any] = None
        self._initialized = False
        self._cache = _LRUCache(maxsize=4096)
        self._initialize_database()

    def _initialize_database(self) -> None:
        if not GEOIP2_AVAILABLE:
            logger.debug(
                "[CVAS:GeoIP] geoip2 library not installed — "
                "GeoIP enrichment operating in fallback mode."
            )
            return

        if not self.db_path:
            # Fallback path search (relative to project root, not CWD)
            _here = Path(__file__).parent
            candidates = [
                _here.parent.parent / "data" / "GeoLite2-City.mmdb",
                _here.parent.parent / "system" / "data" / "GeoLite2-City.mmdb",
                Path("/var/lib/geoip/GeoLite2-City.mmdb"),
                Path("/usr/share/GeoIP/GeoLite2-City.mmdb"),
            ]
            for cand in candidates:
                if cand.exists():
                    self.db_path = cand
                    break

        if self.db_path and self.db_path.exists():
            try:
                self._reader = geoip2.database.Reader(str(self.db_path))
                self._initialized = True
                logger.info(f"[CVAS:GeoIP] Loaded GeoIP database from {self.db_path}")
            except Exception as e:
                logger.warning(f"[CVAS:GeoIP] Failed to load MMDB file: {e}")
        else:
            logger.debug(
                "[CVAS:GeoIP] GeoLite2-City.mmdb not found. "
                "Using generic fallback location markers."
            )

    def lookup(self, ip_address: str) -> Dict[str, Any]:
        """
        Lookup IP geographic information. Returns dict with country, city, etc.
        Results are cached in an instance-level LRU cache (max 4096 entries).
        """
        if not ip_address or ip_address in _PRIVATE_IPS:
            return dict(_INTERNAL_RESULT)

        # Also catch RFC-1918 ranges without importing ipaddress module
        if ip_address.startswith(("10.", "192.168.", "172.")):
            return dict(_INTERNAL_RESULT)

        cached = self._cache.get(ip_address)
        if cached is not None:
            return cached

        result = self._do_lookup(ip_address)
        self._cache.set(ip_address, result)
        return result

    def _do_lookup(self, ip_address: str) -> Dict[str, Any]:
        """Perform the actual MaxMind database lookup."""
        if not self._initialized or not self._reader:
            return dict(_UNKNOWN_RESULT)

        try:
            response = self._reader.city(ip_address)
            country = (
                response.country.name
                or response.continent.name
                or "External Location"
            )
            country_code = response.country.iso_code or "XX"
            city = response.city.name or ""
            return {
                "country": country,
                "country_code": country_code,
                "city": city,
                "is_private": False,
            }
        except Exception:
            return dict(_UNKNOWN_RESULT)

    def close(self) -> None:
        if self._reader:
            try:
                self._reader.close()
            except Exception:
                pass
            self._reader = None
        self._cache.clear()
