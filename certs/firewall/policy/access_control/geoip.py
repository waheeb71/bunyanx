"""
Enterprise bunyanx v2.0 - GeoIP Filter
High-Performance Memory-Preloaded Country-based traffic filtering.
"""

import logging
import threading
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from pathlib import Path
from collections import OrderedDict

try:
    import maxminddb
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False


@dataclass
class CountryInfo:
    ip: str
    country_code: str
    country_name: str
    continent_code: str
    continent_name: str
    asn: Optional[int] = None
    is_anonymous_proxy: bool = False
    is_satellite_provider: bool = False

class LRUCache:
    """Bounded O(1) LRU Cache with 16-bucket lock-striping to eliminate thread contention"""
    def __init__(self, capacity: int = 100000, num_shards: int = 16):
        self.num_shards = num_shards
        self.capacity_per_shard = max(1, capacity // num_shards)
        self.shards = [OrderedDict() for _ in range(num_shards)]
        self.locks = [threading.Lock() for _ in range(num_shards)]
        
    def _get_shard(self, key: str):
        idx = hash(key) % self.num_shards
        return self.shards[idx], self.locks[idx]
        
    def get(self, key):
        shard, lock = self._get_shard(key)
        with lock:
            if key not in shard:
                return None
            shard.move_to_end(key)
            return shard[key]
            
    def put(self, key, value):
        shard, lock = self._get_shard(key)
        with lock:
            shard[key] = value
            shard.move_to_end(key)
            if len(shard) > self.capacity_per_shard:
                shard.popitem(last=False)
                
    def clear(self):
        for i in range(self.num_shards):
            with self.locks[i]:
                self.shards[i].clear()

class GeoIPFilter:
    """
    GeoIP-based traffic filtering utilizing an in-memory MaxMind MMDB reader
    and Hot-IP LRU caching for blazing fast line-rate lookups.
    """
    def __init__(
        self,
        db_path: Optional[str] = None,
        asn_db_path: Optional[str] = None,
        logger: Optional[logging.Logger] = None
    ):
        self.db_path = Path(db_path) if db_path else None
        self.asn_db_path = Path(asn_db_path) if asn_db_path else None
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        
        self.reader = None
        self.asn_reader = None
        
        self._country_whitelist: Set[str] = set()
        self._country_blacklist: Set[str] = set()
        self._continent_blacklist: Set[str] = set()
        self._asn_blacklist: Set[int] = set()
        
        self._block_anonymous_proxies = False
        self._block_satellite_providers = False
        
        self._verdict_cache = LRUCache(capacity=100000) 
        self._lock = threading.RLock()
        
        if GEOIP_AVAILABLE:
            self._load_databases()
            
    def _load_databases(self) -> bool:
        """Load MMDB purely into memory (MODE_MEMORY)"""
        try:
            if getattr(maxminddb, 'MODE_MEMORY', None):
                mode = maxminddb.MODE_MEMORY
            else:
                mode = maxminddb.MODE_AUTO
                
            if self.db_path and self.db_path.exists():
                self.reader = geoip2.database.Reader(str(self.db_path), mode=mode)
                self.logger.info(f"Loaded MMDB GeoIP database into fast memory: {self.db_path}")
            
            if self.asn_db_path and self.asn_db_path.exists():
                self.asn_reader = geoip2.database.Reader(str(self.asn_db_path), mode=mode)
                self.logger.info(f"Loaded MMDB ASN database into fast memory: {self.asn_db_path}")
                
            return self.reader is not None
        except Exception as e:
            self.logger.error(f"Failed to load memory GeoIP databases: {e}")
            return False
            
    def lookup(self, ip: str) -> Optional[CountryInfo]:
        """Deep lookup from Memory MMDB"""
        if not GEOIP_AVAILABLE or not self.reader:
            return None
            
        try:
            response = self.reader.city(ip)
            asn = None
            if self.asn_reader:
                try:
                    asn_response = self.asn_reader.asn(ip)
                    asn = asn_response.autonomous_system_number
                except Exception:
                    pass
                    
            return CountryInfo(
                ip=ip,
                country_code=response.country.iso_code or 'XX',
                country_name=response.country.name or 'Unknown',
                continent_code=response.continent.code or 'XX',
                continent_name=response.continent.name or 'Unknown',
                asn=asn,
                is_anonymous_proxy=getattr(response.traits, 'is_anonymous_proxy', getattr(response.traits, 'is_anonymous', False)),
                is_satellite_provider=getattr(response.traits, 'is_satellite_provider', False)
            )
        except Exception:
            return None
            
    def is_blocked(self, ip: str) -> Tuple[bool, Optional[str]]:
        """Fast-Path Verdict Check using LRU Cache"""
        # 1. Hot IP Cache Check
        cached_verdict = self._verdict_cache.get(ip)
        if cached_verdict is not None:
            return cached_verdict
            
        # 2. Slow Path Database Deep Match
        info = self.lookup(ip)
        if not info:
            self._verdict_cache.put(ip, (False, None))
            return False, None
            
        with self._lock:
            if self._block_anonymous_proxies and info.is_anonymous_proxy:
                verdict = (True, "Anonymous proxy blocked")
            elif self._block_satellite_providers and info.is_satellite_provider:
                verdict = (True, "Satellite provider blocked")
            elif info.asn and info.asn in self._asn_blacklist:
                verdict = (True, f"ASN {info.asn} blocked")
            elif self._country_whitelist and info.country_code not in self._country_whitelist:
                verdict = (True, f"Country {info.country_code} not whitelisted")
            elif info.country_code in self._country_blacklist:
                verdict = (True, f"Country {info.country_code} blacklisted")
            elif info.continent_code in self._continent_blacklist:
                verdict = (True, f"Continent {info.continent_code} blacklisted")
            else:
                verdict = (False, None)
                
        # 3. Store verdict directly for fast L1 bypassing
        self._verdict_cache.put(ip, verdict)
        return verdict

    def _invalidate_cache(self):
        self._verdict_cache.clear()

    def blacklist_country(self, code: str):
        with self._lock:
            self._country_blacklist.add(code.upper())
        self._invalidate_cache()
    
    def whitelist_country(self, code: str):
        with self._lock:
            self._country_whitelist.add(code.upper())
        self._invalidate_cache()
