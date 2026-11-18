import time
import asyncio
import threading
import logging
import yaml
from pathlib import Path
from typing import Dict, Optional

class TokenBucket:
    """
    Improved Token Bucket implementation supporting both Sync and Async consumption.
    Thread-safe for high-performance inspection pipeline usage.
    """
    
    def __init__(self, capacity_bytes: float, fill_rate_bytes_sec: float):
        self.capacity = float(capacity_bytes)
        self.fill_rate = float(fill_rate_bytes_sec)
        self.tokens = float(capacity_bytes)
        self.last_update = time.time()
        self.last_access = time.time()
        self._lock = threading.Lock()     # Use threading.Lock for sync performance
        self._async_lock = asyncio.Lock() # Use asyncio.Lock for async throttle logic
        
    def _replenish(self):
        """Internal logic to add tokens based on elapsed time."""
        now = time.time()
        elapsed = now - self.last_update
        self.tokens = min(self.capacity, self.tokens + elapsed * self.fill_rate)
        self.last_update = now

    def consume_sync(self, amount: int) -> bool:
        """High-performance synchronous consumption for the Inspection Pipeline."""
        with self._lock:
            self._replenish()
            if self.tokens >= amount:
                self.tokens -= amount
                return True
            return False

    async def consume_async(self, amount: int) -> bool:
        """Asynchronous consumption for proxy handlers or specific tasks."""
        async with self._async_lock:
            # We also sync with the threading lock to avoid split-brain with sync consumers
            with self._lock:
                self._replenish()
                if self.tokens >= amount:
                    self.tokens -= amount
                    return True
                return False

class QoSManager:
    """
    Unified Quality of Service (QoS) Manager.
    Single source of truth for bandwidth shaping across the bunyanx engine.
    """
    
    _instance = None
    _instance_lock = threading.Lock()
    
    @classmethod
    def get_instance(cls, config: Optional[dict] = None, logger: Optional[logging.Logger] = None, db_manager=None) -> 'QoSManager':
        """Singleton pattern: guarantees API and Pipeline share the exact same state."""
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls(config, logger, db_manager)
            return cls._instance

    def __init__(self, config: Optional[dict] = None, logger: Optional[logging.Logger] = None, db_manager=None):
        if QoSManager._instance is not None:
            raise RuntimeError("QoSManager is a Singleton. Use QoSManager.get_instance()")
            
        self.config = config or {}
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        self.db_manager = db_manager
        self._last_config_load_time = None
        
        # IP -> TokenBucket mapping for per-IP limits
        self.ip_buckets: Dict[str, TokenBucket] = {}
        self._buckets_lock = threading.Lock()
        
        # Set basic defaults first
        self.enabled = False
        self.mode = "monitor"
        self.default_per_ip_rate = 1250000
        self.default_per_ip_burst = 2500000
        self._gc_interval = 60
        self._gc_idle_timeout = 300
        self.max_buckets = 50000

        # Load from config hierarchy (Dict -> DB -> YAML -> Defaults)
        self._initialize_config(db_manager)
        
        # Start background Memory Guard (Garbage Collector)
        self._shutdown_flag = threading.Event()
        self._gc_thread = threading.Thread(target=self._prune_inactive_buckets, name="QoSMgr-GC", daemon=True)
        self._gc_thread.start()
        
    def stop(self):
        """Clean shutdown of background threads."""
        self._shutdown_flag.set()
        if self._gc_thread.is_alive():
            self._gc_thread.join(timeout=2)
        
    def _initialize_config(self, db_manager):
        if self.config:
            self.enabled = self.config.get("enabled", self.enabled)
            self.mode = self.config.get("mode", self.mode)
            self.default_per_ip_rate = self.config.get("default_user_rate_bytes", self.default_per_ip_rate)
            self.default_per_ip_burst = self.config.get("default_user_burst_bytes", self.default_per_ip_burst)
            self._gc_interval = self.config.get("gc_interval_sec", self._gc_interval)
            self._gc_idle_timeout = self.config.get("gc_idle_timeout_sec", self._gc_idle_timeout)
            self.max_buckets = self.config.get("max_buckets", self.max_buckets)
            return

        # Attempt to load defaults from settings.yaml
        yaml_loaded = False
        try:
            yaml_path = Path(__file__).parent / 'config' / 'settings.yaml'
            if yaml_path.exists():
                with open(yaml_path, 'r', encoding='utf-8') as f:
                    full_yaml = yaml.safe_load(f) or {}
                    yaml_config = full_yaml.get('qos', {})
                    if yaml_config:
                        self.enabled = yaml_config.get("enabled", self.enabled)
                        self.mode = yaml_config.get("mode", self.mode)
                        self.default_per_ip_rate = yaml_config.get("default_user_rate_bytes", self.default_per_ip_rate)
                        self.default_per_ip_burst = yaml_config.get("default_user_burst_bytes", self.default_per_ip_burst)
                        self._gc_interval = yaml_config.get("gc_interval_sec", self._gc_interval)
                        self._gc_idle_timeout = yaml_config.get("gc_idle_timeout_sec", self._gc_idle_timeout)
                        self.max_buckets = yaml_config.get("max_buckets", self.max_buckets)
                        yaml_loaded = True
                        self.logger.info("QoS settings loaded from default settings.yaml")
        except Exception as e:
            self.logger.warning("Failed to load QoS settings.yaml: %s", e)

        # Attempt to override customizable limits from DB
        if db_manager is not None:
            try:
                from system.database.database import QoSConfig as DBConfig
                with db_manager.sync_session() as db:
                    db_config = db.query(DBConfig).first()
                    if db_config:
                        self.enabled = db_config.enabled
                        self.mode = getattr(db_config, 'mode', self.mode) or self.mode
                        self.default_per_ip_rate = db_config.default_user_rate_bytes
                        self.default_per_ip_burst = db_config.default_user_burst_bytes
                        self._last_config_load_time = db_config.updated_at
                        self.logger.info("QoS configuration loaded and updated from DB.")
                    else:
                        if not yaml_loaded:
                            self.logger.info("QoS DB config not found, using static defaults.")
            except Exception as e:
                self.logger.error("Failed to load QoS DB config: %s", e)
        
    def get_bucket_for_ip(self, ip_address: str) -> TokenBucket:
        """Get or create a thread-safe token bucket for a specific IP."""
        with self._buckets_lock:
            if ip_address not in self.ip_buckets:
                if len(self.ip_buckets) >= self.max_buckets:
                    # Batch evict 1% of max_buckets (or at least 1) to make room
                    evict_count = max(1, int(self.max_buckets * 0.01))
                    sorted_ips = sorted(self.ip_buckets.keys(), key=lambda ip: self.ip_buckets[ip].last_access)
                    for old_ip in sorted_ips[:evict_count]:
                        del self.ip_buckets[old_ip]
                    self.logger.warning(
                        "QoS: max_buckets limit (%d) reached. Evicted %d oldest IP buckets.",
                        self.max_buckets, evict_count
                    )
                self.ip_buckets[ip_address] = TokenBucket(self.default_per_ip_burst, self.default_per_ip_rate)
            # Update activity timestamp safely
            self.ip_buckets[ip_address].last_access = time.time()
            return self.ip_buckets[ip_address]

    def _sync_config_from_db(self):
        """Query the database to check for updated QoS limits (resolves multi-process desync)."""
        if self.db_manager is None:
            return
            
        try:
            from system.database.database import QoSConfig as DBConfig
            with self.db_manager.sync_session() as db:
                db_config = db.query(DBConfig).first()
                if db_config and db_config.updated_at:
                    if (self._last_config_load_time is None or 
                            db_config.updated_at > self._last_config_load_time):
                        
                        db_mode = getattr(db_config, 'mode', 'monitor') or 'monitor'
                        db_max_buckets = getattr(db_config, 'max_buckets', self.max_buckets) or self.max_buckets
                        # Apply limits dynamic update if fields changed
                        if (self.enabled != db_config.enabled or
                                self.mode != db_mode or
                                self.default_per_ip_rate != db_config.default_user_rate_bytes or
                                self.default_per_ip_burst != db_config.default_user_burst_bytes or
                                self.max_buckets != db_max_buckets):
                            
                            self.update_limits(
                                enabled=db_config.enabled,
                                mode=db_mode,
                                rate_bytes=db_config.default_user_rate_bytes,
                                burst_bytes=db_config.default_user_burst_bytes,
                                max_buckets=db_max_buckets,
                            )
                        
                        self._last_config_load_time = db_config.updated_at
        except Exception as e:
            self.logger.error("Failed to sync QoS config from DB: %s", e)

    def _prune_inactive_buckets(self):
        """
        Background Garbage Collector: Defends against Memory Leaks & DDoS.
        Removes buckets idle beyond gc_idle_timeout_sec. Also syncs configuration.
        Optimized lock-free scanning and exception-safe loop wrapper.
        """
        last_gc_run = 0.0
        while not self._shutdown_flag.wait(timeout=5):
            try:
                # 1. Sync config from DB
                self._sync_config_from_db()
                
                # 2. Run GC if interval elapsed
                now = time.time()
                if now - last_gc_run >= self._gc_interval:
                    last_gc_run = now
                    
                    # Shallow copy dictionary items under brief lock to minimize hold time
                    with self._buckets_lock:
                        if not self.ip_buckets:
                            continue
                        buckets_snapshot = list(self.ip_buckets.items())
                    
                    # Scan for stale buckets without holding any lock
                    stale_ips = []
                    for ip, bucket in buckets_snapshot:
                        if now - bucket.last_access > self._gc_idle_timeout:
                            stale_ips.append(ip)
                            
                    if stale_ips:
                        # Re-acquire lock briefly to perform actual deletion
                        pruned_count = 0
                        with self._buckets_lock:
                            for ip in stale_ips:
                                if ip in self.ip_buckets:
                                    # Double-check last_access in case it was refreshed during scanning
                                    if now - self.ip_buckets[ip].last_access > self._gc_idle_timeout:
                                        del self.ip_buckets[ip]
                                        pruned_count += 1
                        
                        if pruned_count > 0:
                            self.logger.debug(
                                "QoS GC: Pruned %d inactive IP buckets. Active: %d",
                                pruned_count, len(self.ip_buckets),
                            )
            except Exception as e:
                self.logger.error("Unhandled exception in QoS GC background thread: %s", e, exc_info=True)

    def _prune_inactive_buckets_once(self):
        """Single-pass GC for testing — prunes stale buckets once."""
        now = time.time()
        # Shallow copy under brief lock
        with self._buckets_lock:
            buckets_snapshot = list(self.ip_buckets.items())
            
        stale_ips = []
        for ip, bucket in buckets_snapshot:
            if now - bucket.last_access > self._gc_idle_timeout:
                stale_ips.append(ip)
                
        if stale_ips:
            with self._buckets_lock:
                for ip in stale_ips:
                    if ip in self.ip_buckets:
                        if now - self.ip_buckets[ip].last_access > self._gc_idle_timeout:
                            del self.ip_buckets[ip]

    def reset_bucket(self, ip_address: str) -> bool:
        """Manually refill tokens for a specific IP bucket. Returns True if bucket existed."""
        with self._buckets_lock:
            if ip_address in self.ip_buckets:
                bucket = self.ip_buckets[ip_address]
                with bucket._lock:
                    bucket.tokens = bucket.capacity
                    bucket.last_update = time.time()
                return True
            return False
        
    def update_limits(self, enabled: bool, mode: str, rate_bytes: int, burst_bytes: int, max_buckets: Optional[int] = None):
        """Dynamically update global QoS limits and notify all buckets."""
        self.enabled = enabled
        self.mode = mode
        self.default_per_ip_rate = rate_bytes
        self.default_per_ip_burst = burst_bytes
        if max_buckets is not None:
            self.max_buckets = max_buckets
        
        with self._buckets_lock:
            for bucket in self.ip_buckets.values():
                with bucket._lock:
                    bucket.fill_rate = float(rate_bytes)
                    bucket.capacity = float(burst_bytes)
                    if bucket.tokens > bucket.capacity:
                        bucket.tokens = bucket.capacity
                
        self.logger.info(
            "QoS global limits updated: enabled=%s, mode=%s, rate=%d B/s, burst=%d B, max_buckets=%d",
            enabled, mode, rate_bytes, burst_bytes, self.max_buckets,
        )
        
    def check_traffic(self, ip_address: str, data_size_bytes: int) -> bool:
        """
        Synchronous, non-blocking check for the Inspection Pipeline.
        Returns True if allowed, False if traffic exceeds bandwidth limits.
        """
        if not self.enabled or data_size_bytes <= 0:
            return True
            
        bucket = self.get_bucket_for_ip(ip_address)
        return bucket.consume_sync(data_size_bytes)

    async def throttle(self, ip_address: str, data_size: int) -> None:
        """
        Asynchronous traffic shaping (Delay-to-Refill).
        Sleeps until tokens are available for the given IP address.
        """
        if not self.enabled or data_size <= 0:
            return
            
        bucket = self.get_bucket_for_ip(ip_address)
        
        while True:
            if await bucket.consume_async(data_size):
                return
                
            # Read tokens under lock to avoid race condition
            with bucket._lock:
                needed = data_size - bucket.tokens
                fill_rate = bucket.fill_rate
            wait_time = max(0.001, needed / fill_rate)
            await asyncio.sleep(wait_time)
