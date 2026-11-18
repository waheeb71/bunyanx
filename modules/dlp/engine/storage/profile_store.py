import os
import time
import json
import logging
import threading
from pathlib import Path
from typing import Dict, Deque, List, Optional
from collections import defaultdict, deque
from dataclasses import dataclass, field

from modules.dlp.engine.msem_lite import IPT_WINDOW_SIZE

logger = logging.getLogger(__name__)

# Constants for Snapshot logic
_ENV = os.getenv("NGFW_ENV", "production").lower()
_DATA_DIR_ENV = os.getenv("NGFW_DATA_DIR", "")
if _DATA_DIR_ENV:
    _PROFILE_SNAPSHOT_PATH = Path(_DATA_DIR_ENV) / "befp_profiles_snapshot.json"
elif _ENV != "production":
    _PROFILE_SNAPSHOT_PATH = Path(__file__).parent.parent.parent / "data" / "befp_profiles_snapshot.json"
else:
    _PROFILE_SNAPSHOT_PATH = None

_PROFILE_SNAPSHOT_INTERVAL_SEC = int(os.getenv("DLP_PROFILE_SNAPSHOT_INTERVAL", "300"))
CHUNK_WINDOW_SIZE = 20

@dataclass
class FlowProfile:
    """Per-source-IP behavioral profile maintained in memory."""
    src_ip: str
    events: deque = field(default_factory=lambda: deque(maxlen=500))
    velocity_log: deque = field(default_factory=lambda: deque(maxlen=10000))
    recent_sizes: deque = field(default_factory=lambda: deque(maxlen=CHUNK_WINDOW_SIZE))
    accumulation: Dict[str, float] = field(default_factory=dict)
    accumulation_log: Dict[str, deque] = field(default_factory=lambda: defaultdict(lambda: deque(maxlen=30)))
    baseline_velocity_bps: float = 0.0
    baseline_samples: int = 0
    ipt_window: Deque[float] = field(default_factory=lambda: deque(maxlen=IPT_WINDOW_SIZE))
    last_packet_time: float = 0.0
    last_seen: float = field(default_factory=time.time)


class ProfileStore:
    """
    Manages in-memory storage, retrieval, and persistence of FlowProfiles.
    Thread-safe and implements LRU-like eviction.
    """
    MAX_PROFILES = 10_000
    PROFILE_TTL_SEC = 3600

    def __init__(self):
        self._profiles: Dict[str, FlowProfile] = {}
        self._lock = threading.RLock()

    def get_or_create(self, src_ip: str) -> FlowProfile:
        with self._lock:
            if src_ip not in self._profiles:
                if len(self._profiles) >= self.MAX_PROFILES:
                    self._evict_stale()
                self._profiles[src_ip] = FlowProfile(src_ip=src_ip)
            profile = self._profiles[src_ip]
            profile.last_seen = time.time()
            return profile

    def get(self, src_ip: str) -> Optional[FlowProfile]:
        with self._lock:
            return self._profiles.get(src_ip)

    def iter_profiles(self):
        with self._lock:
            return list(self._profiles.items())

    def _evict_stale(self):
        now = time.time()
        stale = [ip for ip, p in self._profiles.items() if now - p.last_seen > self.PROFILE_TTL_SEC]
        for ip in stale:
            del self._profiles[ip]
        if not stale:
            sorted_ips = sorted(self._profiles, key=lambda ip: self._profiles[ip].last_seen)
            for ip in sorted_ips[:max(1, len(self._profiles) // 10)]:
                del self._profiles[ip]
        logger.debug(f"BEFP cache eviction: removed {len(stale)} stale profiles.")

    def save_snapshot(self) -> None:
        if _PROFILE_SNAPSHOT_PATH is None:
            logger.warning("[DLP][BEFP] Cannot save snapshot: NGFW_DATA_DIR not configured.")
            return

        snapshot = {}
        cutoff = time.time() - self.PROFILE_TTL_SEC
        with self._lock:
            for ip, p in self._profiles.items():
                if p.last_seen < cutoff:
                    continue
                snapshot[ip] = {
                    "baseline_velocity_bps": p.baseline_velocity_bps,
                    "baseline_samples": p.baseline_samples,
                    "accumulation": p.accumulation,
                    "last_seen": p.last_seen,
                }

        try:
            _PROFILE_SNAPSHOT_PATH.parent.mkdir(parents=True, exist_ok=True)
            tmp = _PROFILE_SNAPSHOT_PATH.with_suffix(".json.tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(snapshot, f)
            os.replace(tmp, _PROFILE_SNAPSHOT_PATH)
            logger.info("[DLP][BEFP] Profile snapshot saved: %d active IPs → %s", len(snapshot), _PROFILE_SNAPSHOT_PATH)
        except Exception as e:
            logger.error("[DLP][BEFP] Failed to save profile snapshot: %s", e)

    def restore_snapshot(self) -> None:
        if _PROFILE_SNAPSHOT_PATH is None or not _PROFILE_SNAPSHOT_PATH.exists():
            logger.info("[DLP][BEFP] No profile snapshot found — starting fresh.")
            return

        try:
            with open(_PROFILE_SNAPSHOT_PATH, "r", encoding="utf-8") as f:
                snapshot = json.load(f)
        except Exception as e:
            logger.warning("[DLP][BEFP] Could not read profile snapshot: %s", e)
            return

        now = time.time()
        restored = 0
        cutoff = now - self.PROFILE_TTL_SEC

        with self._lock:
            for ip, data in snapshot.items():
                if data.get("last_seen", 0) < cutoff:
                    continue
                p = FlowProfile(src_ip=ip)
                p.baseline_velocity_bps = float(data.get("baseline_velocity_bps", 0.0))
                p.baseline_samples      = int(data.get("baseline_samples", 0))
                p.accumulation          = dict(data.get("accumulation", {}))
                p.last_seen             = float(data.get("last_seen", now))
                self._profiles[ip] = p
                restored += 1

        logger.info("[DLP][BEFP] Snapshot restored: %d active IP profiles loaded.", restored)

    def start_periodic_snapshot(self) -> None:
        def _loop():
            while True:
                time.sleep(_PROFILE_SNAPSHOT_INTERVAL_SEC)
                try:
                    self.save_snapshot()
                except Exception as e:
                    logger.error("[DLP][BEFP] Periodic snapshot failed: %s", e)

        t = threading.Thread(target=_loop, daemon=True, name="BEFP-Snapshot")
        t.start()
        logger.info("[DLP][BEFP] Periodic snapshot thread started (interval=%ds, path=%s).", _PROFILE_SNAPSHOT_INTERVAL_SEC, _PROFILE_SNAPSHOT_PATH)
