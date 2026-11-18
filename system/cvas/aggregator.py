"""
bunyanx Voice Alert Service (CVAS) - Burst Event Aggregator
==============================================================
Provides sliding-window event aggregation and duplicate suppression for CVAS.
Prevents speech flooding during high-volume attacks or DDoS events by merging
burst alerts into single SOC announcements.

FIX (BUG-06): flush_expired_buckets() is NO LONGER called inside process_event().
              Flushing is exclusively the responsibility of the periodic flush
              loop in CVASService._periodic_flush_loop() (every 5 seconds).
              Calling flush on every incoming event caused O(n) scan per event.
"""

import time
import logging
from typing import Dict, List, Optional, Tuple, Any

logger = logging.getLogger(__name__)

# Maximum entries kept in the recent-phrases and recent-IPs dicts.
# Prevents unbounded growth in high-throughput scenarios.
_MAX_RECENT_ENTRIES = 2048


class AggregationItem:
    __slots__ = ("key", "initial_payload", "count", "first_seen", "last_seen")

    def __init__(self, key: Tuple[str, str, str], initial_payload: Dict[str, Any]):
        self.key = key              # (src_ip, threat_type, module)
        self.initial_payload = initial_payload
        self.count = 1
        self.first_seen = time.time()
        self.last_seen = time.time()

    def add_occurrence(self) -> None:
        self.count += 1
        self.last_seen = time.time()


class EventAggregator:
    """
    Sliding-window event aggregator & duplicate suppressor.
    """

    def __init__(
        self,
        window_seconds: float = 30.0,
        min_burst_count: int = 3,
        deduplication_window_s: float = 45.0,
        ip_cooldown_s: float = 60.0,
    ):
        self.window_seconds = window_seconds
        self.min_burst_count = min_burst_count
        self.deduplication_window_s = deduplication_window_s
        self.ip_cooldown_s = ip_cooldown_s

        # Active aggregation buckets: key -> AggregationItem
        self._buckets: Dict[Tuple[str, str, str], AggregationItem] = {}
        # Recent spoken phrase timestamps for duplicate suppression
        self._recent_phrases: Dict[str, float] = {}
        # Recent spoken source IPs for IP-level voice cooldown
        self._recent_ips: Dict[str, float] = {}

    def process_event(self, topic: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Process an incoming event.

        FIX (BUG-06): flush_expired_buckets() removed from here.
        Flushing only happens in the periodic 5-second loop.

        Returns:
            - Dict payload if event should be spoken immediately.
            - None if buffered into a burst bucket (will be announced later).
        """
        src_ip = payload.get("src_ip", "")
        threat_type = payload.get("threat_type", payload.get("reason", "threat"))
        module = payload.get("module", payload.get("source_module", "core"))

        if not src_ip:
            # Non-IP events (system alerts, PKI, etc.) pass through directly
            return payload

        key = (src_ip, str(threat_type), str(module))

        if key in self._buckets:
            self._buckets[key].add_occurrence()
            logger.debug(f"[CVAS:Aggregator] Buffered event {key} (count={self._buckets[key].count})")
            return None  # Buffered for burst summary
        else:
            self._buckets[key] = AggregationItem(key, payload)
            return payload  # First occurrence passes through immediately

    def flush_expired_buckets(self, current_time: Optional[float] = None) -> List[Dict[str, Any]]:
        """
        Flushes buckets whose aggregation window has expired.
        Called by CVASService._periodic_flush_loop() every 5 seconds.
        Returns a list of burst summary payloads ready for speech generation.
        """
        now = current_time or time.time()
        expired_keys: List[Tuple[str, str, str]] = []
        burst_summaries: List[Dict[str, Any]] = []

        for key, item in list(self._buckets.items()):
            if now - item.first_seen >= self.window_seconds:
                expired_keys.append(key)
                if item.count >= self.min_burst_count:
                    burst_payload = dict(item.initial_payload)
                    burst_payload["is_burst"] = True
                    burst_payload["burst_count"] = item.count
                    burst_payload["window_s"] = int(self.window_seconds)
                    burst_summaries.append(burst_payload)
                    logger.info(
                        f"[CVAS:Aggregator] Burst: {key} → "
                        f"{item.count} events in {int(self.window_seconds)}s"
                    )

        for key in expired_keys:
            del self._buckets[key]

        return burst_summaries

    def is_duplicate_phrase(self, phrase_text: str) -> bool:
        """
        Returns True if this exact phrase was spoken within deduplication_window_s.
        Also registers the phrase timestamp so subsequent calls are suppressed.
        Enforces _MAX_RECENT_ENTRIES cap to prevent unbounded dict growth.
        """
        now = time.time()

        # Evict stale entries
        cutoff = now - self.deduplication_window_s
        self._recent_phrases = {
            p: ts for p, ts in self._recent_phrases.items() if ts >= cutoff
        }

        # Cap size to prevent growth under adversarial input
        if len(self._recent_phrases) >= _MAX_RECENT_ENTRIES:
            oldest_key = min(self._recent_phrases, key=self._recent_phrases.get)
            del self._recent_phrases[oldest_key]

        if phrase_text in self._recent_phrases:
            return True

        self._recent_phrases[phrase_text] = now
        return False

    def is_ip_in_cooldown(self, src_ip: str) -> bool:
        """
        Returns True if this source IP is currently in voice cooldown.
        Prevents voice spam when a single IP generates many different alert types.
        """
        if not src_ip or src_ip in ("127.0.0.1", "::1", "localhost"):
            return False

        now = time.time()
        cutoff = now - self.ip_cooldown_s
        self._recent_ips = {
            ip: ts for ip, ts in self._recent_ips.items() if ts >= cutoff
        }

        # Cap size
        if len(self._recent_ips) >= _MAX_RECENT_ENTRIES:
            oldest_key = min(self._recent_ips, key=self._recent_ips.get)
            del self._recent_ips[oldest_key]

        if src_ip in self._recent_ips:
            return True

        self._recent_ips[src_ip] = now
        return False
