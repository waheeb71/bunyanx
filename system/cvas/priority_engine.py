"""
bunyanx Voice Alert Service (CVAS) - Priority Queue & Rate Engine
=====================================================================
Thread-safe min-heap Priority Queue and rate limiter for spoken alerts.
Ensures critical alerts interrupt or precede lower priority speech.
"""

import time
import queue
import logging
from dataclasses import dataclass, field
from typing import Optional, Any, Dict, List

logger = logging.getLogger(__name__)


@dataclass(order=True)
class VoicePriorityItem:
    priority: int                   # Lower numeric value = Higher priority (10=CRITICAL, 20=HIGH, 30=MEDIUM, 40=LOW)
    timestamp: float = field(compare=False)
    spoken_text: str = field(compare=False)
    topic: str = field(compare=False)
    level_key: str = field(compare=False)
    payload: Dict[str, Any] = field(compare=False)


class PriorityEngine:
    """
    Min-heap priority queue & rate-limiting controller for CVAS.
    """

    PRIORITY_MAP = {
        "level1_critical": 10,
        "level2_high": 20,
        "level3_medium": 30,
        "level4_low_info": 40,
    }

    def __init__(self, max_queue_size: int = 100, rate_limit_per_min: int = 10):
        self.max_queue_size = max_queue_size
        self.rate_limit_per_min = rate_limit_per_min
        self._queue: queue.PriorityQueue = queue.PriorityQueue(maxsize=max_queue_size)
        self._spoken_timestamps: List[float] = []

        # Statistics
        self.stats = {
            "enqueued": 0,
            "spoken": 0,
            "dropped_full": 0,
            "dropped_rate_limit": 0,
            "cleared": 0,
        }

    def get_priority_value(self, verbosity_level: str) -> int:
        return self.PRIORITY_MAP.get(verbosity_level, 30)

    def is_rate_limited(self) -> bool:
        """Checks if maximum spoken alerts per minute limit has been reached.
        FIX (ARCH-04): timestamps list is now capped so it cannot grow unbounded
        in long-running deployments.
        """
        now = time.time()
        # Evict entries older than 60 s
        self._spoken_timestamps = [
            ts for ts in self._spoken_timestamps if now - ts < 60.0
        ]
        # Safety cap: never store more than rate_limit_per_min * 2 entries
        if len(self._spoken_timestamps) > self.rate_limit_per_min * 2 + 10:
            self._spoken_timestamps = self._spoken_timestamps[-(self.rate_limit_per_min * 2):]
        return len(self._spoken_timestamps) >= self.rate_limit_per_min

    def enqueue_alert(
        self,
        topic: str,
        spoken_text: str,
        verbosity_level: str,
        payload: Dict[str, Any]
    ) -> bool:
        """
        Enqueues a spoken alert item into the priority queue.
        Returns True if successfully enqueued, False if dropped due to queue size or rate limiting.
        """
        if not spoken_text:
            return False

        priority_val = self.get_priority_value(verbosity_level)

        # Allow Level 1 CRITICAL alerts to bypass rate-limiting
        if priority_val > 10 and self.is_rate_limited():
            self.stats["dropped_rate_limit"] += 1
            logger.debug(f"[CVAS:PriorityEngine] Rate limit reached ({self.rate_limit_per_min}/min). Alert dropped: {topic}")
            return False

        item = VoicePriorityItem(
            priority=priority_val,
            timestamp=time.time(),
            spoken_text=spoken_text,
            topic=topic,
            level_key=verbosity_level,
            payload=payload
        )

        try:
            self._queue.put_nowait(item)
            self.stats["enqueued"] += 1
            logger.debug(f"[CVAS:PriorityEngine] Enqueued alert for {topic} with priority {priority_val}")
            return True
        except queue.Full:
            self.stats["dropped_full"] += 1
            logger.warning(f"[CVAS:PriorityEngine] Queue full (max={self.max_queue_size}). Dropping item: {spoken_text}")
            return False

    def fetch_next_alert(self, timeout: float = 1.0) -> Optional[VoicePriorityItem]:
        """Fetches the highest priority alert from the queue."""
        try:
            item = self._queue.get(timeout=timeout)
            return item
        except queue.Empty:
            return None

    def record_spoken(self) -> None:
        """Records a successful speech event timestamp for rate limiting."""
        self._spoken_timestamps.append(time.time())
        self.stats["spoken"] += 1

    def mark_done(self) -> None:
        """Signals task completion to queue."""
        try:
            self._queue.task_done()
        except ValueError:
            pass

    def clear_queue(self) -> int:
        """Empties all pending queued items."""
        count = 0
        while not self._queue.empty():
            try:
                self._queue.get_nowait()
                self._queue.task_done()
                count += 1
            except (queue.Empty, ValueError):
                break
        self.stats["cleared"] += count
        logger.info(f"[CVAS:PriorityEngine] Cleared {count} items from priority queue.")
        return count

    def get_items_snapshot(self) -> List[Dict[str, Any]]:
        """Returns a snapshot of items in the queue without consuming them."""
        snapshot = []
        with self._queue.mutex:
            for item in list(self._queue.queue):
                snapshot.append({
                    "priority": item.priority,
                    "topic": item.topic,
                    "level_key": item.level_key,
                    "spoken_text": item.spoken_text,
                    "timestamp": item.timestamp,
                })
        return snapshot
