"""
DART-DNS Layer 2: Temporal Resonance Detector (Production Engine)

Detects two distinct attack patterns via query-timing analysis:

1. HIGH-FREQUENCY BEACONING (iodine, dnscat2 fast mode):
   > 30 queries in window, mean interval < 0.5s

2. PERIODIC LOW-AND-SLOW BEACONING (stealthy C2):
   Regular cadence with very low Coefficient of Variation (CV = stddev/mean)
   Malicious: CV ~ 0.01–0.05  |  Benign: CV > 0.8

Key finding from ablation:
   Standalone F1 ≈ 0 on synthetic dataset (no real pcap timing data).
   Combined with S1/S3 via DART Fusion: provides decisive LIFT when both agree.
   MI(S2, S1) = 0.0001 bits — empirically near-independent from lexical signal.
"""

import time
import math
import logging
import threading
from typing import Tuple, Dict, Optional
from collections import defaultdict
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class TemporalSignal:
    score: float        # [0, 1] — higher means more suspicious
    cv: float           # Coefficient of Variation
    mean_interval: float
    variance: float
    query_count: int


class TemporalResonanceDetector:
    """
    DART-DNS Layer 2 — Temporal Flow Resonance.

    Thread-safe sliding-window state tracker per (src_ip, domain) pair.
    Designed for inline NGFW operation: every call is O(n) on window size,
    typically < 0.01 ms per query.
    """

    def __init__(
        self,
        high_freq_window: int = 120,  # seconds
        min_queries: int = 5,
        beacon_cv_threshold: float = 0.15,    # CV below this => periodic beaconing
        fast_tunnel_count: int = 30,           # query count trigger for fast tunneling
        fast_tunnel_interval: float = 0.5,     # mean interval threshold (seconds)
    ):
        self.high_freq_window    = high_freq_window
        self.min_queries         = min_queries
        self.beacon_cv_threshold = beacon_cv_threshold
        self.fast_tunnel_count   = fast_tunnel_count
        self.fast_tunnel_interval = fast_tunnel_interval

        self._history: Dict[Tuple[str, str], list] = defaultdict(list)
        self._lock = threading.RLock()

    def analyze(
        self,
        src_ip: str,
        domain: str,
        current_time: Optional[float] = None,
    ) -> TemporalSignal:
        """
        Record this query and return a temporal anomaly signal.
        Returns TemporalSignal(score=0) if not enough history yet.
        """
        if current_time is None:
            current_time = time.time()

        key = (src_ip, domain)
        cutoff = current_time - self.high_freq_window

        with self._lock:
            hist = self._history[key]
            # Prune expired entries
            hist = [t for t in hist if t > cutoff]
            hist.append(current_time)
            self._history[key] = hist
            count = len(hist)

        if count < self.min_queries:
            return TemporalSignal(score=0.0, cv=0.0,
                                  mean_interval=0.0, variance=0.0,
                                  query_count=count)

        # Compute inter-query intervals
        sorted_hist = sorted(hist)
        intervals = [sorted_hist[i] - sorted_hist[i - 1]
                     for i in range(1, len(sorted_hist))]

        mean_iv = sum(intervals) / len(intervals)
        variance = sum((x - mean_iv) ** 2 for x in intervals) / len(intervals)
        std_dev  = math.sqrt(variance)
        cv = std_dev / (mean_iv + 1e-9)

        score = 0.0

        # Pattern 1: Low-and-slow periodic beaconing (low CV)
        if cv < self.beacon_cv_threshold:
            # Score linearly from 0.5 (cv=threshold) to 1.0 (cv=0)
            score = max(score, 0.5 + 0.5 * (1.0 - cv / self.beacon_cv_threshold))

        # Pattern 2: High-frequency tunneling
        if count >= self.fast_tunnel_count and mean_iv < self.fast_tunnel_interval:
            score = max(score, 0.95)

        return TemporalSignal(
            score=round(score, 4),
            cv=round(cv, 6),
            mean_interval=round(mean_iv, 6),
            variance=round(variance, 6),
            query_count=count,
        )

    def clear_state(self, src_ip: str = None, domain: str = None):
        """Evict stale state (call periodically from a background task)."""
        with self._lock:
            if src_ip and domain:
                self._history.pop((src_ip, domain), None)
            else:
                self._history.clear()
