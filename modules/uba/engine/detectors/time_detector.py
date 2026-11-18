"""
Enterprise bunyanx — UBA Time Anomaly Detector

Detects access at unusual hours compared to the user's established work-hour
baseline using a 3-sigma rule applied to the per-user hour histogram.

Score: 0.0 – 0.35
"""

import math
import time
import logging
from typing import Dict

logger = logging.getLogger(__name__)


def _histogram_mean_stddev(histogram: Dict[str, int]) -> tuple[float, float]:
    """Compute circular mean and circular standard deviation of hours."""
    total = sum(histogram.values())
    if total == 0:
        return 12.0, 6.0   # fallback

    sum_sin = 0.0
    sum_cos = 0.0
    for h_str, count in histogram.items():
        try:
            h = float(h_str)
        except ValueError:
            continue
        theta = h * (2 * math.pi / 24.0)
        sum_sin += count * math.sin(theta)
        sum_cos += count * math.cos(theta)

    mean_sin = sum_sin / total
    mean_cos = sum_cos / total

    # Circular mean angle
    mean_theta = math.atan2(mean_sin, mean_cos)
    mean_hour = (mean_theta * (24.0 / (2 * math.pi))) % 24.0

    # Resulting vector length R
    R = math.sqrt(mean_sin ** 2 + mean_cos ** 2)
    R = max(1e-9, min(R, 1.0))

    # Circular standard deviation in radians
    stddev_rad = math.sqrt(-2.0 * math.log(R))
    # Convert to hours
    stddev_hours = stddev_rad * (24.0 / (2 * math.pi))

    # Floor stddev at 1.0 hour to prevent division by zero or overly narrow thresholds
    # Cap at 12.0 hours (maximum spread)
    stddev_hours = max(1.0, min(stddev_hours, 12.0))

    return mean_hour, stddev_hours


class TimeAnomalyDetector:
    """
    Analyse whether the event's current hour falls within the user's
    typical work-hour window.

    Strategy:
    1. If histogram has enough data (≥ baseline_min_events on profile):
       Use 3-sigma Gaussian test relative to the hour distribution.
    2. Otherwise: fall back to simple start/end window check.
    """

    MAX_SCORE = 0.35

    def analyze(self, profile, current_time: float | None = None) -> tuple[float, list[str]]:
        """
        Returns (score, flags).

        profile: UBAUserProfile DB row (or any object with the expected attrs)
        current_time: unix timestamp — defaults to now
        """
        ts = current_time or time.time()
        hour = time.localtime(ts).tm_hour
        flags: list[str] = []
        score = 0.0

        histogram: dict = profile.hour_histogram or {}

        if profile.baseline_locked and histogram:
            mean, stddev = _histogram_mean_stddev(histogram)
            # Handle wrap-around midnight (simplistic: use modular distance)
            delta = min(abs(hour - mean), 24 - abs(hour - mean))
            sigma = delta / max(stddev, 0.5)

            if sigma > 3.0:
                score = self.MAX_SCORE
                flags.append(f"time:extreme_outlier_{hour}h ({sigma:.1f}σ)")
            elif sigma > 2.0:
                score = self.MAX_SCORE * 0.6
                flags.append(f"time:unusual_hour_{hour}h ({sigma:.1f}σ)")
        else:
            # Fallback: simple window check (default 0 to 23 allows 24/7 access)
            start = getattr(profile, 'typical_hours_start', 0)
            end = getattr(profile, 'typical_hours_end', 23)
            if not (start <= hour <= end):
                score = self.MAX_SCORE * 0.7
                flags.append(f"time:outside_window_{hour}h (expected {start}-{end})")

        return score, flags

    def update_histogram(self, histogram: dict, current_time: float | None = None) -> dict:
        """Increment the hour bucket for the current time."""
        ts = current_time or time.time()
        hour = str(time.localtime(ts).tm_hour)
        histogram = dict(histogram or {})
        histogram[hour] = histogram.get(hour, 0) + 1
        return histogram
