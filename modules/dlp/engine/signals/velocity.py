import time
from collections import deque
from modules.dlp.engine.storage.profile_store import FlowProfile

class VelocityAnalyzer:
    """
    Compares current data transfer rate against the IP's learned personal baseline.
    Uses an Exponential Moving Average (EMA) to update the baseline dynamically.
    """
    EMA_ALPHA = 0.15  # Lower = more stable baseline, slower adaptation

    @staticmethod
    def compute_rate(velocity_log: deque, window_sec: int) -> float:
        """Bytes/sec over the given window."""
        now = time.time()
        cutoff = now - window_sec
        total_bytes = 0
        for ts, b in reversed(velocity_log):
            if ts < cutoff:
                break
            total_bytes += b
        return total_bytes / window_sec

    @staticmethod
    def score(profile: FlowProfile, new_bytes: int) -> float:
        """Returns 0.0–1.0 velocity anomaly score."""
        now = time.time()
        profile.velocity_log.append((now, new_bytes))

        # Evict logs older than 3600 seconds to bound memory and CPU usage
        cutoff = now - 3600
        while profile.velocity_log and profile.velocity_log[0][0] < cutoff:
            profile.velocity_log.popleft()

        current_rate = VelocityAnalyzer.compute_rate(profile.velocity_log, 30)  # 30s burst rate

        # Avoid false positives on low-speed traffic
        if current_rate < 50 * 1024:
            # Still update baseline to adapt to normal traffic rates
            profile.baseline_velocity_bps = (
                VelocityAnalyzer.EMA_ALPHA * current_rate
                + (1 - VelocityAnalyzer.EMA_ALPHA) * profile.baseline_velocity_bps
            )
            profile.baseline_samples += 1
            return 0.0

        if profile.baseline_samples < 20:
            rate = VelocityAnalyzer.compute_rate(profile.velocity_log, 300)
            if profile.baseline_velocity_bps == 0:
                profile.baseline_velocity_bps = rate
            else:
                profile.baseline_velocity_bps = (
                    VelocityAnalyzer.EMA_ALPHA * rate
                    + (1 - VelocityAnalyzer.EMA_ALPHA) * profile.baseline_velocity_bps
                )
            profile.baseline_samples += 1
            return 0.0

        baseline = max(profile.baseline_velocity_bps, 50 * 1024)  # minimum baseline of 50 KB/s

        ratio = current_rate / baseline
        profile.baseline_velocity_bps = (
            VelocityAnalyzer.EMA_ALPHA * current_rate
            + (1 - VelocityAnalyzer.EMA_ALPHA) * profile.baseline_velocity_bps
        )
        profile.baseline_samples += 1

        if ratio < 3.0:
            return 0.0
        elif ratio < 5.0:
            return 0.3
        elif ratio < 10.0:
            return 0.6 + (ratio - 5.0) * 0.08
        else:
            return 1.0
