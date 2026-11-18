import time
from modules.dlp.engine.storage.profile_store import FlowProfile

ACCUMULATION_WINDOW_SEC = 86400

class AccumulationTracker:
    """
    Tracks total data transferred from a source IP to each destination
    over a 24-hour rolling window. Detects "low and slow" exfiltration
    that individual packet analysis would completely miss.
    """
    WARN_THRESHOLD_BYTES   = 50 * 1024 * 1024   # 50 MB
    ALERT_THRESHOLD_BYTES  = 200 * 1024 * 1024  # 200 MB
    BLOCK_THRESHOLD_BYTES  = 500 * 1024 * 1024  # 500 MB

    @staticmethod
    def score(profile: FlowProfile, dst_ip: str, new_bytes: int) -> float:
        now = time.time()
        hour_key = int(now // 3600)
        cutoff_hour = int((now - ACCUMULATION_WINDOW_SEC) // 3600)

        # Restrict the number of tracked destinations to prevent memory exhaustion DoS
        if len(profile.accumulation_log) >= 128 and dst_ip not in profile.accumulation_log:
            # Evict the least recently updated destination
            oldest_dst = min(
                profile.accumulation_log.keys(),
                key=lambda ip: profile.accumulation_log[ip][-1][0] if profile.accumulation_log[ip] else 0
            )
            profile.accumulation_log.pop(oldest_dst, None)
            profile.accumulation.pop(oldest_dst, None)

        log = profile.accumulation_log[dst_ip]
        
        # Hour-bucket summation: if the last entry is the same hour, add to it
        if log and log[-1][0] == hour_key:
            log[-1] = (hour_key, log[-1][1] + new_bytes)
        else:
            log.append((hour_key, new_bytes))

        # Evict hour buckets older than 24 hours
        while log and log[0][0] < cutoff_hour:
            log.popleft()

        total = sum(b for _, b in log)
        profile.accumulation[dst_ip] = total

        if total >= AccumulationTracker.BLOCK_THRESHOLD_BYTES:
            return 1.0
        elif total >= AccumulationTracker.ALERT_THRESHOLD_BYTES:
            return 0.75
        elif total >= AccumulationTracker.WARN_THRESHOLD_BYTES:
            return 0.4
        else:
            return 0.0
