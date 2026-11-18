import math
from collections import deque

class ChunkPatternDetector:
    """
    Detects systematic file splitting by analyzing the statistical distribution
    of recent packet sizes. Very low variance across many similarly-sized packets
    is a strong indicator of automated, tool-driven data exfiltration.
    """

    @staticmethod
    def score(recent_sizes: deque, new_size: int) -> float:
        recent_sizes.append(new_size)

        if len(recent_sizes) < 10:
            return 0.0  # Need minimum window

        sizes = list(recent_sizes)
        mean = sum(sizes) / len(sizes)
        if mean < 64:
            return 0.0  # Too small to be meaningful

        # To avoid false positives on standard TCP segment streams (MSS ~ 1400-1460 bytes)
        # or large bulk transfers where packets are naturally filled to max MTU.
        if mean >= 1350:
            return 0.0

        variance = sum((s - mean) ** 2 for s in sizes) / len(sizes)
        std_dev = math.sqrt(variance)
        cv = std_dev / mean  # Coefficient of Variation

        if cv < 0.05 and mean > 512:
            return 0.85
        elif cv < 0.10 and mean > 512:
            return 0.60
        elif cv < 0.15 and mean > 1024:
            return 0.35
        else:
            return 0.0
