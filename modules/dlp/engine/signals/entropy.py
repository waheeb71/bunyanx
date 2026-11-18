import math
from typing import Dict, Tuple

PROTOCOL_ENTROPY_BASELINES: Dict[str, Tuple[float, float]] = {
    "DNS":   (1.5, 4.2),
    "HTTP":  (3.0, 5.5),
    "HTTPS": (6.0, 8.0),   # TLS is always high — intentionally wide range
    "SMTP":  (3.5, 5.0),
    "FTP":   (3.0, 6.0),
    "ICMP":  (0.0, 3.5),   # ICMP should be very low entropy
    "SSH":   (6.5, 8.0),
    "UDP":   (2.0, 5.5),
    "TCP":   (2.0, 6.0),
}

class ShannonEntropyCalc:
    """
    Computes Shannon entropy H(X) = -Σ p(x)·log₂p(x) for raw bytes.
    Output range: 0.0 (fully repetitive) → 8.0 (fully random/encrypted).
    """

    @staticmethod
    def compute(data: bytes) -> float:
        if not data:
            return 0.0
        from collections import defaultdict
        freq: Dict[int, int] = defaultdict(int)
        for byte in data:
            freq[byte] += 1
        n = len(data)
        entropy = 0.0
        for count in freq.values():
            p = count / n
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    @staticmethod
    def score(entropy: float, protocol: str) -> float:
        """
        Converts raw entropy into a 0.0–1.0 score relative to protocol baseline.
        Returns 0.0 for normal entropy, closer to 1.0 for highly suspicious.
        """
        if protocol.upper() in ("HTTPS", "SSH", "TLS"):
            return 0.0

        if entropy >= 7.2:
            return 1.0
        elif entropy >= 6.5:
            return 0.75
        elif entropy >= 5.5:
            return 0.45
        elif entropy >= 4.5:
            return 0.15
        else:
            return 0.0
