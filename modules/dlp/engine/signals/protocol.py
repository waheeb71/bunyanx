from .entropy import PROTOCOL_ENTROPY_BASELINES

class ProtocolBaselineRegistry:
    """
    Compares payload entropy against the known normal range for each protocol.
    Any deviation outside the expected range becomes a "protocol anomaly score".
    This is how we detect DNS Tunneling, ICMP Covert Channels, etc. — zero-day.
    """

    @staticmethod
    def deviation_score(entropy: float, protocol: str) -> float:
        proto = protocol.upper()
        low, high = PROTOCOL_ENTROPY_BASELINES.get(proto, (2.0, 7.0))

        if low <= entropy <= high:
            return 0.0

        if entropy > high:
            overshoot = entropy - high
            max_possible = 8.0 - high
            return min(overshoot / max(max_possible, 0.1), 1.0)
        else:
            undershoot = low - entropy
            max_possible = low
            return min(undershoot / max(max_possible, 0.1), 1.0) * 0.5
