import math
import logging
from collections import Counter

logger = logging.getLogger(__name__)


def _mask_domain(domain: str) -> str:
    """
    Mask a domain for safe logging — prevents exfiltrated data encoded in
    DNS labels from being written to log files or shipped to SIEM.
    Shows: first 4 chars of SLD + '***' + TLD only.
    Example: 'exfiltrated-payload.evil.com' → 'exfi***.evil.com'
    """
    parts = domain.split(".")
    if len(parts) >= 2:
        sld = parts[0]
        tld = ".".join(parts[1:])
        masked_sld = sld[:4] + "***" if len(sld) > 4 else sld + "***"
        return f"{masked_sld}.{tld}"
    return domain[:4] + "***"


class DGADetector:
    """Detects Domain Generation Algorithms (DGA) based on Shannon Entropy and n-gram analysis."""

    @staticmethod
    def shannon_entropy(domain_str: str) -> float:
        """Calculates the Shannon entropy of a domain string. High entropy often means DGA."""
        if not domain_str:
            return 0.0

        clean_str = domain_str.split('.')[0] if '.' in domain_str else domain_str
        counts = Counter(clean_str)
        lengths = len(clean_str)
        entropy = -sum((count / lengths) * math.log2(count / lengths) for count in counts.values())
        return entropy

    @classmethod
    def is_dga(cls, domain: str, threshold: float = 3.8) -> bool:
        """
        Returns True if the domain is likely DGA.

        NOTE: dga_entropy_threshold=3.8 is tuned for random/pseudo-random DGA families
        (e.g., Conficker, Kraken). Dictionary-based DGA families (e.g., Matsnu, Suppobox)
        generate pronounceable domains with lower entropy (~2.8-3.2) and will NOT be
        caught by this detector alone — rely on the DART Lexical Analyzer (ngram_surprise)
        for those families. Consider lowering threshold to 3.2 if Matsnu-style DGA is
        a concern in your threat model.
        """
        entropy = cls.shannon_entropy(domain)
        is_dga = entropy >= threshold
        if is_dga:
            # Mask domain to avoid logging exfiltrated data encoded in DNS labels (SEC-6)
            logger.info(f"DGA Detected: {_mask_domain(domain)} (Entropy: {entropy:.2f})")
        return is_dga
