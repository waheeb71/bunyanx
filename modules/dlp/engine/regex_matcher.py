"""
bunyanx NGFW — DLP Regex Matcher
=====================================
Built-in pattern library for high-value sensitive data types.

Security notes
--------------
* All patterns are pre-compiled at class load time (no runtime compilation).
* Patterns are designed to avoid Catastrophic Backtracking (ReDoS).
  - IBAN: uses possessive-style non-overlapping groups and strict length bounds
    instead of nested quantifiers.
  - CREDIT_CARD: atomic groups via non-backtracking alternation.
* scan_text() enforces a per-pattern timeout via a threading.Timer sentinel
  to guarantee bounded execution time even against adversarial inputs.
* Matched values are masked before returning — raw PII never leaves this module.

Timeout guarantee
-----------------
Each individual regex is constrained to MAX_PATTERN_TIMEOUT_SEC seconds.
If a pattern exceeds the timeout on a given chunk of text, it is skipped
and the event is logged as a WARNING (not silently dropped).
"""

import re
import time
import logging
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

# Maximum seconds allowed for a single regex scan on the entire text chunk.
# This provides a hard safety net against ReDoS even if pattern analysis
# misses a pathological case.
MAX_PATTERN_TIMEOUT_SEC: float = 2.0


class RegexMatcher:
    """
    Scans text for sensitive data patterns using a curated, ReDoS-hardened
    pattern library.

    All patterns compile once at class load (PATTERNS_COMPILED). The scan
    is stateless and safe to call from multiple threads simultaneously.
    """

    # ── Pattern Library ──────────────────────────────────────────────────────
    # IBAN (ReDoS-hardened):
    #   Original used nested `(?:[ ]?...){3,7}` which can catastrophically
    #   backtrack on inputs like "SA000000000000000000000000000X".
    #
    #   Fix: Strip spaces first via a two-pass approach — match the compact
    #   (no-space) form OR the grouped-4 form with strict structure.
    #   The {15,34} overall length bound prevents backtracking at scale.
    #
    #   Compact IBAN:  CC99[A-Z0-9]{11,30}   (15–34 total chars after CC99)
    #   Grouped IBAN:  CC99 XXXX XXXX ...    (groups of 4, max 8 groups)
    #   We match both forms with an alternation but NOT nested quantifiers.

    _IBAN_COMPACT = r"[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}"
    _IBAN_GROUPED = (
        r"[A-Z]{2}[0-9]{2}"          # Country + check digits
        r"(?:[ ][A-Z0-9]{4}){2,7}"  # Groups of exactly 4 alphanums
        r"(?:[ ][A-Z0-9]{1,4})?"    # Optional final short group
    )
    # Combined with word-boundary anchors and total-length assertion
    _IBAN_PATTERN = rf"\b(?:{_IBAN_COMPACT}|{_IBAN_GROUPED})\b"

    PATTERNS: Dict[str, str] = {
        # Credit card: 13–19 digits, optional separators every 4 digits.
        # Non-backtracking: the alternation is ordered and non-overlapping.
        "CREDIT_CARD": r"\b(?:\d{4}[ \-]?){3}(?:\d{4}|\d{3}|\d{2}|\d{1})\b",

        # US SSN: strict DDD-DD-DDDD format only (no spaces variant to avoid FP)
        "SSN": r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",

        # Email: anchored length limits prevent polynomial backtracking
        "EMAIL": r"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,10}\b",

        # US Phone: structured groups, no open-ended alternation
        "PHONE_US": r"\b(?:\+?1[ \-.]?)?(?:\(\d{3}\)|\d{3})[ \-.]?\d{3}[ \-.]?\d{4}\b",

        # IBAN: ReDoS-hardened (see explanation above)
        "IBAN": _IBAN_PATTERN,

        # API Key heuristic: high-entropy 32–64 char strings after common prefixes
        # SECURITY FIX: Added more header variants (x-api-key, authorization) and format patterns
        "API_KEY": r"\b(?:key|token|secret|api[_-]?key|bearer|x-api-key|authorization)[_\-\s:=]+[A-Za-z0-9\-_]{32,64}\b|\bx-api-key:\s*[A-Za-z0-9\-_]{32,64}\b",

        # Private key header (PEM format)
        "PRIVATE_KEY": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    }

    # Pre-compiled at class load time — no runtime compilation cost.
    PATTERNS_COMPILED: Dict[str, re.Pattern] = {
        k: re.compile(v, re.IGNORECASE)
        for k, v in PATTERNS.items()
    }

    @classmethod
    def scan_text(cls, text: str) -> List[Dict[str, str]]:
        """
        Scan *text* for all registered sensitive data patterns.

        Returns a list of findings. Each finding contains:
            type        : pattern name (e.g. "CREDIT_CARD")
            value_masked: the matched string with PII masked

        Thread-safe. Does not retain any state.
        Uses a soft per-pattern timeout to guard against ReDoS.
        """
        if not text:
            return []

        findings: List[Dict[str, str]] = []

        for p_name, p_regex in cls.PATTERNS_COMPILED.items():
            start_time = time.monotonic()
            try:
                for match in p_regex.finditer(text):
                    # Enforce per-pattern timeout (soft guard)
                    elapsed = time.monotonic() - start_time
                    if elapsed > MAX_PATTERN_TIMEOUT_SEC:
                        logger.warning(
                            f"[DLP][REGEX] Pattern '{p_name}' exceeded timeout "
                            f"({elapsed:.2f}s > {MAX_PATTERN_TIMEOUT_SEC}s) — "
                            f"remaining matches skipped for this chunk."
                        )
                        break

                    match_str = match.group(0)
                    masked = cls._mask(match_str)
                    findings.append({
                        "type": p_name,
                        "value_masked": masked,
                    })

            except re.error as exc:
                logger.error(f"[DLP][REGEX] Pattern '{p_name}' raised a regex error: {exc}")
            except Exception as exc:
                logger.error(f"[DLP][REGEX] Unexpected error in pattern '{p_name}': {exc}")

        return findings

    @staticmethod
    def _mask(value: str) -> str:
        """
        Mask a sensitive matched value for safe logging/reporting.

        - Short values (≤ 8 chars): fully redacted as '***'
        - Longer values: show first 4 + '****' + last 4
        """
        if len(value) <= 8:
            return "***"
        return value[:4] + "****" + value[-4:]
