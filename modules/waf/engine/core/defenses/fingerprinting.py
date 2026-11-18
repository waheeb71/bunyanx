"""
Enterprise bunyanx — Advanced Client Fingerprinting Engine

Detects bots that spoof User-Agents by analyzing TLS fingerprints (JA3/JA4)
and HTTP header ordering using full Needleman-Wunsch Sequence Alignment.

Layers:
  1. JA3/JA4 TLS hash blacklist (scripting tools vs claimed browser)
  2. Needleman-Wunsch alignment of actual header order vs known browser profiles
  3. Micro-anomaly checks (missing Accept-Encoding, impossible UA version, etc.)
"""

import logging
import hashlib
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class FingerprintResult:
    is_suspicious: bool
    risk_score: float = 0.0
    client_type: str = "unknown"
    ja3_hash: Optional[str] = None
    reason: Optional[str] = None
    alignment_score: float = 0.0   # Needleman-Wunsch similarity (0.0–1.0)


# ── Needleman-Wunsch Sequence Alignment ─────────────────────────────────────

def _needleman_wunsch(seq_a: List[str], seq_b: List[str],
                      match: int = 2, mismatch: int = -1, gap: int = -1) -> float:
    """
    Full global Needleman-Wunsch alignment between two header-key sequences.
    Returns a similarity ratio in [0.0, 1.0]:
      1.0  = perfect match
      0.0  = completely different sequences

    Time complexity: O(|a| × |b|) — acceptable for typical HTTP header counts (10-40).
    """
    n, m = len(seq_a), len(seq_b)
    if n == 0 or m == 0:
        return 0.0

    # Initialise scoring matrix
    dp = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(n + 1):
        dp[i][0] = i * gap
    for j in range(m + 1):
        dp[0][j] = j * gap

    # Fill matrix
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            score_diag = dp[i-1][j-1] + (match if seq_a[i-1] == seq_b[j-1] else mismatch)
            score_up   = dp[i-1][j] + gap
            score_left = dp[i][j-1] + gap
            dp[i][j]   = max(score_diag, score_up, score_left)

    raw_score = dp[n][m]

    # Normalise: perfect match score = min(n, m) * match
    max_possible = min(n, m) * match
    min_possible = max(n, m) * gap  # worst case: all gaps

    if max_possible == min_possible:
        return 1.0

    similarity = (raw_score - min_possible) / (max_possible - min_possible)
    return max(0.0, min(1.0, similarity))


# ── Browser Profile Database ─────────────────────────────────────────────────

# Canonical header ordering for major browsers (based on empirical traffic analysis).
# These are the keys only — order matters, values do not.
BROWSER_PROFILES: Dict[str, List[str]] = {
    "chrome": [
        "host", "connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
        "upgrade-insecure-requests", "user-agent", "accept", "sec-fetch-site",
        "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "accept-encoding",
        "accept-language",
    ],
    "chrome_xhr": [
        "host", "connection", "sec-ch-ua", "sec-ch-ua-mobile", "x-requested-with",
        "user-agent", "content-type", "accept", "sec-fetch-site", "sec-fetch-mode",
        "sec-fetch-dest", "referer", "accept-encoding", "accept-language",
    ],
    "firefox": [
        "host", "user-agent", "accept", "accept-language", "accept-encoding",
        "connection", "upgrade-insecure-requests", "sec-fetch-dest",
        "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
    ],
    "safari": [
        "host", "accept", "user-agent", "accept-language", "accept-encoding",
        "connection",
    ],
    "edge": [
        "host", "connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
        "upgrade-insecure-requests", "user-agent", "accept", "sec-fetch-site",
        "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "accept-encoding",
        "accept-language",
    ],
    "mobile_ios": [
        "host", "accept", "user-agent", "accept-language", "accept-encoding",
    ],
    "mobile_android": [
        "host", "connection", "sec-ch-ua", "sec-ch-ua-mobile", "user-agent",
        "accept", "accept-encoding", "accept-language",
    ],
}

# Similarity threshold below which we consider the header order suspicious
ALIGNMENT_SUSPICIOUS_THRESHOLD = 0.45   # <45% match → bot
ALIGNMENT_HIGH_RISK_THRESHOLD   = 0.25  # <25% match → high confidence bot


# ── JA3/JA4 Threat Intel ────────────────────────────────────────────────────

# Known bad JA3 hashes for popular scripting / scanning tools.
# In production this should be fed from a live TI database.
SUSPICIOUS_JA3_HASHES: Dict[str, str] = {
    "cd08e31494f9531f560d64c695473da9": "python-requests",
    "3b5074b1b5d032e5620f69f9f700ff0e": "curl",
    "ca9be6e205ab04cbebe777f98fb6957a": "go-http-client",
    "a0e9f5d64349fb13191bc781f81f42e1": "sqlmap",
    "6bea65232d6daa7c2e7ad6e5ad20cf6f": "nikto",
    "b386946a5a44d1ddcc843bc75336dfce": "nmap-http",
    "b47eb0ceb8bcb2f4afad84c6d6434a67": "scrapy",
    "e30f4ca51c31c0e6a42d944cd9dd2a3e": "nuclei",
    "1a9a3b62e9c63a6e50bf12cf47a05b22": "httpx",
}

BROWSER_JA3_PREFIXES = {"chrome", "firefox", "safari", "edge"}


# ── User-Agent Version Anomaly Checks ───────────────────────────────────────

def _ua_version_anomaly(user_agent: str, client_type: str) -> Optional[str]:
    """
    Detect impossible UA version combinations, e.g. Chrome/50 on a Windows 11 UA
    or Safari with a Linux platform — common bot spoofing patterns.
    """
    ua_lower = user_agent.lower()
    if client_type == "safari" and "linux" in ua_lower:
        return "Safari never runs on Linux — spoofed UA"
    if client_type == "chrome":
        # Chrome claims version in token: Chrome/X.Y
        try:
            idx = ua_lower.index("chrome/")
            ver_str = user_agent[idx + 7:].split()[0].split(".")[0]
            ver = int(ver_str)
            if ver < 80:
                return f"Chrome version {ver} is EOL (pre-2020) — likely spoofed"
        except (ValueError, IndexError):
            pass
    if client_type == "firefox":
        try:
            idx = ua_lower.index("firefox/")
            ver = int(user_agent[idx + 8:].split(".")[0])
            if ver < 70:
                return f"Firefox version {ver} is EOL — likely spoofed"
        except (ValueError, IndexError):
            pass
    return None


# ── Main Fingerprinting Engine ───────────────────────────────────────────────

class AdvancedFingerprinting:
    """
    Client Fingerprinting Engine — 3-layer bot detection:

    Layer 1 — JA3/JA4 TLS hash blacklist
    Layer 2 — Needleman-Wunsch global sequence alignment of HTTP header order
    Layer 3 — UA version anomaly and micro-signal checks
    """

    def __init__(self, check_ja3: bool = True, check_headers: bool = True):
        self.check_ja3    = check_ja3
        self.check_headers = check_headers
        logger.info(
            "AdvancedFingerprinting initialized | JA3=%s | "
            "NW-Alignment=%s | Browser profiles=%d",
            self.check_ja3, self.check_headers, len(BROWSER_PROFILES),
        )

    # ── Public API ───────────────────────────────────────────────────────────

    def analyze(
        self,
        user_agent: str,
        headers: Dict[str, str],
        ja3_hash: Optional[str] = None,
        ja4_hash: Optional[str] = None,
    ) -> FingerprintResult:
        """
        Analyze a client connection for UA spoofing and fingerprint anomalies.

        Returns a FingerprintResult with:
          - is_suspicious  : bool
          - risk_score     : 0.0–1.0
          - alignment_score: Needleman-Wunsch similarity to the claimed browser profile
          - reason         : human-readable explanation for SIEM/SOC
        """
        score     = 0.0
        reasons: List[str] = []
        is_susp   = False
        alignment_score = 1.0  # default: perfectly aligned (no suspicion)

        ua_lower    = user_agent.lower()
        client_type = self._detect_browser(ua_lower)

        # ── Layer 1: JA3 TLS Fingerprint ─────────────────────────────────
        if self.check_ja3 and ja3_hash:
            tool = SUSPICIOUS_JA3_HASHES.get(ja3_hash)
            if tool:
                if client_type in BROWSER_JA3_PREFIXES:
                    score    += 0.90
                    is_susp   = True
                    reasons.append(
                        f"JA3 identifies scripting tool '{tool}' "
                        f"but UA claims '{client_type}' — high-confidence spoof"
                    )
                else:
                    score += 0.40
                    reasons.append(f"JA3 matches known bot/scanner tool '{tool}'")

        # ── Layer 2: Needleman-Wunsch Header Order Alignment ─────────────
        if self.check_headers and client_type in BROWSER_PROFILES:
            actual_keys  = [k.lower() for k in headers.keys()]
            profile_keys = BROWSER_PROFILES[client_type]

            # Also test secondary profile (e.g. chrome_xhr) and take the best score
            alignment_score = _needleman_wunsch(actual_keys, profile_keys)

            secondary = f"{client_type}_xhr"
            if secondary in BROWSER_PROFILES:
                alt_score = _needleman_wunsch(actual_keys, BROWSER_PROFILES[secondary])
                alignment_score = max(alignment_score, alt_score)

            if alignment_score < ALIGNMENT_HIGH_RISK_THRESHOLD:
                score    += 0.70
                is_susp   = True
                reasons.append(
                    f"Header order critically deviates from '{client_type}' profile "
                    f"(NW-similarity={alignment_score:.2f}) — strong bot signal"
                )
            elif alignment_score < ALIGNMENT_SUSPICIOUS_THRESHOLD:
                score    += 0.45
                is_susp   = True
                reasons.append(
                    f"Header order deviates from '{client_type}' profile "
                    f"(NW-similarity={alignment_score:.2f})"
                )

        # ── Layer 3: Micro-anomalies ──────────────────────────────────────
        header_keys_lower = [k.lower() for k in headers.keys()]

        # 3a. Real browsers ALWAYS send Accept-Encoding
        if "accept-encoding" not in header_keys_lower and client_type != "unknown":
            score   += 0.30
            reasons.append(
                f"'{client_type}' browsers always send Accept-Encoding — missing header"
            )

        # 3b. UA version anomaly (impossible version/platform combos)
        ua_anomaly = _ua_version_anomaly(user_agent, client_type)
        if ua_anomaly:
            score   += 0.35
            is_susp  = True
            reasons.append(ua_anomaly)

        # 3c. Headless Chrome / Selenium signals in UA
        if any(sig in ua_lower for sig in ("headlesschrome", "phantomjs", "selenium", "webdriver")):
            score   += 0.95
            is_susp  = True
            reasons.append("Headless browser / automation framework detected in User-Agent")

        # 3d. Missing Host header (HTTP/1.1 RFC violation — scripting tools often omit it)
        if "host" not in header_keys_lower:
            score   += 0.20
            reasons.append("Missing Host header — RFC 7230 violation, common in scripts")

        return FingerprintResult(
            is_suspicious   = is_susp or (score >= 0.5),
            risk_score      = min(1.0, score),
            client_type     = client_type,
            ja3_hash        = ja3_hash,
            reason          = " | ".join(reasons) if reasons else None,
            alignment_score = alignment_score,
        )

    # ── Private helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _detect_browser(ua_lower: str) -> str:
        """Detect claimed browser from User-Agent string."""
        # Order matters: Edge must come before Chrome (Edge UA contains "chrome")
        if "edg/" in ua_lower or "edga/" in ua_lower:
            return "edge"
        if "chrome" in ua_lower and "mobile" not in ua_lower:
            return "chrome"
        if "firefox" in ua_lower:
            return "firefox"
        if "safari" in ua_lower and "chrome" not in ua_lower:
            if "mobile" in ua_lower or "iphone" in ua_lower or "ipad" in ua_lower:
                return "mobile_ios"
            return "safari"
        if "android" in ua_lower:
            return "mobile_android"
        return "unknown"
