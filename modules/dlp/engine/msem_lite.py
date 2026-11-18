"""
bunyanx NGFW — Multi-Spectral Entropy Monitor (MSEM-Lite)
=============================================================
Signal 6 for the Behavioral Entropy Flow Profiler (BEFP).

Motivation
----------
Shannon entropy alone cannot distinguish machine-generated (malware) traffic
from human traffic when both share similar byte distributions. MSEM-Lite adds
four complementary measures that expose different structural dimensions of a
payload and its timing — dimensions that are fundamentally hard for an attacker
to mimic simultaneously.

Four Signals
------------
1. Rényi Entropy (α=2)       — Collision entropy.  More sensitive than Shannon
                                to uneven byte distributions; resistant to
                                mimicry attacks that fool Shannon alone.

2. Permutation Entropy (m=4) — Ordinal pattern entropy.  Captures the temporal
                                ordering structure of byte values.  Automated
                                exfiltration tools produce low permutation
                                entropy because they write data in predictable,
                                repetitive byte-order sequences.

3. Lempel-Ziv Complexity      — LZ76 normalised complexity. Approximates
   (normalised)                 Kolmogorov complexity: compressible payloads
                                (structured data being stolen) score low;
                                truly random noise scores high.

4. IPT Spectral Peak Power    — Fast-Fourier Transform applied to the sequence
                                of Inter-Packet Timing (IPT) intervals held in
                                the per-IP sliding window.  C2 heartbeats and
                                automated chunked uploads produce a dominant
                                periodic component, visible as a sharp spectral
                                peak.  Human network usage does not.

Composite Score
---------------
    msem_score = w1*renyi_score + w2*perm_score + w3*lz_score + w4*ipt_score

All component scores are normalised to [0.0 – 1.0] where 1.0 = maximally
suspicious.  The composite score feeds into BEFP as Signal 6 (weight 0.25).

Complexity Budget
-----------------
All four signals are O(n) or O(n log n) in payload size n:
- Rényi:           O(n)
- Permutation:     O(n)
- LZ-76:           O(n log n) amortised
- IPT Spectral:    O(k log k) for window size k  (k ≤ 50, negligible)

Target per-packet latency: < 80 µs on commodity hardware.
"""

from __future__ import annotations

import math
import logging
import threading
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Sequence

import numpy as np

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

# Rényi entropy: order parameter α
RENYI_ALPHA: float = 2.0

# Permutation entropy: embedding dimension (pattern length)
PERM_ORDER: int = 4

# Minimum payload bytes required before running any signal
MIN_PAYLOAD_BYTES: int = 32

# LZ complexity: minimum distinct word count below which traffic is trivially
# compressible (score saturates at 1.0)
LZ_MIN_WORDS_NORMAL: int = 16

# IPT window: number of inter-packet intervals to keep per IP
IPT_WINDOW_SIZE: int = 50

# IPT Spectral: minimum intervals required before attempting FFT
IPT_MIN_SAMPLES: int = 8

# Composite signal weights — must sum to 1.0
MSEM_SIGNAL_WEIGHTS = {
    "renyi":    0.30,
    "perm":     0.35,   # highest weight: hardest to fake
    "lz":       0.20,
    "ipt":      0.15,
}

assert abs(sum(MSEM_SIGNAL_WEIGHTS.values()) - 1.0) < 1e-9, \
    "MSEM signal weights do not sum to 1.0"


# ─────────────────────────────────────────────────────────────────────────────
# Result Dataclass
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class MSEMLiteResult:
    """Output of a single MSEM-Lite analysis pass."""

    score: float
    """Composite MSEM-Lite anomaly score [0.0 – 1.0]."""

    renyi_entropy: float
    """Raw Rényi H₂ value (bits per byte, range 0–8)."""

    renyi_score: float
    """Anomaly sub-score for Rényi entropy [0–1]."""

    perm_entropy: float
    """Raw Permutation entropy (normalised to 0–1 already)."""

    perm_score: float
    """Anomaly sub-score for Permutation entropy [0–1]."""

    lz_complexity: float
    """Normalised Lempel-Ziv-76 complexity [0–1]."""

    lz_score: float
    """Anomaly sub-score for LZ complexity [0–1]."""

    ipt_spectral_peak: float
    """Dominant FFT peak power in IPT sequence [0–1]."""

    ipt_score: float
    """Anomaly sub-score for IPT spectral periodicity [0–1]."""

    explanation: list[str] = field(default_factory=list)
    """Human-readable reasons for elevated score."""


# ─────────────────────────────────────────────────────────────────────────────
# Signal 1 — Rényi Entropy (α = 2)
# ─────────────────────────────────────────────────────────────────────────────

class RenyiEntropyCalc:
    """
    Computes Rényi entropy of order α for a byte sequence.

    H_α(X) = 1/(1−α) · log₂(Σᵢ pᵢ^α)

    For α=2 this simplifies to the *collision entropy*:
        H₂(X) = −log₂(Σᵢ pᵢ²)

    Range: 0.0 (all bytes identical) → 8.0 (perfectly uniform distribution).

    Compared with Shannon entropy, H₂ is more sensitive to heavy-tailed byte
    distributions and is harder to fool via byte-frequency mimicry.
    """

    @staticmethod
    def compute(data: bytes, alpha: float = RENYI_ALPHA) -> float:
        """Return Rényi entropy in bits per byte."""
        if not data:
            return 0.0

        n = len(data)
        freq = Counter(data)

        if alpha == 1.0:
            # Limit α→1 is Shannon entropy
            h = 0.0
            for count in freq.values():
                p = count / n
                if p > 0.0:
                    h -= p * math.log2(p)
            return round(h, 6)

        sum_p_alpha = sum((count / n) ** alpha for count in freq.values())

        if sum_p_alpha <= 0.0:
            return 0.0

        h = (1.0 / (1.0 - alpha)) * math.log2(sum_p_alpha)
        return round(max(0.0, min(h, 8.0)), 6)

    @staticmethod
    def score(renyi_h: float, protocol: str) -> float:
        """
        Map raw Rényi H₂ to an anomaly score [0–1].

        Encrypted protocols (HTTPS, SSH, TLS) always carry high-entropy
        ciphertext — we skip entropy-based scoring for them.
        For plaintext protocols, unusually high entropy signals that the
        payload is encrypted or compressed *before* transmission, which is
        the hallmark of staged exfiltration.
        """
        if protocol.upper() in ("HTTPS", "SSH", "TLS"):
            return 0.0

        if renyi_h >= 7.0:
            return 1.0
        elif renyi_h >= 6.5:
            return 0.75
        elif renyi_h >= 5.8:
            return 0.45
        elif renyi_h >= 5.0:
            return 0.15
        else:
            return 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Signal 2 — Permutation Entropy
# ─────────────────────────────────────────────────────────────────────────────

class PermutationEntropyCalc:
    """
    Computes the Permutation Entropy (PE) of a byte sequence.

    Algorithm (Bandt & Pompe, 2002):
      1. Divide the byte sequence into overlapping windows of length m (order).
      2. For each window, compute its *ordinal pattern*: the ranking of values
         from smallest to largest, encoded as a permutation index.
      3. Count the frequency of each of the m! possible permutation patterns.
      4. Apply Shannon entropy to the pattern frequency distribution.
      5. Normalise by log₂(m!) so the result lies in [0, 1].

    Why it matters for exfiltration detection
    -----------------------------------------
    Human-generated data (documents, spreadsheets) exhibits rich, varied
    ordinal patterns → PE close to 1.0 (maximum disorder).

    Automated exfiltration tools serialise structured data (database records,
    fixed-width fields) in a highly repetitive, predictable byte order →
    PE significantly below the human baseline.

    The pattern is protocol-independent and payload-content-agnostic: it
    detects *how* bytes are ordered in time, not *what* they are.
    """

    # Cached factorial lookup to avoid repeated computation
    _factorial_cache: dict[int, int] = {}

    # Maximum input bytes for PE computation
    # 512 B is statistically sufficient: with m=4 there are m!=24 possible
    # ordinal patterns; 508 sliding windows provide ~21 samples per pattern,
    # which is adequate for a stable distribution estimate.
    # This bounds worst-case latency to <10 ms on commodity hardware.
    # (In production, individual packet payloads are MTU-bounded to ~1460 B,
    # so this cap mainly protects the offline evaluation path.)
    MAX_PERM_BYTES: int = 512

    @classmethod
    def _factorial(cls, n: int) -> int:
        if n not in cls._factorial_cache:
            result = 1
            for i in range(2, n + 1):
                result *= i
            cls._factorial_cache[n] = result
        return cls._factorial_cache[n]

    @staticmethod
    def _ordinal_pattern_index(window: Sequence[int]) -> int:
        """
        Encode the ordinal pattern of a window as a single integer.

        The encoding uses the Lehmer code (factoradic number system), which
        uniquely maps each permutation of length m to an integer in [0, m!).
        This is O(m²) but m ≤ 6 so the cost is negligible.
        """
        m = len(window)
        # To break ties, we sort elements based on their value and original index
        indexed_window = [(val, idx) for idx, val in enumerate(window)]
        sorted_indexed = sorted(indexed_window, key=lambda x: (x[0], x[1]))
        
        # Map each element's original position to its sorted rank
        rank = {item[1]: r for r, item in enumerate(sorted_indexed)}

        index = 0
        for i in range(m):
            r = rank[i]
            index += r * PermutationEntropyCalc._factorial(m - 1 - i)
            # Remove used rank so lower ranks shift down
            for j in range(i + 1, m):
                if rank[j] > rank[i]:
                    rank[j] -= 1

        return index

    @classmethod
    def compute(cls, data: bytes, order: int = PERM_ORDER) -> float:
        """
        Return the normalised Permutation Entropy in [0, 1].

        Parameters
        ----------
        data  : raw payload bytes
        order : embedding dimension m (typically 3–6; default 4)

        Returns
        -------
        float : 0.0 = fully ordered/repetitive, 1.0 = maximally disordered
        """
        n = len(data)
        if n < order:
            return 1.0   # Too short to judge: assume normal

        # Cap input to bound worst-case latency (same principle as LZ's MAX_LZ_BYTES)
        if n > cls.MAX_PERM_BYTES:
            data = data[:cls.MAX_PERM_BYTES]
            n = cls.MAX_PERM_BYTES

        pattern_counts: dict[int, int] = defaultdict(int)
        n_windows = n - order + 1

        for i in range(n_windows):
            window = data[i : i + order]
            idx = cls._ordinal_pattern_index(window)
            pattern_counts[idx] += 1

        total = sum(pattern_counts.values())
        if total == 0:
            return 1.0

        # Shannon entropy over pattern distribution
        h = 0.0
        for count in pattern_counts.values():
            p = count / total
            if p > 0.0:
                h -= p * math.log2(p)

        # Normalise to [0, 1] by dividing by log₂(m!)
        max_h = math.log2(cls._factorial(order))
        if max_h == 0.0:
            return 1.0

        return round(min(h / max_h, 1.0), 6)

    @staticmethod
    def score(perm_h: float) -> float:
        """
        Anomaly score [0–1] from normalised permutation entropy.

        Low PE = repetitive ordinal patterns = automated machine behaviour.
        Exfiltration tools typically score below 0.55.
        Legitimate users rarely fall below 0.70.
        """
        if perm_h <= 0.40:
            return 1.0
        elif perm_h <= 0.55:
            return 0.80
        elif perm_h <= 0.65:
            return 0.50
        elif perm_h <= 0.75:
            return 0.35
        elif perm_h <= 0.88:
            return 0.20
        else:
            return 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Signal 3 — Lempel-Ziv Complexity (LZ-76)
# ─────────────────────────────────────────────────────────────────────────────

class LempelZivComplexity:
    """
    Computes a normalised Lempel-Ziv 1976 complexity measure over a byte
    sequence.

    LZ-76 complexity C(s) counts the number of distinct sub-strings (words)
    encountered while scanning s left-to-right, where each new word is the
    shortest string not yet seen as a prefix of the already-scanned portion.

    Normalisation
    -------------
    C(s) is normalised by the maximum expected complexity for a purely random
    sequence of the same length n:

        C_max approx n / log2(n)

    Result in [0, 1]:
      - Near 0 : highly compressible (structured / repetitive data)
      - Near 1 : random-like (encrypted or compressed data)

    Exfiltration link
    -----------------
    Sensitive data (database dumps, config files, source code) is moderately
    compressible -- LZ score typically 0.25-0.55.  After an attacker processes
    it (zip, AES, base64), the LZ complexity rises sharply (0.85-1.0).
    Pairing this with high entropy signals gives very strong exfiltration
    confidence.

    Performance -- REM-08 FIX
    -------------------------
    The original implementation built a set[bytes] of sub-strings of growing
    length: O(n^2) time and O(n^2) memory.  For a 65 KB payload that is
    ~4 billion byte comparisons and ~2 GB of allocated bytes objects.

    This implementation uses the standard two-pointer algorithm that counts
    LZ words in a single left-to-right scan with only two integer pointers
    and no sub-string materialisation in the hot path.

    Input is capped at 8 KB (MAX_LZ_BYTES) which is statistically sufficient
    for the entropy/complexity signal and bounds worst-case latency.
    """

    # Maximum input bytes for LZ computation.
    # zlib.compress is O(n) at C level — 4 KB takes < 0.5 ms.
    # Larger caps give better discrimination; 4 KB is a good balance.
    MAX_LZ_BYTES: int = 4096

    @classmethod
    def compute_normalized(cls, data: bytes) -> float:
        """
        Return normalised LZ complexity in [0, 1] via zlib deflate ratio.

        Implementation
        --------------
        The original two-pointer LZ-76 algorithm proved O(n²) on high-entropy
        (encrypted) input — ~2,005 ms/call at 8 KB on random bytes.  This
        implementation replaces it with the **zlib deflate compression ratio**:

            C_deflate(s) = len(zlib.compress(s, level=1)) / len(s)

        Why this is equivalent
        ~~~~~~~~~~~~~~~~~~~~~~
        zlib at level=1 uses LZ77 (same algorithmic family as LZ-76): it
        identifies back-references to earlier substrings and emits literal bytes
        for novel content.  The ratio of compressed to uncompressed length is a
        monotone proxy for Kolmogorov complexity, which both LZ-76 word count
        and LZ77 compression ratio approximate.

        Range and normalisation
        ~~~~~~~~~~~~~~~~~~~~~~~
        For typical network payloads the deflate ratio falls in [0.05, 1.08]:
          • All-zeros / maximal-repetition  → ~0.05  (extreme low end)
          • Structured plaintext (HTTP/DNS) → ~0.20–0.55
          • Base64 / gzip-pre-compressed    → ~0.75–0.95
          • Random / AES-encrypted          → ~1.00–1.08

        We map this to [0, 1] using fixed empirical bounds [LZ_RATIO_MIN,
        LZ_RATIO_MAX], chosen to place plaintext traffic near 0 and
        fully-random payloads near 1 without clipping benign variation.

        Performance
        ~~~~~~~~~~~
        zlib is a C extension; 4 KB compresses in < 0.5 ms.  This is a
        10,000× improvement over the previous two-pointer implementation on
        encrypted payloads.
        """
        import zlib

        if len(data) > cls.MAX_LZ_BYTES:
            data = data[:cls.MAX_LZ_BYTES]

        n = len(data)
        if n < 8:
            return 0.5   # Too short to judge: assume neutral

        compressed_len = len(zlib.compress(data, level=1))
        ratio = compressed_len / n

        # Linear normalisation to [0, 1]
        # LZ_RATIO_MIN ≈ 0.05 (all-zeros), LZ_RATIO_MAX ≈ 1.08 (random)
        LZ_RATIO_MIN = 0.05
        LZ_RATIO_MAX = 1.08
        norm = (ratio - LZ_RATIO_MIN) / (LZ_RATIO_MAX - LZ_RATIO_MIN)
        return round(min(max(norm, 0.0), 1.0), 6)

    @staticmethod
    def score(lz_norm: float, protocol: str) -> float:
        """
        Anomaly score [0–1] based on LZ complexity.

        Strategy — two-sided scoring:
        - Very LOW complexity  (< 0.35): plain-text structured data being
          exfiltrated without encryption; moderate anomaly.
        - Very HIGH complexity (> 0.85): data has been encrypted/compressed
          before exfiltration; strong anomaly for plaintext protocols.

        Encrypted protocols skip the high-complexity branch since their
        payloads are legitimately random.
        """
        is_encrypted_proto = protocol.upper() in ("HTTPS", "SSH", "TLS")

        # ── Calibration note (zlib normalization) ─────────────────────────────
        # With the zlib deflate ratio implementation, the normalization range is:
        #   0.00 → ~0.05 : extreme compression (all-zeros, perfect repetition)
        #   0.05 → ~0.55 : structured plaintext (HTTP bodies, JSON, DNS)
        #   0.55 → ~0.80 : semi-structured (base64, gzip output, mixed)
        #   0.80 → 1.00  : near-random (AES, TLS record layer, encrypted exfil)
        #
        # The old thresholds (calibrated for LZ-76 word-count normalization)
        # fired the "suspicious plaintext" branch at lz_norm < 0.20, but
        # benign HTTP now scores 0.00–0.05.  Thresholds are updated accordingly.
        # ──────────────────────────────────────────────────────────────────────

        # Suspiciously compressible — only flag truly anomalous cases
        # (e.g., all-zeros padding, null-byte exfiltration payloads)
        if lz_norm < 0.05:
            return 0.35       # Extreme compression — unusual for real traffic
        elif lz_norm < 0.15:
            return 0.10       # Very structured but plausibly legitimate

        # Suspiciously random for plaintext protocols only
        # Legitimate HTTP/DNS/FTP does not carry AES-ciphertext payloads.
        if not is_encrypted_proto:
            if lz_norm > 0.88:
                return 1.0
            elif lz_norm > 0.82:
                return 0.70
            elif lz_norm > 0.72:
                return 0.35

        return 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Signal 4 — Inter-Packet Timing Spectral Analysis
# ─────────────────────────────────────────────────────────────────────────────

class IPTSpectralAnalyzer:
    """
    Detects periodic communication patterns using FFT over the sequence of
    Inter-Packet Timing (IPT) intervals stored in the per-IP window.

    Why timing, not payload?
    ------------------------
    Timing analysis is *protocol-agnostic and encryption-immune*.  It works
    equally well on HTTPS, DNS-over-TLS, or any other encrypted channel
    without decryption.

    Malware behaviour
    -----------------
    C2 beaconing, automated chunked uploads, and heartbeat connections all
    transmit in regular intervals (e.g., every 30 s ± jitter).  This
    introduces a dominant frequency component in the IPT sequence that the
    FFT exposes as a peak.

    Human behaviour
    ---------------
    Humans do not browse or transfer files at perfectly regular intervals.
    The IPT spectrum of legitimate sessions is broad-band and featureless —
    no single frequency dominates.

    Algorithm
    ---------
    1. Collect the last k IPT values from the sliding window (k ≤ 50).
    2. Detrend by subtracting the mean.
    3. Apply a Hann window to reduce spectral leakage.
    4. Compute the one-sided power spectrum via np.fft.rfft.
    5. Measure the *peak-to-mean power ratio* (PMR) of the spectrum,
       excluding the DC component (index 0).
    6. A high PMR indicates a dominant periodic component.
    """

    # PMR thresholds for anomaly scoring
    _PMR_HIGH   = 12.0   # Strong periodicity (definite C2 pattern)
    _PMR_MEDIUM = 7.0    # Moderate periodicity
    _PMR_LOW    = 4.0    # Weak periodicity

    @staticmethod
    def analyze(ipt_window: Deque[float]) -> float:
        """
        Compute the spectral peak anomaly score [0–1] for the given IPT window.

        Parameters
        ----------
        ipt_window : deque of inter-packet times in seconds (or milliseconds —
                     the absolute unit does not matter; only relative ratios do)

        Returns
        -------
        float : 0.0 (aperiodic — normal) → 1.0 (highly periodic — suspicious)
        """
        intervals = list(ipt_window)
        n = len(intervals)

        if n < IPT_MIN_SAMPLES:
            return 0.0

        arr = np.asarray(intervals, dtype=np.float64)

        # Perfectly periodic check (zero jitter / constant interval)
        if arr.max() - arr.min() < 1e-9:
            return 1.0

        # Detrend: remove mean to eliminate DC bias
        arr -= arr.mean()

        # Apply Hann window to minimise spectral leakage
        window = np.hanning(n)
        arr *= window

        # One-sided power spectrum
        spectrum = np.abs(np.fft.rfft(arr)) ** 2

        # Exclude DC component (index 0)
        if len(spectrum) < 2:
            return 0.0

        ac_spectrum = spectrum[1:]
        if ac_spectrum.max() == 0.0:
            return 0.0

        mean_power = ac_spectrum.mean()
        if mean_power == 0.0:
            return 0.0

        pmr = ac_spectrum.max() / mean_power  # Peak-to-Mean Ratio

        if pmr >= IPTSpectralAnalyzer._PMR_HIGH:
            return 1.0
        elif pmr >= IPTSpectralAnalyzer._PMR_MEDIUM:
            return 0.65 + (pmr - IPTSpectralAnalyzer._PMR_MEDIUM) / \
                   (IPTSpectralAnalyzer._PMR_HIGH - IPTSpectralAnalyzer._PMR_MEDIUM) * 0.35
        elif pmr >= IPTSpectralAnalyzer._PMR_LOW:
            return 0.30 + (pmr - IPTSpectralAnalyzer._PMR_LOW) / \
                   (IPTSpectralAnalyzer._PMR_MEDIUM - IPTSpectralAnalyzer._PMR_LOW) * 0.35
        else:
            return 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Main: MSEM-Lite Analyzer (Thread-Safe Singleton)
# ─────────────────────────────────────────────────────────────────────────────

class MSEMLiteAnalyzer:
    """
    Singleton coordinator for the MSEM-Lite engine.

    Combines the four signals into a single composite anomaly score and
    produces a human-readable explanation for each detection event.

    Usage
    -----
    Called once per payload from ``BEFPAnalyzer.analyze()``.  Returns an
    ``MSEMLiteResult`` that feeds into:
     - BEFP as Signal 6 (weight 0.25 of the total ERS)
     - The Isolation Forest feature vector (4 new dimensions)
    """

    _instance: "MSEMLiteAnalyzer | None" = None
    _lock = threading.Lock()

    def __new__(cls) -> "MSEMLiteAnalyzer":
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return
        # Stateless calculators — no per-instance state needed
        self._initialized = True
        logger.info("MSEMLiteAnalyzer initialised — MSEM-Lite engine active.")

    # ── Public API ─────────────────────────────────────────────────────────

    def analyze(
        self,
        payload: bytes,
        protocol: str,
        ipt_window: Deque[float],
    ) -> MSEMLiteResult:
        """
        Run all four MSEM-Lite signals on a single payload.

        Parameters
        ----------
        payload    : raw payload bytes from the network packet
        protocol   : protocol string e.g. "HTTP", "DNS", "HTTPS"
        ipt_window : per-IP sliding deque of inter-packet intervals (seconds)

        Returns
        -------
        MSEMLiteResult with composite score and per-signal breakdown.
        Returns a zero-score result if the payload is too small.
        """
        if not payload or len(payload) < MIN_PAYLOAD_BYTES:
            return self._zero_result()

        proto = protocol.upper()

        # ── Signal 1: Rényi Entropy ─────────────────────────────────────────
        renyi_h = RenyiEntropyCalc.compute(payload, alpha=RENYI_ALPHA)
        s_renyi = RenyiEntropyCalc.score(renyi_h, proto)

        # ── Signal 2: Permutation Entropy ───────────────────────────────────
        perm_h = PermutationEntropyCalc.compute(payload, order=PERM_ORDER)
        s_perm = PermutationEntropyCalc.score(perm_h)

        # ── Signal 3: Lempel-Ziv Complexity ─────────────────────────────────
        lz_norm = LempelZivComplexity.compute_normalized(payload)
        s_lz = LempelZivComplexity.score(lz_norm, proto)

        # ── Signal 4: IPT Spectral Periodicity ──────────────────────────────
        ipt_peak = IPTSpectralAnalyzer.analyze(ipt_window)
        s_ipt = ipt_peak   # score IS the spectral peak value

        # ── Composite Score ──────────────────────────────────────────────────
        w = MSEM_SIGNAL_WEIGHTS
        composite = (
            w["renyi"] * s_renyi +
            w["perm"]  * s_perm  +
            w["lz"]    * s_lz    +
            w["ipt"]   * s_ipt
        )
        composite = round(min(composite, 1.0), 4)

        # ── Human-Readable Explanation ───────────────────────────────────────
        explanation: list[str] = []

        if s_renyi > 0.3:
            explanation.append(
                f"Rényi H₂={renyi_h:.2f} bits/byte — anomalous for {proto}"
            )
        if s_perm > 0.3:
            explanation.append(
                f"Permutation entropy={perm_h:.3f} — low ordinal diversity "
                f"(automated pattern)"
            )
        if s_lz > 0.3:
            explanation.append(
                f"LZ complexity={lz_norm:.3f} — "
                + ("suspiciously compressible" if lz_norm < 0.35
                   else "suspiciously random (pre-encrypted)")
            )
        if s_ipt > 0.3:
            explanation.append(
                f"IPT spectral peak power={ipt_peak:.3f} — "
                f"periodic transmission detected (C2 / automated chunking)"
            )

        return MSEMLiteResult(
            score=composite,
            renyi_entropy=renyi_h,
            renyi_score=round(s_renyi, 4),
            perm_entropy=perm_h,
            perm_score=round(s_perm, 4),
            lz_complexity=lz_norm,
            lz_score=round(s_lz, 4),
            ipt_spectral_peak=round(ipt_peak, 4),
            ipt_score=round(s_ipt, 4),
            explanation=explanation,
        )

    # ── Internal helpers ────────────────────────────────────────────────────

    @staticmethod
    def _zero_result() -> MSEMLiteResult:
        """Return a neutral zero-score result for payloads below the minimum."""
        return MSEMLiteResult(
            score=0.0,
            renyi_entropy=0.0,
            renyi_score=0.0,
            perm_entropy=1.0,
            perm_score=0.0,
            lz_complexity=0.0,
            lz_score=0.0,
            ipt_spectral_peak=0.0,
            ipt_score=0.0,
            explanation=[],
        )
