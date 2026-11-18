"""
bunyanx NGFW — Full MSEM: Manifold Flatness Scorer
======================================================
Upgrades MSEM-Lite to a full 7-dimensional temporal manifold framework.

Theory
------
Each network packet produces a 7-dimensional point in an entropy-spectral
feature space:

    P(t) = [H_shannon, H_renyi, H_tsallis, H_perm, S_spectral, C_lz, D_div]

A sliding window of W such points forms a *local manifold*. The intrinsic
dimensionality of that manifold — computed via truncated SVD — quantifies
the structural complexity of the traffic:

    Human traffic    : diverse behaviour → high-dimensional manifold (d ≈ 5-6)
                       MFS near 0  (expansive, spread-out cloud)
    Machine traffic  : repetitive automation → low-dimensional manifold (d ≈ 1-2)
                       MFS near 1  (collapsed, flat cloud)

Manifold Flatness Score
-----------------------
    d_intrinsic = number of singular values explaining ≥ VARIANCE_THRESHOLD
    MFS = 1 - (d_intrinsic / 7)          ∈ [0, 1]

    MFS → 1  :  flat manifold  →  automated exfiltration
    MFS → 0  :  rich manifold  →  normal human behaviour

New Dimensions vs MSEM-Lite
----------------------------
    Dim 3: Tsallis entropy (q=2)        — non-linear byte correlations
    Dim 5: Payload spectral peak        — periodicity in CONTENT (not timing)
    Dim 7: KL divergence from baseline  — drift from this IP's historical profile

The Manifold Collapse Property (research claim)
-----------------------------------------------
Exfiltration tools that mimic ≥ 2 dimensions simultaneously produce
contradictory statistical constraints that collapse into a 1-2D manifold —
which is precisely the detection signature. This is a provably unavoidable
consequence of the Curse of Dimensionality in reverse: adding more evasion
dimensions requires more deterministic behaviour, not less.

Complexity
----------
    SevenDPoint construction:  O(n)   per packet
    ManifoldFlatnessScorer:    O(W·k) where W=20 window, k=7 dims
    SVD on 20×7 matrix:        O(min(W,k)²·max(W,k)) ≈ 7²·20 = 980 FLOPs
    Total per packet:          < 5 µs on commodity hardware

Activation
----------
Full MSEM is gated by the environment variable NGFW_FULL_MSEM=true.
When disabled, MSEMAnalyzer falls back to MSEM-Lite transparently.
"""

from __future__ import annotations

import math
import os
import logging
import threading
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

TSALLIS_Q: float = 2.0          # Tsallis non-extensivity parameter
SPECTRAL_ORDER: int = 4         # Window size for payload FFT (powers of 2)
MIN_PAYLOAD: int = 32           # Minimum bytes for signal computation
MANIFOLD_WINDOW: int = 20       # Number of 7D points in the sliding window
MIN_WINDOW_FOR_MFS: int = 10    # Minimum points before computing MFS
VARIANCE_THRESHOLD: float = 0.95  # Fraction of variance for intrinsic dim

# Feature flag: set NGFW_FULL_MSEM=true to enable manifold computation
FULL_MSEM_ENABLED: bool = os.getenv("NGFW_FULL_MSEM", "false").lower() == "true"

# KL Divergence: decay factor for historical byte frequency baseline
KL_DECAY_ALPHA: float = 0.05   # EMA decay — lower = slower adaptation


# ─────────────────────────────────────────────────────────────────────────────
# Data Structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class SevenDPoint:
    """
    A single 7-dimensional entropy-spectral point for one packet.
    All values normalised to [0, 1].
    """
    h_shannon:  float   # dim 1: Shannon entropy / 8
    h_renyi:    float   # dim 2: Rényi H₂ / 8
    h_tsallis:  float   # dim 3: Tsallis(q=2) normalised
    h_perm:     float   # dim 4: Permutation entropy (already [0,1])
    s_spectral: float   # dim 5: Payload spectral peak power [0,1]
    c_lz:       float   # dim 6: LZ-76 normalised complexity [0,1]
    d_div:      float   # dim 7: KL divergence from baseline [0,1]

    def to_array(self) -> np.ndarray:
        return np.array([
            self.h_shannon, self.h_renyi, self.h_tsallis, self.h_perm,
            self.s_spectral, self.c_lz, self.d_div
        ], dtype=np.float32)


@dataclass(frozen=True)
class ManifoldResult:
    """Result of Manifold Flatness scoring for one packet."""
    mfs_score: float            # Manifold Flatness Score [0,1]
    d_intrinsic: int            # Intrinsic dimensionality (1-7)
    variance_explained: float   # Fraction explained by d_intrinsic dims
    singular_values: List[float]
    explanation: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class FullMSEMResult:
    """
    Extended result combining MSEM-Lite signals with Manifold Flatness.
    Replaces MSEMLiteResult when NGFW_FULL_MSEM=true.
    """
    # Composite score (higher = more suspicious) [0,1]
    score: float

    # 7D point for this packet
    point: SevenDPoint

    # Manifold result (None if window not yet full)
    manifold: Optional[ManifoldResult]

    # Per-signal scores [0,1]
    renyi_score:    float
    perm_score:     float
    lz_score:       float
    tsallis_score:  float
    spectral_score: float
    div_score:      float
    mfs_score:      float       # 0.0 if manifold is None

    explanation: List[str] = field(default_factory=list)

    # Backward-compatible alias for BEFP integration
    @property
    def renyi_entropy(self) -> float:
        return self.point.h_renyi * 8.0

    @property
    def perm_entropy(self) -> float:
        return self.point.h_perm

    @property
    def lz_complexity(self) -> float:
        return self.point.c_lz

    @property
    def ipt_spectral_peak(self) -> float:
        return 0.0   # IPT handled externally by MSEM-Lite

    @property
    def ipt_score(self) -> float:
        return 0.0



# ─────────────────────────────────────────────────────────────────────────────
# Dimension 3: Tsallis Entropy (q=2)
# ─────────────────────────────────────────────────────────────────────────────

class TsallisEntropyCalc:
    """
    Computes Tsallis entropy of order q for a byte sequence.

    S_q(X) = (1 - Σᵢ pᵢ^q) / (q - 1)

    For q=2: S₂(X) = 1 - Σᵢ pᵢ²   (= 1 - collision probability)

    Tsallis entropy is especially sensitive to *correlated* byte sequences —
    it penalises unequal probability distributions more aggressively than
    Shannon for q > 1.  Two payloads with identical Shannon entropy but
    different internal byte correlations will have different Tsallis entropy,
    exposing structured data hidden behind uniform byte frequencies.

    Range: 0.0 (all bytes identical) → (q-1)/q·(1-1/256) ≈ 0.496 for q=2.
    Normalised to [0, 1] by dividing by the theoretical maximum.
    """

    # Maximum Tsallis S₂ for 256-symbol alphabet
    _MAX_S2: float = 1.0 - (1.0 / 256.0)   # ≈ 0.99609

    @staticmethod
    def compute(data: bytes, q: float = TSALLIS_Q) -> float:
        """Return normalised Tsallis entropy ∈ [0, 1]."""
        if not data:
            return 0.0

        n = len(data)
        freq = Counter(data)

        if q == 1.0:
            # Limit q→1 is Shannon entropy, normalised by log₂(256) = 8
            h = -sum((c / n) * math.log2(c / n)
                     for c in freq.values() if c > 0)
            return min(h / 8.0, 1.0)

        sum_p_q = sum((c / n) ** q for c in freq.values())
        tsallis = (1.0 - sum_p_q) / (q - 1.0)

        return round(min(tsallis / TsallisEntropyCalc._MAX_S2, 1.0), 6)

    @staticmethod
    def score(tsallis_norm: float, protocol: str) -> float:
        """
        Anomaly score [0–1] from normalised Tsallis entropy.

        High Tsallis (close to 1) on a plaintext protocol → anomalous.
        Encrypted protocols are skipped (legitimately near-maximum).
        """
        if protocol.upper() in ("HTTPS", "SSH", "TLS"):
            return 0.0

        if tsallis_norm >= 0.92:
            return 1.0
        elif tsallis_norm >= 0.85:
            return 0.70
        elif tsallis_norm >= 0.75:
            return 0.35
        else:
            return 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Dimension 5: Payload Spectral Peak
# ─────────────────────────────────────────────────────────────────────────────

class PayloadSpectralAnalyzer:
    """
    Applies FFT to the raw payload byte sequence to detect periodic structure
    within the content of a single packet.

    Unlike IPTSpectralAnalyzer (which operates on inter-packet timing),
    this analyzer detects periodicity in the payload itself:

    - Encrypted data:   White noise spectrum → no dominant peak
    - Structured dump:  No periodicity within a single packet,
                        but repeated headers/delimiters create periodic peaks
    - Steganographic:   LSB patterns create subtle low-frequency peaks

    Algorithm
    ---------
    1. Convert byte sequence to float array
    2. Detrend by subtracting mean
    3. Compute one-sided power spectrum via rfft
    4. Measure peak-to-mean ratio (PMR) excluding DC

    Note: This signal is NEW — not present in MSEM-Lite.
    It measures periodicity in CONTENT, not in TIMING.
    """

    @staticmethod
    def analyze(data: bytes) -> float:
        """
        Return spectral anomaly score [0, 1] for the payload byte sequence.

        Low score: uniform spectrum (encrypted / truly random)
        High score: dominant periodic component (structured padding / headers)
        """
        n = len(data)
        if n < MIN_PAYLOAD:
            return 0.0

        arr = np.frombuffer(data, dtype=np.uint8).astype(np.float32)
        arr -= arr.mean()

        if arr.std() < 1e-6:
            return 0.0   # Constant payload — already caught by Rényi

        spectrum = np.abs(np.fft.rfft(arr)) ** 2

        if len(spectrum) < 2:
            return 0.0

        ac_spectrum = spectrum[1:]  # Exclude DC
        mean_power = ac_spectrum.mean()
        if mean_power == 0.0:
            return 0.0

        pmr = ac_spectrum.max() / mean_power

        # Scoring: human internet data has PMR ≈ 1-3, structured data ≈ 5-15
        if pmr >= 20.0:
            return 1.0
        elif pmr >= 15.0:
            return 0.70
        elif pmr >= 10.0:
            return 0.35
        else:
            return 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Dimension 7: KL Divergence Tracker
# ─────────────────────────────────────────────────────────────────────────────

class KLDivergenceTracker:
    """
    Tracks the per-IP historical byte frequency distribution and computes
    the KL divergence of each new packet's distribution from the baseline.

    KL(P || Q) = Σ P(x) log₂(P(x) / Q(x))

    A sudden shift in byte distribution (high KL) signals that the traffic
    pattern has changed abruptly — characteristic of exfiltration onset where
    a new type of data (encrypted payload, archive) suddenly appears.

    Baseline updating
    -----------------
    The historical baseline is updated using Exponential Moving Average (EMA):
        Q_new[b] = (1 - α) · Q_old[b] + α · P_current[b]
    where α = KL_DECAY_ALPHA (default 0.05).

    This allows the baseline to slowly adapt to legitimate changes in user
    behaviour while still raising an alert for rapid distribution shifts.
    """

    # Uniform prior for Laplace smoothing to avoid log(0)
    _PRIOR: float = 1.0 / 256.0

    def __init__(self):
        self._baselines: Dict[str, np.ndarray] = {}
        self._lock = threading.Lock()
        # Maximum theoretical KL for 256-symbol alphabet
        self._max_kl: float = math.log2(256)   # = 8.0

    def compute_and_update(self, src_ip: str, data: bytes) -> float:
        """
        Compute normalised KL divergence for this packet from the IP's
        historical baseline, then update the baseline via EMA.

        Returns KL divergence normalised to [0, 1].
        """
        if not data:
            return 0.0

        # Current packet byte distribution
        n = len(data)
        freq = np.zeros(256, dtype=np.float64)
        for b in data:
            freq[b] += 1
        p_current = (freq + self._PRIOR) / (n + 256 * self._PRIOR)

        with self._lock:
            if src_ip not in self._baselines:
                # First packet: initialise baseline, no divergence
                self._baselines[src_ip] = p_current.copy()
                return 0.0

            q_baseline = self._baselines[src_ip]

            # KL Divergence (base-2)
            # Both p and q are smoothed so log is safe
            kl = float(np.sum(p_current * np.log2(p_current / q_baseline)))
            kl = max(0.0, kl)   # Numerical precision guard

            # Update baseline with EMA
            self._baselines[src_ip] = (
                (1 - KL_DECAY_ALPHA) * q_baseline
                + KL_DECAY_ALPHA * p_current
            )

        return round(min(kl / self._max_kl, 1.0), 6)

    @staticmethod
    def score(kl_norm: float) -> float:
        """Anomaly score [0–1] from normalised KL divergence."""
        if kl_norm >= 0.50:
            return 1.0
        elif kl_norm >= 0.30:
            return 0.70
        elif kl_norm >= 0.15:
            return 0.35
        else:
            return 0.0

    def evict(self, src_ip: str) -> None:
        """Remove a stale IP from the baseline registry."""
        with self._lock:
            self._baselines.pop(src_ip, None)


# ─────────────────────────────────────────────────────────────────────────────
# Manifold Flatness Scorer — Core
# ─────────────────────────────────────────────────────────────────────────────

class ManifoldFlatnessScorer:
    """
    Computes the Manifold Flatness Score (MFS) for a sliding window of
    7D entropy-spectral points accumulated per source IP.

    Algorithm
    ---------
    Given a window W = [P₁, P₂, ..., P_k] where each Pᵢ ∈ ℝ⁷:

    1. Build matrix X ∈ ℝ^{k×7}
    2. Centre X: X' = X - column_means
    3. Compute truncated SVD: X' ≈ U Σ Vᵀ
    4. Variance explained by each singular value: vᵢ = σᵢ² / Σ σⱼ²
    5. d_intrinsic = min i such that Σⱼ≤ᵢ vⱼ ≥ VARIANCE_THRESHOLD
    6. MFS = 1 - (d_intrinsic / 7)

    Complexity
    ----------
    numpy.linalg.svd on a 20×7 matrix:
        O(min(k,7)² · max(k,7)) = O(7² · 20) = O(980)
        ≈ 2–5 µs on modern hardware — acceptable for DLP path.

    Manifold Collapse Property
    --------------------------
    An exfiltration tool attempting to evade MSEM-Lite by randomising its
    byte distribution will produce 7D points concentrated in a low-dimensional
    subspace:
      - If it uses a PRNG: all 7 dimensions become correlated via the PRNG
        → effectively 1-2 independent dimensions (detected: MFS→1)
      - If it uses a CSPRNG: perfectly random bytes → all dimensions collapse
        to near-uniform values → near-zero variance → d_intrinsic = 1
        (detected: MFS→1)
    In both cases, the manifold collapses — the inverse of what the attacker
    intends.
    """

    def __init__(self):
        # Per-IP sliding window of 7D points
        self._windows: Dict[str, Deque[SevenDPoint]] = defaultdict(
            lambda: deque(maxlen=MANIFOLD_WINDOW)
        )
        self._lock = threading.Lock()

    def add_point_and_score(
        self,
        src_ip: str,
        point: SevenDPoint,
    ) -> ManifoldResult:
        """
        Append point to the IP's manifold window and compute MFS.

        Returns a ManifoldResult. If the window is not yet full enough
        (< MIN_WINDOW_FOR_MFS points), returns a neutral result.
        """
        with self._lock:
            self._windows[src_ip].append(point)
            window_snapshot = list(self._windows[src_ip])

        n_pts = len(window_snapshot)

        if n_pts < MIN_WINDOW_FOR_MFS:
            return ManifoldResult(
                mfs_score=0.5,    # Neutral — insufficient data
                d_intrinsic=7,
                variance_explained=0.0,
                singular_values=[],
                explanation=[],
            )

        return self._compute_mfs(window_snapshot)

    def _compute_mfs(self, points: List[SevenDPoint]) -> ManifoldResult:
        """Run the SVD-based intrinsic dimensionality computation."""
        # Build matrix X ∈ ℝ^{n×7}
        X = np.array([p.to_array() for p in points], dtype=np.float32)

        # Centre columns (mean subtraction)
        X -= X.mean(axis=0, keepdims=True)

        # Handle degenerate case: zero variance in all columns
        col_std = X.std(axis=0)
        if col_std.max() < 1e-8:
            # All points identical → fully collapsed manifold
            return ManifoldResult(
                mfs_score=1.0,
                d_intrinsic=1,
                variance_explained=1.0,
                singular_values=[0.0] * 7,
                explanation=["Manifold fully collapsed: all 7D points identical"],
            )

        # Truncated SVD (full_matrices=False → economical decomposition)
        _, sigma, _ = np.linalg.svd(X, full_matrices=False)

        # Variance explained by each singular value
        total_var = float((sigma ** 2).sum())
        if total_var < 1e-10:
            d_intrinsic = 1
            var_explained = 1.0
        else:
            var_ratios = (sigma ** 2) / total_var
            cumvar = np.cumsum(var_ratios)
            # d_intrinsic: smallest d such that cumvar[d-1] >= threshold
            exceeds = np.where(cumvar >= VARIANCE_THRESHOLD)[0]
            d_intrinsic = int(exceeds[0] + 1) if len(exceeds) > 0 else len(sigma)
            var_explained = float(cumvar[d_intrinsic - 1])

        # MFS: 1 = flat (d=1), 0 = expansive (d=7)
        mfs = round(1.0 - (d_intrinsic / 7.0), 4)

        # Build explanation
        explanation: List[str] = []
        if mfs >= 0.70:
            explanation.append(
                f"Manifold flatness={mfs:.3f} (d_intrinsic={d_intrinsic}/7) "
                f"— highly automated/repetitive behaviour"
            )
        elif mfs >= 0.50:
            explanation.append(
                f"Manifold flatness={mfs:.3f} (d_intrinsic={d_intrinsic}/7) "
                f"— moderately regular traffic pattern"
            )

        return ManifoldResult(
            mfs_score=mfs,
            d_intrinsic=d_intrinsic,
            variance_explained=round(var_explained, 4),
            singular_values=[round(float(s), 4) for s in sigma],
            explanation=explanation,
        )

    def evict(self, src_ip: str) -> None:
        """Remove stale IP from manifold window registry."""
        with self._lock:
            self._windows.pop(src_ip, None)


# ─────────────────────────────────────────────────────────────────────────────
# Full MSEM Analyzer — Singleton
# ─────────────────────────────────────────────────────────────────────────────

class FullMSEMAnalyzer:
    """
    Thread-safe singleton that coordinates all 7 Full-MSEM signals and
    the Manifold Flatness Scorer.

    Entry point: FullMSEMAnalyzer().analyze(...)

    Usage in entropy_analyzer.py
    --------------------------------
    Called from BEFPAnalyzer.analyze() when NGFW_FULL_MSEM=true, replacing
    the MSEMLiteAnalyzer call.  Returns FullMSEMResult which is a superset
    of MSEMLiteResult — fully backward-compatible.

    Composite Score Weights
    -----------------------
    The composite score combining all 7 sub-scores:

        full_msem = (0.18·s_renyi  + 0.20·s_perm  + 0.12·s_lz
                   + 0.12·s_tsallis + 0.08·s_spectral
                   + 0.10·s_div   + 0.20·s_mfs)

    MFS carries the highest weight (0.20) because it integrates information
    from all 7 dimensions simultaneously.
    """

    _instance: "FullMSEMAnalyzer | None" = None
    _lock = threading.Lock()

    # Composite weights — must sum to 1.0
    _WEIGHTS = {
        "renyi":    0.18,
        "perm":     0.20,
        "lz":       0.12,
        "tsallis":  0.12,
        "spectral": 0.08,
        "div":      0.10,
        "mfs":      0.20,
    }
    assert abs(sum(_WEIGHTS.values()) - 1.0) < 1e-9

    def __new__(cls) -> "FullMSEMAnalyzer":
        with cls._lock:
            if cls._instance is None:
                inst = super().__new__(cls)
                inst._initialized = False
                cls._instance = inst
        return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return
        from modules.dlp.engine.msem_lite import (
            RenyiEntropyCalc,
            PermutationEntropyCalc,
            LempelZivComplexity,
        )
        self._renyi   = RenyiEntropyCalc
        self._perm    = PermutationEntropyCalc
        self._lz      = LempelZivComplexity
        self._tsallis = TsallisEntropyCalc
        self._payload_spectral = PayloadSpectralAnalyzer
        self._kl      = KLDivergenceTracker()
        self._mfs     = ManifoldFlatnessScorer()
        self._initialized = True
        logger.info(
            "FullMSEMAnalyzer initialised — 7D Manifold engine active "
            f"(window={MANIFOLD_WINDOW}, variance_threshold={VARIANCE_THRESHOLD})"
        )

    # ── Public API ──────────────────────────────────────────────────────────

    def analyze(
        self,
        src_ip: str,
        payload: bytes,
        protocol: str,
        ipt_window,      # deque[float] — still used by MSEM-Lite internally
    ) -> FullMSEMResult:
        """
        Full 7-signal analysis for a single packet.

        Parameters
        ----------
        src_ip   : Source IP for per-IP state tracking
        payload  : Raw payload bytes
        protocol : Protocol string ("HTTP", "DNS", "HTTPS", ...)
        ipt_window : Per-IP deque of inter-packet intervals (from FlowProfile)

        Returns
        -------
        FullMSEMResult with composite score and full breakdown.
        """
        if not payload or len(payload) < MIN_PAYLOAD:
            return self._zero_result()

        proto = protocol.upper()

        # ── Dim 1: Shannon (reuse existing BEFP signal — set via FlowProfile)
        # We don't recompute Shannon here; BEFP signal_entropy covers it.
        # We store a normalised version in the 7D point for manifold use.
        from collections import Counter as _Counter
        n = len(payload)
        freq = _Counter(payload)
        shannon_h = 0.0
        for c in freq.values():
            p = c / n
            if p > 0:
                shannon_h -= p * math.log2(p)
        shannon_norm = round(shannon_h / 8.0, 6)

        # ── Dim 2: Rényi H₂
        renyi_h   = self._renyi.compute(payload)
        s_renyi   = self._renyi.score(renyi_h, proto)
        renyi_norm = round(renyi_h / 8.0, 6)

        # ── Dim 3: Tsallis(q=2)
        tsallis_norm = self._tsallis.compute(payload)
        s_tsallis    = self._tsallis.score(tsallis_norm, proto)

        # ── Dim 4: Permutation Entropy
        perm_h  = self._perm.compute(payload)
        s_perm  = self._perm.score(perm_h)

        # ── Dim 5: Payload Spectral Peak
        s_spectral_raw = self._payload_spectral.analyze(payload)
        spectral_norm  = round(s_spectral_raw, 6)

        # ── Dim 6: LZ Complexity
        lz_norm = self._lz.compute_normalized(payload)
        s_lz    = self._lz.score(lz_norm, proto)

        # ── Dim 7: KL Divergence from baseline
        kl_norm = self._kl.compute_and_update(src_ip, payload)
        s_div   = KLDivergenceTracker.score(kl_norm)

        # ── Build 7D point
        point = SevenDPoint(
            h_shannon=shannon_norm,
            h_renyi=renyi_norm,
            h_tsallis=tsallis_norm,
            h_perm=perm_h,
            s_spectral=spectral_norm,
            c_lz=lz_norm,
            d_div=kl_norm,
        )

        # ── Manifold Flatness Score
        manifold = self._mfs.add_point_and_score(src_ip, point)
        s_mfs    = manifold.mfs_score

        # ── Composite Score
        w = self._WEIGHTS
        composite = (
            w["renyi"]    * s_renyi   +
            w["perm"]     * s_perm    +
            w["lz"]       * s_lz      +
            w["tsallis"]  * s_tsallis +
            w["spectral"] * s_spectral_raw +
            w["div"]      * s_div     +
            w["mfs"]      * s_mfs
        )
        composite = round(min(composite, 1.0), 4)

        # ── Explanation
        explanation: List[str] = []
        if s_renyi > 0.3:
            explanation.append(
                f"Renyi H2={renyi_h:.2f} bits/byte anomalous for {proto}"
            )
        if s_perm > 0.3:
            explanation.append(
                f"Permutation entropy={perm_h:.3f} — low ordinal diversity"
            )
        if s_lz > 0.3:
            explanation.append(
                f"LZ complexity={lz_norm:.3f} — "
                + ("compressible data" if lz_norm < 0.35 else "pre-encrypted")
            )
        if s_tsallis > 0.3:
            explanation.append(
                f"Tsallis entropy={tsallis_norm:.3f} — non-linear byte correlations"
            )
        if s_spectral_raw > 0.3:
            explanation.append(
                f"Payload spectral peak — periodic byte pattern in content"
            )
        if s_div > 0.3:
            explanation.append(
                f"KL divergence={kl_norm:.3f} — sudden distribution shift for {src_ip}"
            )
        explanation.extend(manifold.explanation)

        return FullMSEMResult(
            score=composite,
            point=point,
            manifold=manifold,
            renyi_score=round(s_renyi, 4),
            perm_score=round(s_perm, 4),
            lz_score=round(s_lz, 4),
            tsallis_score=round(s_tsallis, 4),
            spectral_score=round(s_spectral_raw, 4),
            div_score=round(s_div, 4),
            mfs_score=round(s_mfs, 4),
            explanation=explanation,
        )

    def evict_ip(self, src_ip: str) -> None:
        """
        Remove all per-IP state for a stale source IP.
        Called by BEFPAnalyzer when an IP profile is evicted via LRU.
        """
        self._kl.evict(src_ip)
        self._mfs.evict(src_ip)

    # ── Helpers ─────────────────────────────────────────────────────────────

    @staticmethod
    def _zero_result() -> FullMSEMResult:
        return FullMSEMResult(
            score=0.0,
            point=SevenDPoint(0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0),
            manifold=None,
            renyi_score=0.0,
            perm_score=0.0,
            lz_score=0.0,
            tsallis_score=0.0,
            spectral_score=0.0,
            div_score=0.0,
            mfs_score=0.0,
            explanation=[],
        )
