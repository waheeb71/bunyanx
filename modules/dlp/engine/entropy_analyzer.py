"""
bunyanx NGFW — Behavioral Entropy Flow Profiler (BEFP)
==========================================================
Novel Research Feature: بدلاً من فحص المحتوى، نحلل سلوك تدفق البيانات.

6 إشارات تُجمع في نقطة خطر واحدة → Exfiltration Risk Score (ERS)

Signal 1 — Shannon Entropy           : هل البيانات مشفرة/مضغوطة بشكل مشبوه؟
Signal 2 — Temporal Velocity         : هل معدل الإرسال يتجاوز baseline الشخصي؟
Signal 3 — Data Chunking Pattern     : هل الملف مجزأ لتجنب الكشف؟
Signal 4 — Protocol Entropy Deviation: هل البروتوكول يحمل بيانات خارج نطاقه الطبيعي؟
Signal 5 — Cross-Session Accumulation: هل هناك تسريب تراكمي بطيء عبر الجلسات؟
Signal 6 — MSEM-Lite                 : Rényi + Permutation Entropy + LZ Complexity
                                       + IPT Spectral Periodicity
                                       (يكشف الحتمية الآلية وأنماط C2 الدورية)
"""

import math
import time
import json
import os
import threading
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Deque, Optional, Tuple, List

from modules.dlp.engine.msem_lite import MSEMLiteAnalyzer, MSEMLiteResult, IPT_WINDOW_SIZE
from modules.dlp.engine.weight_optimizer import load_weights_from_config

# Full MSEM: activated via environment variable NGFW_FULL_MSEM=true
try:
    from modules.dlp.engine.manifold_scorer import FullMSEMAnalyzer, FullMSEMResult, FULL_MSEM_ENABLED
    _FULL_MSEM_AVAILABLE = True
except ImportError:
    _FULL_MSEM_AVAILABLE = False
    FULL_MSEM_ENABLED = False

logger = logging.getLogger(__name__)

if FULL_MSEM_ENABLED and _FULL_MSEM_AVAILABLE:
    logger.info("[NGFW_FULL_MSEM=true] Full MSEM (7D Manifold) mode activated.")
else:
    logger.info("[NGFW_FULL_MSEM=false] MSEM-Lite (4-signal) mode active.")


# ─────────────────────────────────────────────────────────────────────────────
# SIGNAL CONFIG
# ─────────────────────────────────────────────────────────────────────────────

# Entropy range (bits per byte) considered "normal" per protocol
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

# ERS weights — must sum to 1.0
# Note: these are initial values; run weight_optimizer.py (Grid Search)
# after collecting >= 200 labeled samples to derive empirically optimal weights.
ERS_WEIGHTS = {
    "entropy":      0.22,
    "velocity":     0.18,
    "chunking":     0.10,
    "protocol":     0.15,
    "accumulation": 0.10,
    "msem":         0.25,   # Signal 6 — MSEM-Lite
}

# Override defaults with Grid-Search-optimised weights if config file exists
_optimised = load_weights_from_config()
if _optimised:
    ERS_WEIGHTS = _optimised

# Velocity window durations in seconds
VELOCITY_WINDOWS = [30, 300, 3600]  # 30s, 5min, 1hr

# Chunk detection: keeps last N packet sizes per IP
CHUNK_WINDOW_SIZE = 20

# Accumulation tracking window (24 hours)
ACCUMULATION_WINDOW_SEC = 86400

# Min payload bytes to run entropy analysis (avoid noise from tiny packets)
MIN_PAYLOAD_BYTES = 32

# ERS thresholds → decision
# REM-09 FIX: Unified thresholds across all files.
# Previously entropy_analyzer used 0.35/0.60/0.80 while intelligence_layer
# used 0.40/0.70/0.80 — now all code references this single source of truth.
ERS_THRESHOLDS = {
    "NORMAL":       0.35,   # < 0.35 → NORMAL
    "SUSPICIOUS":   0.60,   # 0.35–0.60 → SUSPICIOUS
    "HIGH_RISK":    0.80,   # 0.60–0.80 → HIGH_RISK
    "EXFILTRATION": 1.01,   # ≥ 0.80 → EXFILTRATION (sentinel)
}

from dataclasses import dataclass
from typing import Optional, List
from modules.dlp.engine.msem_lite import MSEMLiteResult
from modules.dlp.engine.storage.profile_store import FlowProfile

@dataclass
class BEFPResult:
    """Full result from a BEFP analysis pass."""
    src_ip: str
    ers: float                            # Exfiltration Risk Score 0.0–1.0
    signal_entropy: float
    signal_velocity: float
    signal_chunking: float
    signal_protocol: float
    signal_accumulation: float
    signal_msem: float                    # Signal 6 — MSEM-Lite composite
    msem_detail: Optional[MSEMLiteResult] # Full MSEM-Lite breakdown
    protocol: str
    payload_entropy: float
    decision: str                         # NORMAL / SUSPICIOUS / HIGH_RISK / EXFILTRATION
    explanation: List[str]                # Human-readable breakdown

    def to_finding_dict(self) -> dict:
        return {
            "rule_name": f"BEHAV_ENTROPY_EXFIL_{self.decision}",
            "severity": {
                "NORMAL": "LOW",
                "SUSPICIOUS": "MEDIUM",
                "HIGH_RISK": "HIGH",
                "EXFILTRATION": "CRITICAL",
            }.get(self.decision, "MEDIUM"),
            "description": (
                f"BEFP ERS={self.ers:.3f} [{self.decision}] on {self.src_ip} "
                f"via {self.protocol}. " + " | ".join(self.explanation)
            ),
            "match_count": 1,
            "metadata": {
                "ers": self.ers,
                "signals": {
                    "entropy": self.signal_entropy,
                    "velocity": self.signal_velocity,
                    "chunking": self.signal_chunking,
                    "protocol_deviation": self.signal_protocol,
                    "accumulation": self.signal_accumulation,
                    "msem": self.signal_msem,
                },
                "msem_detail": {
                    "renyi_entropy":    self.msem_detail.renyi_entropy    if self.msem_detail else 0.0,
                    "renyi_score":      self.msem_detail.renyi_score      if self.msem_detail else 0.0,
                    "perm_entropy":     self.msem_detail.perm_entropy     if self.msem_detail else 0.0,
                    "perm_score":       self.msem_detail.perm_score       if self.msem_detail else 0.0,
                    "lz_complexity":    self.msem_detail.lz_complexity    if self.msem_detail else 0.0,
                    "lz_score":         self.msem_detail.lz_score         if self.msem_detail else 0.0,
                    "ipt_spectral_peak":self.msem_detail.ipt_spectral_peak if self.msem_detail else 0.0,
                    "ipt_score":        self.msem_detail.ipt_score        if self.msem_detail else 0.0,
                } if self.msem_detail else {},
                "payload_entropy_bits": self.payload_entropy,
                "protocol": self.protocol,
            }
        }



from modules.dlp.engine.signals import (
    ShannonEntropyCalc,
    VelocityAnalyzer,
    ChunkPatternDetector,
    ProtocolBaselineRegistry,
    AccumulationTracker,
)



# ─────────────────────────────────────────────────────────────────────────────
# MAIN: BEFP Analyzer (Thread-Safe Singleton)
# ─────────────────────────────────────────────────────────────────────────────

from modules.dlp.engine.storage.profile_store import ProfileStore, FlowProfile

# ─────────────────────────────────────────────────────────────────────────────
# MAIN: BEFP Analyzer (Thread-Safe Singleton)
# ─────────────────────────────────────────────────────────────────────────────

class BEFPAnalyzer:
    """
    Core Behavioral Entropy Flow Profiler.
    Thread-safe singleton with LRU-like eviction to prevent memory leaks.
    Integrates all 5 signals into a single Exfiltration Risk Score (ERS).
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
            
        self.profile_store = ProfileStore()
        
        # Signal 6 engine — Full MSEM or Lite depending on feature flag
        if FULL_MSEM_ENABLED and _FULL_MSEM_AVAILABLE:
            self._msem = FullMSEMAnalyzer()
            self._full_msem = True
            logger.info("BEFPAnalyzer: using FullMSEMAnalyzer (7D manifold).")
        else:
            self._msem = MSEMLiteAnalyzer()
            self._full_msem = False
            logger.info("BEFPAnalyzer: using MSEMLiteAnalyzer (4-signal Lite).")
        self._initialized = True
        logger.info(
            "BEFPAnalyzer initialized — Behavioral Entropy Flow Profiler active "
            "(6 signals including MSEM-Lite)."
        )

    def analyze(
        self,
        src_ip: str,
        dst_ip: str,
        payload: bytes,
        protocol: str = "TCP",
        dst_port: int = 0,
    ) -> Optional[BEFPResult]:
        """
        Run full BEFP analysis on a single payload.
        Returns BEFPResult if payload is large enough to analyze, else None.
        """
        if not payload or len(payload) < MIN_PAYLOAD_BYTES:
            return None

        try:
            profile = self.profile_store.get_or_create(src_ip)
            payload_len = len(payload)
            proto_upper = (protocol or "TCP").upper()

            # ── Signal 1: Shannon Entropy ──────────────────────────────────
            raw_entropy = ShannonEntropyCalc.compute(payload)
            s_entropy = ShannonEntropyCalc.score(raw_entropy, proto_upper)

            # ── Signal 2: Temporal Velocity ────────────────────────────────
            s_velocity = VelocityAnalyzer.score(profile, payload_len)

            # ── Signal 3: Chunk Pattern Detection ─────────────────────────
            s_chunking = ChunkPatternDetector.score(profile.recent_sizes, payload_len)

            # ── Signal 4: Protocol Entropy Deviation ───────────────────────
            s_protocol = ProtocolBaselineRegistry.deviation_score(raw_entropy, proto_upper)

            # ── Signal 5: Cross-Session Accumulation ───────────────────────
            s_accumulation = AccumulationTracker.score(profile, dst_ip, payload_len)

            # ── Signal 6: MSEM (Lite or Full) ─────────────────────────────────
            now = time.time()
            if profile.last_packet_time > 0.0:
                ipt = now - profile.last_packet_time
                profile.ipt_window.append(ipt)
            profile.last_packet_time = now

            if self._full_msem:
                # Full MSEM: 7D manifold + MFS
                msem_result = self._msem.analyze(
                    src_ip=src_ip,
                    payload=payload,
                    protocol=proto_upper,
                    ipt_window=profile.ipt_window,
                )
            else:
                # MSEM-Lite: 4-signal composite
                msem_result = self._msem.analyze(
                    payload=payload,
                    protocol=proto_upper,
                    ipt_window=profile.ipt_window,
                )
            s_msem = msem_result.score

            # ── ERS Composite Score ────────────────────────────────────────
            w = ERS_WEIGHTS
            ers = (
                w["entropy"]      * s_entropy +
                w["velocity"]     * s_velocity +
                w["chunking"]     * s_chunking +
                w["protocol"]     * s_protocol +
                w["accumulation"] * s_accumulation +
                w["msem"]         * s_msem
            )
            ers = round(min(ers, 1.0), 4)

            # ── Decision ─────────────────────────────────────────────
            # REM-09: Use unified ERS_THRESHOLDS constants
            if ers >= ERS_THRESHOLDS["HIGH_RISK"]:
                decision = "EXFILTRATION"
            elif ers >= ERS_THRESHOLDS["SUSPICIOUS"]:
                decision = "HIGH_RISK"
            elif ers >= ERS_THRESHOLDS["NORMAL"]:
                decision = "SUSPICIOUS"
            else:
                decision = "NORMAL"

            # ── Human-readable explanation ─────────────────────────────────
            explanation = []
            if s_entropy > 0.3:
                explanation.append(f"High payload entropy ({raw_entropy:.2f} bits/byte)")
            if s_velocity > 0.3:
                explanation.append(f"Velocity spike ({s_velocity:.2f}) vs. personal baseline")
            if s_chunking > 0.3:
                explanation.append(f"Systematic chunk pattern detected (CV low)")
            if s_protocol > 0.3:
                explanation.append(f"Protocol {proto_upper} entropy anomaly (deviation={s_protocol:.2f})")
            if s_accumulation > 0.3:
                accu = profile.accumulation.get(dst_ip, 0) / (1024 * 1024)
                explanation.append(f"Cumulative transfer to {dst_ip}: {accu:.1f} MB in 24h")
            if s_msem > 0.3:
                explanation.extend(msem_result.explanation)
            if not explanation:
                explanation.append("All signals within normal range")

            return BEFPResult(
                src_ip=src_ip,
                ers=ers,
                signal_entropy=round(s_entropy, 4),
                signal_velocity=round(s_velocity, 4),
                signal_chunking=round(s_chunking, 4),
                signal_protocol=round(s_protocol, 4),
                signal_accumulation=round(s_accumulation, 4),
                signal_msem=round(s_msem, 4),
                msem_detail=msem_result,
                protocol=proto_upper,
                payload_entropy=raw_entropy,
                decision=decision,
                explanation=explanation,
            )

        except Exception as e:
            logger.error(f"BEFP analysis failed for {src_ip}: {e}", exc_info=True)
            return None

    def get_profile_summary(self, src_ip: str) -> Optional[dict]:
        """API-facing: returns a summary of the behavioral profile for an IP."""
        profile = self.profile_store.get(src_ip)
        if not profile:
            return None
        return {
            "src_ip": src_ip,
            "baseline_velocity_bps": round(profile.baseline_velocity_bps, 2),
            "baseline_samples": profile.baseline_samples,
            "last_seen": profile.last_seen,
            "active_flows": len(profile.accumulation),
            "accumulation_24h_bytes": {
                dst: round(b, 0)
                for dst, b in profile.accumulation.items()
            },
            "recent_chunk_sizes": list(profile.recent_sizes)[-10:],
        }

    def get_all_high_risk_profiles(self) -> List[dict]:
        """Returns IPs with abnormally high accumulation scores."""
        results = []
        for src_ip, profile in self.profile_store.iter_profiles():
            total = sum(profile.accumulation.values())
            if total >= AccumulationTracker.WARN_THRESHOLD_BYTES:
                results.append({
                    "src_ip": src_ip,
                    "total_bytes_24h": total,
                    "destinations": len(profile.accumulation),
                    "baseline_velocity_bps": round(profile.baseline_velocity_bps, 2),
                })
        return sorted(results, key=lambda x: x["total_bytes_24h"], reverse=True)

    # ───────────────────────────────────────────────────────────────────────
    # REM-06: BEFP Profile Persistence
    # ───────────────────────────────────────────────────────────────────────

    def save_snapshot(self) -> None:
        self.profile_store.save_snapshot()

    def restore_snapshot(self) -> None:
        self.profile_store.restore_snapshot()

    def start_periodic_snapshot(self) -> None:
        self.profile_store.start_periodic_snapshot()
