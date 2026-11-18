"""
Anomaly Detector Module
=======================
ML-based anomaly detection combining:
  - Statistical flow features (21 dimensions)
  - PHANTOM Layer 1: Spectral Byte Encoder (SBE, 256-dim)
  - JA3 TLS fingerprint analysis
  - L3 Isolation Forest / XGBoost anomaly scoring
  - L7 DPI multi-class classification
  - UBA Zero-Trust dynamic threshold adjustment

New in PHANTOM Sprint 1
-----------------------
  TrafficFeatures.raw_payload   — raw packet bytes (optional)
  TrafficFeatures.payload_sbe   — pre-computed SBE vector (optional)
  AnomalyResult.details["sbe_score"]  — spectral anomaly contribution
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
import logging
import os
import importlib

import numpy as np

logger = logging.getLogger(__name__)

@dataclass
class TrafficFeatures:
    """Features extracted from traffic for analysis (21 features)"""
    # --- Original 14 features ---
    packets_per_second: float
    bytes_per_second: float
    avg_packet_size: float
    packet_size_variance: float
    tcp_ratio: float
    udp_ratio: float
    syn_ratio: float
    unique_dst_ports: int
    unique_src_ports: int
    inter_arrival_time_mean: float
    inter_arrival_time_variance: float
    failed_connections: int
    connection_attempts: int
    reputation_score: float
    # --- 7 new features (added based on CICIDS2017 / research gaps) ---
    flow_duration: float = 0.0           # seconds; detects Slowloris/slow attacks
    payload_entropy: float = 0.5         # Shannon entropy [0-1]; detects encrypted exfil/malware
    upload_download_ratio: float = 1.0   # bytes_sent/bytes_recv; detects exfiltration
    fin_rst_ratio: float = 0.0           # (FIN+RST)/total pkts; detects failed/reset connections
    max_packet_size: int = 0             # largest packet in flow; detects fragmentation/tunneling
    small_packet_ratio: float = 0.0      # pkts<100B / total; detects C2 beaconing
    ack_ratio: float = 0.0               # ACK/total pkts; important for TCP handshake analysis
    # --- JA3 Encrypted Traffic Analysis ---
    tls_ja3_fingerprint: Optional[str] = None  # For matching against known bad JA3 hashes
    # --- PHANTOM Layer 1 : Spectral Byte Encoder ---
    raw_payload: Optional[bytes] = None
    """Raw bytes of the most recent packet in this flow.
    When set, the AnomalyDetector automatically computes the SBE vector
    and uses it to augment the anomaly score — no manual pre-processing
    required by the caller.
    """
    payload_sbe: Optional["np.ndarray"] = field(default=None, repr=False)
    """Pre-computed 256-dim SBE vector.  If supplied, raw_payload is ignored.
    Use this when the caller has already computed SBE (e.g. CDTGB pipeline).
    """

@dataclass
class AnomalyResult:
    """Result of anomaly detection"""
    is_anomaly: bool
    anomaly_score: float
    confidence: float
    details: Dict[str, float]

class AnomalyDetector:
    """
    ML-based Anomaly Detector
    """
    
    def __init__(self, contamination: float = 0.1, model_path: Optional[str] = None, l7_model_path: Optional[str] = None):
        self.contamination = contamination
        self.model = None
        self.model_type = None
        self.l7_model = None
        self.l7_model_type = None
        self.scaler = None # Scaler for L3 model
        self.l7_scaler = None # Scaler for L7 model
        self.anomalies_detected = 0
        logger.info(f"AnomalyDetector initialized with contamination={contamination}")
        
        if model_path and os.path.exists(model_path):
            self.load_model(model_path, is_l7=False)
            scaler_path = os.path.join(os.path.dirname(model_path), "l3_anomaly_scaler.pkl")
            if os.path.exists(scaler_path):
                self.scaler = self._load_scaler(scaler_path)
            
        if l7_model_path and os.path.exists(l7_model_path):
            self.load_model(l7_model_path, is_l7=True)
            l7_scaler_path = os.path.join(os.path.dirname(l7_model_path), "l7_dpi_scaler.pkl")
            if os.path.exists(l7_scaler_path):
                self.l7_scaler = self._load_scaler(l7_scaler_path)

    def _verify_file_integrity(self, path: str) -> bool:
        """
        Verify model/scaler file SHA-256 against a co-located .sha256 sidecar.
        Permissive when no sidecar exists (warns only).
        """
        import hashlib
        from pathlib import Path
        p = Path(path)
        sha_path = p.with_suffix(p.suffix + ".sha256")
        if not sha_path.exists():
            logger.warning(
                "AnomalyDetector: no SHA-256 sidecar for %s — "
                "model integrity unverified.", p.name
            )
            return True
        try:
            expected = sha_path.read_text().strip().split()[0]
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            actual = h.hexdigest()
            if actual != expected:
                logger.error(
                    "AnomalyDetector: SHA-256 MISMATCH for %s — "
                    "refusing to load (expected=%s actual=%s).",
                    p.name, expected[:16] + "…", actual[:16] + "…",
                )
                return False
            return True
        except Exception as exc:
            logger.error("AnomalyDetector: integrity check failed for %s: %s", path, exc)
            return False

    def _load_scaler(self, scaler_path: str):
        """Load scaler using joblib only.  Pickle fallback removed (RCE risk)."""
        if not self._verify_file_integrity(scaler_path):
            logger.error("AnomalyDetector: scaler %s failed integrity check — not loading.", scaler_path)
            return None
        try:
            import joblib
            scaler = joblib.load(scaler_path)
            logger.info("Loaded scaler from %s", scaler_path)
            return scaler
        except Exception as exc:
            logger.error("Failed to load scaler %s: %s", scaler_path, exc)
            return None

    def load_model(self, model_path: str, is_l7: bool = False):
        """Dynamically load an ONNX, Joblib, or XGBoost model.

        Pickle (.pkl) fallback has been removed — it is an RCE vector if
        the model directory is writable by an attacker.
        """
        if not self._verify_file_integrity(model_path):
            logger.error("AnomalyDetector: model %s failed integrity check — not loading.", model_path)
            return
        try:
            ext = os.path.splitext(model_path)[1].lower()
            model_obj = None
            mod_type = None

            if ext == ".onnx":
                import onnxruntime as ort
                model_obj = ort.InferenceSession(model_path)
                mod_type = "onnx"
                logger.info("Loaded ONNX model from %s", model_path)
            elif ext in [".pkl", ".pickle"]:
                # XGBoost Booster files start with \x05 — try native XGBoost first,
                # then joblib for sklearn models.
                # Pickle is NOT attempted (RCE risk).
                loaded = False

                # 1. Try XGBoost native (handles both JSON/binary XGBoost models)
                try:
                    import xgboost as xgb
                    booster = xgb.Booster()
                    booster.load_model(model_path)
                    model_obj = booster
                    mod_type = "xgboost"
                    loaded = True
                    logger.info("Loaded XGBoost Booster model from %s", model_path)
                except Exception:
                    pass

                # 2. Try joblib (preferred for sklearn — no pickle deserialization risk)
                if not loaded:
                    try:
                        import joblib
                        model_obj = joblib.load(model_path)
                        mod_type = "sklearn"
                        loaded = True
                        logger.info("Loaded model via joblib from %s", model_path)
                    except Exception as exc:
                        logger.error(
                            "AnomalyDetector: could not load %s via XGBoost or joblib: %s",
                            model_path, exc,
                        )
            elif ext == ".joblib":
                import joblib
                model_obj = joblib.load(model_path)
                mod_type = "sklearn"
                logger.info("Loaded Joblib model from %s", model_path)
            else:
                logger.warning("Unsupported model extension %s for %s", ext, model_path)
                return

            if is_l7:
                self.l7_model = model_obj
                self.l7_model_type = mod_type
            else:
                self.model = model_obj
                self.model_type = mod_type
                
        except ImportError as ie:
            logger.error(f"Missing dependency to load module: {ie}. Install onnxruntime/joblib.")
        except Exception as e:
            logger.error(f"Failed to load anomaly model {model_path}: {e}")

    def _extract_features_array(self, features: TrafficFeatures) -> list:
        """Convert dataclass features to a 21-element numerical array suitable for ML"""
        return [
            # Original 14
            features.packets_per_second,
            features.bytes_per_second,
            features.avg_packet_size,
            features.packet_size_variance,
            features.tcp_ratio,
            features.udp_ratio,
            features.syn_ratio,
            features.unique_dst_ports,
            features.unique_src_ports,
            features.inter_arrival_time_mean,
            features.inter_arrival_time_variance,
            features.failed_connections,
            features.connection_attempts,
            features.reputation_score,
            # 7 new features
            features.flow_duration,
            features.payload_entropy,
            features.upload_download_ratio,
            features.fin_rst_ratio,
            features.max_packet_size,
            features.small_packet_ratio,
            features.ack_ratio,
        ]

    # ------------------------------------------------------------------
    # PHANTOM Layer 1 helper
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_sbe_score(features: "TrafficFeatures") -> float:
        """
        Compute a [0, 1] anomaly score contribution from the SBE vector.

        Returns 0.0 if neither raw_payload nor payload_sbe is available.

        The score is derived from the L2 distance between the observed
        spectral vector and the centroid of benign traffic in SBE space.
        Until a proper centroid is trained, we use two heuristics that
        work well even without labelled data:

          1. High FFT entropy (spectrum is flat) → typically encrypted
             benign traffic.  Very peaky or band-limited spectra suggest
             shellcode or protocol tunnelling.
          2. Byte-range entropy: genuine encrypted traffic has near-uniform
             byte distribution.  Compression artefacts or covert channels
             produce hollow distributions.
        """
        try:
            sbe: Optional[np.ndarray] = features.payload_sbe

            if sbe is None and features.raw_payload:
                from modules.ids_ips.engine.spectral.sbe import spectral_byte_encode
                sbe = spectral_byte_encode(features.raw_payload)

            if sbe is None:
                return 0.0

            # FFT component [0:128] — peaks in the low-frequency bin?
            fft_part    = sbe[0:128]
            fft_std     = float(np.std(fft_part))
            # High std → peaky spectrum (shellcode NOP sleds, structured C2)
            # We expect benign encrypted traffic to have low std (flat spectrum)
            fft_score   = min(1.0, fft_std * 4.0)   # empirical scale factor

            # Entropy component [240:248] — the 8-bin histogram normalised
            ent_part    = sbe[248:256]
            ent_mean    = float(np.mean(ent_part))
            # Very high entropy (near 1.0) → random bytes → encrypted/compressed
            # Very low entropy → repetitive pattern → potential shellcode/beacons
            ent_score   = max(0.0, 0.5 - ent_mean) * 2.0  # [0,1]

            # Combine: both signals point to maliciousness → higher score
            combined = (fft_score * 0.6) + (ent_score * 0.4)
            return float(np.clip(combined, 0.0, 1.0))

        except Exception as exc:
            logger.debug("SBE scoring failed: %s", exc)
            return 0.0

    # ------------------------------------------------------------------

    def detect(self, features: "TrafficFeatures") -> "AnomalyResult":
        """
        Detect anomalies in traffic features.

        Args:
            features: Extracted traffic features (21 statistical + optional SBE)

        Returns:
            AnomalyResult with fused score from ML model + SBE spectral analysis
        """
        ja3_details = {}
        ja3_score = 0.0
        ja3_is_anomaly = False

        # ── PHANTOM Layer 1: Spectral Byte Encoder contribution ──────────
        sbe_score = self._compute_sbe_score(features)
        
        # --- ETA/JA3 Integration ---
        if hasattr(features, 'tls_ja3_fingerprint') and features.tls_ja3_fingerprint:
            try:
                from modules.waf.engine.core.defenses.fingerprinting import AdvancedFingerprinting
                fingerprinter = AdvancedFingerprinting(check_headers=False)
                fp_result = fingerprinter.analyze(user_agent="unknown", headers={}, ja3_hash=features.tls_ja3_fingerprint)
                if fp_result.is_suspicious:
                    ja3_score = fp_result.risk_score
                    if fp_result.risk_score > 0.6:
                        ja3_is_anomaly = True
                    ja3_details['ja3_suspicious'] = fp_result.risk_score
                    if fp_result.reason:
                        ja3_details['ja3_reason'] = fp_result.reason
            except Exception as e:
                logger.error(f"Failed to run JA3 ETA Analysis: {e}")

        # Optional L7 DPI Classification
        l7_result = None
        if self.l7_model:
            try:
                import numpy as np
                feature_array = self._extract_features_array(features)
                X = np.array([feature_array], dtype=np.float32)
                if self.l7_scaler:
                    X = self.l7_scaler.transform(X)
                
                label = self.l7_model.predict(X)[0]
                # Assuming label encodes string output or specific int, e.g. 'normal', 'web_attack', 'brute_force'
                if hasattr(self.l7_model, "predict_proba"):
                    proba = self.l7_model.predict_proba(X)[0]
                    confidence = float(np.max(proba))
                else:
                    confidence = 0.9
                    
                l7_result = {
                    "classification": str(label),
                    "confidence": confidence
                }
            except Exception as e:
                logger.error(f"L7 Inference failed: {e}")

        # If a real model is loaded, use it bridging traffic logic to ML inference
        if self.model:
            try:
                feature_array = self._extract_features_array(features)
                
                # Convert feature list to the correct format and scale if needed
                import numpy as np
                X = np.array([feature_array], dtype=np.float32)
                
                if self.scaler:
                    X = self.scaler.transform(X)

                if self.model_type == "onnx":
                    input_name = self.model.get_inputs()[0].name
                    ort_outs = self.model.run(None, {input_name: X})
                    label = ort_outs[0][0]
                    anomaly_score = float(ort_outs[1][0] if len(ort_outs) > 1 else 0.5)
                    is_anomaly = bool(label == -1 or label == 1)

                elif self.model_type == "xgboost":
                    # xgb.Booster.predict() requires a DMatrix
                    import xgboost as xgb
                    dmat = xgb.DMatrix(X)
                    raw = self.model.predict(dmat)
                    # Booster predict returns probability or label depending on objective
                    score_val = float(raw[0])
                    # Treat output > 0.5 as anomaly (binary classifier probability)
                    is_anomaly = score_val > 0.5
                    anomaly_score = score_val

                elif self.model_type == "sklearn":
                    # sklearn IF: 1 for inliers, -1 for outliers
                    label = self.model.predict(X)[0]
                    is_anomaly = bool(label == -1)

                    if hasattr(self.model, "score_samples"):
                        anomaly_score = float(-self.model.score_samples(X)[0])
                    else:
                        anomaly_score = 0.8 if is_anomaly else 0.1

                else:
                    is_anomaly = False
                    anomaly_score = 0.0
                
                details = {"ml_confidence": anomaly_score, "model_type": self.model_type}
                details.update(ja3_details)

                if l7_result:
                    details["l7_classification"] = l7_result["classification"]
                    details["l7_confidence"] = l7_result["confidence"]

                    # Override anomaly status if L7 explicitly states it's an attack
                    if l7_result["classification"] != "normal" and l7_result["confidence"] > 0.8:
                        is_anomaly = True
                        anomaly_score = max(anomaly_score, l7_result["confidence"])

                if ja3_is_anomaly:
                    is_anomaly = True
                    anomaly_score = max(anomaly_score, ja3_score)

                # ── PHANTOM SBE fusion ───────────────────────────────────
                if sbe_score > 0.0:
                    details["sbe_score"] = round(sbe_score, 4)
                    # SBE alone is not conclusive — use it as a boosting signal
                    if sbe_score > 0.65:
                        is_anomaly = True
                        # Weighted fusion: ML model gets 70%, SBE gets 30%
                        anomaly_score = max(anomaly_score,
                                           anomaly_score * 0.7 + sbe_score * 0.3)
                    elif sbe_score > 0.45 and anomaly_score > 0.35:
                        # Soft boost: both signals weakly agree
                        anomaly_score = min(1.0, anomaly_score + sbe_score * 0.15)

                if is_anomaly:
                    self.anomalies_detected += 1

                return AnomalyResult(
                    is_anomaly=is_anomaly,
                    anomaly_score=anomaly_score,
                    confidence=0.9 if is_anomaly else 0.95,
                    details=details,
                )

            except Exception as e:
                logger.error(f"ML Inference failed, falling back to heuristics: {e}")

        # ── Fallback Heuristics (no ML model loaded / inference error) ─
        score   = 0.0
        details = {}

        if features.failed_connections > 100:
            score += 0.4
            details["high_failed_connections"] = features.failed_connections

        if features.packets_per_second > 10_000:
            score += 0.3
            details["high_pps"] = features.packets_per_second

        if features.reputation_score < 50:
            score += 0.3
            details["low_reputation"] = features.reputation_score

        # ── PHANTOM SBE boost in fallback mode ───────────────────────────
        if sbe_score > 0.0:
            details["sbe_score"] = round(sbe_score, 4)
            score = min(1.0, score + sbe_score * 0.4)

        details.update(ja3_details)
        if ja3_is_anomaly:
            score = max(score, ja3_score)

        is_anomaly = score > 0.5

        if is_anomaly:
            self.anomalies_detected += 1

        return AnomalyResult(
            is_anomaly=is_anomaly,
            anomaly_score=score,
            confidence=0.8 if is_anomaly else 0.9,
            details=details,
        )
        
    def get_stats(self) -> Dict[str, int]:
        """
        Get statistics about anomaly detection.
        
        Returns:
            Dictionary containing statistics.
        """
        return {
            'anomalies_detected': self.anomalies_detected
        }
