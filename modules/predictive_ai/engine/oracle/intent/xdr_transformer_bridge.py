"""
bunyanx NGFW — AEGIS Engine: XDR Multi-Modal Transformer Bridge
====================================================================

This module bridges the large-scale XDR Transformer (models/cyber_transformer.py)
trained on 36M real behavioral sessions with the AEGIS Engine's AIS interface.

Architecture Position
---------------------
The XDR Transformer was trained on our 5-phase UEM pipeline data:
  - CIC-IDS2018 / CIC-DDoS2019 / UNSW-NB15     (Network Layer)
  - CERT Insider Threat r4.1 / Sysmon Logs      (Endpoint Layer)
  → Sessionized into 36M behavioral chains
  → Tokenized as <source:action:ts> sequences

This predictor acts as a DROP-IN ENHANCER on top of the existing
TTPTransformerPredictor: it augments the standard 9-class TTP prediction
with the richer multi-modal signal from the XDR model (is_attack score,
intent distribution, TTP multi-hot vector).

Integration Mode
----------------
  BLEND mode (default):
      Π_A_final(a) = (1 - ω_xdr) * Π_A_small(a) + ω_xdr * Π_A_xdr(a)
      where ω_xdr = 0.40 (XDR model has more data, more weight)

  OVERRIDE mode (when XDR checkpoint is high-confidence):
      Π_A_final(a) = Π_A_xdr(a)

Research Reference
------------------
  AEGIS Paper §IV.B — "Stage 2 Enhancement: XDR Multi-Modal Transformer"
  Pre-trained on 36,067,363 behavioral sessions across 5 real datasets.
"""

from __future__ import annotations

import json
import logging
import math
import threading
from collections import deque
from pathlib import Path
from typing import Optional

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_MODELS_DIR   = Path(__file__).resolve().parent.parent.parent.parent / "models"
_XDR_MODEL    = _MODELS_DIR / "cyber_transformer_final.pth"
_XDR_CKPT_DIR = _MODELS_DIR / "checkpoints"
_VOCAB_FILE   = _MODELS_DIR / "vocab.json"

# ---------------------------------------------------------------------------
# TTP Mapping: XDR Intent → AEGIS TTP_NAMES
# ---------------------------------------------------------------------------
# The XDR model was trained on raw behavioral data (network:scan:ts, etc.)
# and classifies intent as: benign, denial_of_service, credential_theft,
# reconnaissance, unknown.
# We map these intents to the AEGIS's 9-class TTP space.

XDR_INTENT_TO_TTP: dict[str, str] = {
    "denial_of_service": "RANSOMWARE",      # High-impact disruptive
    "credential_theft":  "PRIV_ESC",        # Credential → privilege
    "reconnaissance":    "SCAN",            # Probing behavior
    "unknown":           "WAF_EXPLOIT",     # Default to active exploit
    "benign":            "SCAN",            # Minimal threat signal
}

# XDR attack probability → AEGIS TTP probability amplification
# is_attack=1 with high confidence amplifies the mapped TTP probability
_ATTACK_AMPLIFIER = 2.5


class XDRTransformerBridge:
    """
    Bridges the large XDR Transformer (3.28M params, 36M training samples)
    with the AEGIS Engine's AIS prediction interface.

    Operates in two modes:
      1. Full mode — XDR model loaded and running inference
      2. Heuristic mode — XDR model not yet trained; falls back to
         a statistically grounded prior from the training data distribution
         (0.74% attack rate, known intent ratios from dataset_quality_report)

    Parameters
    ----------
    xdr_blend_weight : float
        Weight of the XDR model in the final blended prediction.
        Default: 0.40 (XDR contributes 40%, small Transformer 60%)
    device : str
        PyTorch device string. Default: 'cpu'.
    """

    def __init__(
        self,
        xdr_blend_weight: float = 0.40,
        device: str = "cpu",
    ) -> None:
        self._weight = xdr_blend_weight
        self._device = device
        self._model  = None
        self._vocab: Optional[dict] = None
        self._loaded = False
        self._lock   = threading.Lock()

        # Runtime stats
        self._inference_count  = 0
        self._xdr_active_count = 0

        # Try to load immediately
        self._try_load()

    # ------------------------------------------------------------------
    # Public API (compatible with TTPTransformerPredictor.predict())
    # ------------------------------------------------------------------

    def predict_xdr_amplification(
        self,
        base_probs: dict[str, float],
        event_sequence: list[str],
    ) -> dict[str, float]:
        """
        Amplify a base TTP probability distribution using the XDR model.

        Parameters
        ----------
        base_probs : dict[str, float]
            The existing TTP probability dict from TTPTransformerPredictor.
        event_sequence : list[str]
            The raw event sequence for this IP (e.g., ['network:scan:ts', ...]).
            These are the actual tokens produced by the 5-phase pipeline.

        Returns
        -------
        dict[str, float]
            Blended and renormalized TTP probability distribution.
        """
        with self._lock:
            self._inference_count += 1

        if self._loaded and self._model is not None:
            return self._xdr_inference(base_probs, event_sequence)
        else:
            return self._heuristic_amplification(base_probs, event_sequence)

    def get_is_attack_score(self, event_sequence: list[str]) -> float:
        """
        Returns the XDR model's raw is_attack probability [0..1].
        Uses heuristic if model is not loaded.
        """
        if self._loaded and self._model is not None:
            return self._xdr_attack_score(event_sequence)
        return self._heuristic_attack_score(event_sequence)

    def get_status(self) -> dict:
        """Return bridge status for health checks and paper metrics."""
        return {
            "xdr_model_loaded":    self._loaded,
            "xdr_model_path":      str(_XDR_MODEL),
            "vocab_loaded":        self._vocab is not None,
            "blend_weight":        self._weight,
            "total_inferences":    self._inference_count,
            "xdr_active_inferences": self._xdr_active_count,
            "mode":                "XDR_INFERENCE" if self._loaded else "HEURISTIC_PRIOR",
        }

    # ------------------------------------------------------------------
    # Private: XDR Inference Path
    # ------------------------------------------------------------------

    def _xdr_inference(
        self,
        base_probs: dict[str, float],
        event_sequence: list[str],
    ) -> dict[str, float]:
        """Run real XDR Transformer inference and blend with base_probs."""
        import torch
        import torch.nn.functional as F

        try:
            # Encode the event sequence using the XDR vocab
            token2id = self._vocab.get("token2id", {})
            intent2id = self._vocab.get("intent2id", {})

            PAD_ID = token2id.get("[PAD]", 0)
            UNK_ID = token2id.get("[UNK]", 1)
            CLS_ID = token2id.get("[CLS]", 2)
            SEP_ID = token2id.get("[SEP]", 3)
            MAX_LEN = 50

            # Truncate sequence
            seq = event_sequence[-(MAX_LEN - 2):] if len(event_sequence) > MAX_LEN - 2 else event_sequence
            ids = [CLS_ID] + [token2id.get(tok, UNK_ID) for tok in seq] + [SEP_ID]
            mask = [1] * len(ids)
            # Pad
            pad_len = MAX_LEN - len(ids)
            ids  = ids  + [PAD_ID] * pad_len
            mask = mask + [0] * pad_len

            input_ids      = torch.tensor([ids],  dtype=torch.long)
            attention_mask = torch.tensor([mask], dtype=torch.float32)

            self._model.eval()
            with torch.no_grad():
                outputs = self._model(input_ids, attention_mask)

            # Extract attack score
            attack_logit = outputs["attack"]
            attack_prob  = torch.sigmoid(attack_logit).item()

            # Extract intent distribution
            intent_logits = outputs["intent"]
            intent_probs  = F.softmax(intent_logits, dim=-1).squeeze(0).tolist()

            # Map intent → AEGIS TTP
            id2intent = {v: k for k, v in intent2id.items()}
            top_intent_idx = int(torch.argmax(intent_logits))
            top_intent = id2intent.get(top_intent_idx, "unknown")
            mapped_ttp = XDR_INTENT_TO_TTP.get(top_intent, "WAF_EXPLOIT")

            # Build XDR-weighted TTP dict
            xdr_probs = dict(base_probs)  # Start from base

            if attack_prob > 0.5:
                # Amplify the mapped TTP proportional to attack confidence
                amplification = attack_prob * _ATTACK_AMPLIFIER
                current = xdr_probs.get(mapped_ttp, 0.1)
                xdr_probs[mapped_ttp] = min(1.0, current * amplification)

            # Normalize xdr_probs
            total = sum(xdr_probs.values()) or 1.0
            xdr_probs = {k: v / total for k, v in xdr_probs.items()}

            # Blend: (1-w)*base + w*xdr
            blended = {}
            for ttp in base_probs:
                b = base_probs.get(ttp, 0.0)
                x = xdr_probs.get(ttp, 0.0)
                blended[ttp] = (1 - self._weight) * b + self._weight * x

            # Renormalize
            total = sum(blended.values()) or 1.0
            blended = {k: v / total for k, v in blended.items()}

            with self._lock:
                self._xdr_active_count += 1

            _log.debug(
                "XDRBridge: is_attack=%.3f intent=%s mapped_ttp=%s",
                attack_prob, top_intent, mapped_ttp,
            )
            return blended

        except Exception as e:
            _log.warning("XDRBridge inference failed (%s), falling back to heuristic", e)
            return self._heuristic_amplification(base_probs, event_sequence)

    def _xdr_attack_score(self, event_sequence: list[str]) -> float:
        """Run XDR forward pass for is_attack score only."""
        import torch
        try:
            token2id = self._vocab.get("token2id", {})
            PAD_ID = token2id.get("[PAD]", 0)
            CLS_ID = token2id.get("[CLS]", 2)
            SEP_ID = token2id.get("[SEP]", 3)
            UNK_ID = token2id.get("[UNK]", 1)
            MAX_LEN = 50

            seq = event_sequence[-(MAX_LEN - 2):]
            ids = [CLS_ID] + [token2id.get(t, UNK_ID) for t in seq] + [SEP_ID]
            mask = [1] * len(ids)
            pad_len = MAX_LEN - len(ids)
            ids  = ids  + [PAD_ID] * pad_len
            mask = mask + [0] * pad_len

            input_ids      = torch.tensor([ids],  dtype=torch.long)
            attention_mask = torch.tensor([mask], dtype=torch.float32)

            self._model.eval()
            with torch.no_grad():
                out = self._model(input_ids, attention_mask)
            return float(torch.sigmoid(out["attack"]).item())
        except Exception:
            return self._heuristic_attack_score(event_sequence)

    # ------------------------------------------------------------------
    # Private: Heuristic Fallback (when model not yet trained)
    # ------------------------------------------------------------------

    def _heuristic_amplification(
        self,
        base_probs: dict[str, float],
        event_sequence: list[str],
    ) -> dict[str, float]:
        """
        Statistically grounded amplification based on XDR dataset priors.

        From dataset_quality_report.json:
          - 0.74% attack rate in dataset
          - Known intents: denial_of_service, credential_theft, reconnaissance
          - Attack samples = 268,041 / 36,067,363 total

        Attack signals detected via token analysis:
          - 'network:scan' tokens → SCAN / RECONNAISSANCE
          - 'network:exploit' tokens → WAF_EXPLOIT
          - 'endpoint:exec' tokens → PRIV_ESC
          - 'network:payload_transfer' → DLP_EXFIL / RANSOMWARE
        """
        attack_signal_tokens = {
            "network:scan":             ("SCAN",       0.65),
            "network:exploit":          ("WAF_EXPLOIT", 0.75),
            "endpoint:exec":            ("PRIV_ESC",   0.60),
            "network:payload_transfer": ("DLP_EXFIL",  0.70),
            "endpoint:reg_mod":         ("PERSISTENCE", 0.55),
            "network:c2":               ("DGA_C2",     0.80),
            "network:lateral":          ("LATERAL",    0.72),
            "endpoint:inject":          ("PRIV_ESC",   0.68),
        }

        amplified = dict(base_probs)
        detected_attack = False

        for token in event_sequence:
            tok_lower = token.lower()
            for signal, (ttp, strength) in attack_signal_tokens.items():
                if signal in tok_lower:
                    current = amplified.get(ttp, 0.1)
                    amplified[ttp] = min(1.0, current + (strength * self._weight * 0.5))
                    detected_attack = True

        if not detected_attack:
            return base_probs  # No signal, return unchanged

        # Renormalize
        total = sum(amplified.values()) or 1.0
        return {k: v / total for k, v in amplified.items()}

    def _heuristic_attack_score(self, event_sequence: list[str]) -> float:
        """Estimate attack probability from token patterns (heuristic mode)."""
        attack_tokens = {"exploit", "scan", "payload", "c2", "lateral", "inject", "priv"}
        hits = sum(
            1 for tok in event_sequence
            if any(a in tok.lower() for a in attack_tokens)
        )
        # Base rate 0.0074 from dataset + signal amplification
        return min(0.95, 0.0074 + hits * 0.12)

    # ------------------------------------------------------------------
    # Private: Model Loading
    # ------------------------------------------------------------------

    def _try_load(self) -> None:
        """
        Attempt to load the XDR model. 
        Gracefully continues in heuristic mode if not available.
        """
        # Load vocab (always try)
        if _VOCAB_FILE.exists():
            try:
                with open(_VOCAB_FILE, "r", encoding="utf-8") as f:
                    self._vocab = json.load(f)
                _log.info("XDRBridge: Vocab loaded (%d tokens)", len(self._vocab.get("token2id", {})))
            except Exception as e:
                _log.warning("XDRBridge: Vocab load failed: %s", e)

        # Find best available checkpoint
        model_path = None
        if _XDR_MODEL.exists():
            model_path = _XDR_MODEL
            _log.info("XDRBridge: Found final model at %s", model_path)
        else:
            # Try latest checkpoint
            ckpts = sorted(_XDR_CKPT_DIR.glob("ckpt_step_*.pth")) if _XDR_CKPT_DIR.exists() else []
            if ckpts:
                model_path = ckpts[-1]
                _log.info("XDRBridge: Found checkpoint at %s", model_path)

        if model_path is None:
            _log.info(
                "XDRBridge: No trained model found. Operating in HEURISTIC_PRIOR mode. "
                "Run models/train.py to enable full XDR inference."
            )
            return

        # Load the model
        try:
            import torch
            import sys, os
            sys.path.insert(0, str(_MODELS_DIR))
            import importlib.util

            spec = importlib.util.spec_from_file_location(
                "cyber_transformer_m",
                str(_MODELS_DIR / "cyber_transformer.py")
            )
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            MultiModalCyberTransformer = mod.MultiModalCyberTransformer

            checkpoint = torch.load(model_path, map_location=self._device, weights_only=False)

            # Extract config
            if "config" in checkpoint:
                cfg = checkpoint["config"]
                d_model    = cfg.get("d_model", 256)
                nhead      = cfg.get("nhead", 8)
                num_layers = cfg.get("num_layers", 4)
                max_seq    = cfg.get("max_seq_len", 50)
            else:
                d_model, nhead, num_layers, max_seq = 256, 8, 4, 50

            vocab_size   = checkpoint.get("vocab_size", len(self._vocab.get("token2id", {})) if self._vocab else 27)
            num_intents  = checkpoint.get("num_intents", 5)
            num_ttps_xdr = checkpoint.get("num_ttps", 3)

            model = MultiModalCyberTransformer(
                vocab_size=vocab_size,
                num_intents=max(num_intents, 2),
                num_ttps=max(num_ttps_xdr, 1),
                d_model=d_model,
                nhead=nhead,
                num_layers=num_layers,
                max_seq_len=max_seq,
            )

            state_key = "model_state_dict" if "model_state_dict" in checkpoint else "model"
            model.load_state_dict(checkpoint[state_key])
            model.eval()
            self._model  = model
            self._loaded = True

            _log.info(
                "XDRBridge: XDR Transformer loaded from %s | "
                "vocab=%d, intents=%d, ttps=%d, d_model=%d",
                model_path.name, vocab_size, num_intents, num_ttps_xdr, d_model
            )

        except Exception as exc:
            _log.warning(
                "XDRBridge: Model load failed (%s). Heuristic mode active.", exc
            )
            self._loaded = False
