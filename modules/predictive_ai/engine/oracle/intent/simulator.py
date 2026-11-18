"""
bunyanx NGFW — AEGIS Engine: Adversarial Intent Simulator (AIS)
===================================================================

Models the attacker's intent using a hybrid ML-driven sequence model.
The sequence model (Transformer) processes both network TTPs and endpoint
signals to predict the probability distribution of the next likely TTP.

The prediction is then amplified by the XDR Multi-Modal Transformer Bridge,
which was pre-trained on 36,067,363 real behavioral sessions from:
  - CIC-IDS2018 / CIC-DDoS2019 / UNSW-NB15 (Network Layer)
  - CERT Insider Threat r4.1 / Sysmon Logs  (Endpoint Layer)

Strict Architectural Rules:
- NO CTI hard-overrides or heuristics in the primary path.
- NO silent fallbacks to Q-Tables or LSTMs.
- The Transformer is the primary source of truth for TTP prediction.
- XDR Bridge enriches the prediction with cross-domain behavioral context.
- If the small Transformer model is missing, an explicit RuntimeError is raised.
"""

from __future__ import annotations

import logging
import threading
from collections import deque
from typing import NamedTuple

from modules.predictive_ai.engine.AEGIS.core.constants import (
    NUM_TTPS,
    TTP_NAMES,
)
from modules.predictive_ai.engine.AEGIS.intent.attention_predictor import (
    TTPTransformerPredictor,
)
from modules.predictive_ai.engine.AEGIS.intent.xdr_transformer_bridge import (
    XDRTransformerBridge,
)

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Output type
# ---------------------------------------------------------------------------

class TTPPrediction(NamedTuple):
    """A single TTP and its predicted probability."""
    ttp: str
    probability: float


# ---------------------------------------------------------------------------
# AdversarialIntentSimulator
# ---------------------------------------------------------------------------

class AdversarialIntentSimulator:
    """
    Hybrid ML-driven attacker intent model.

    Core responsibility
    -------------------
    Given the historical sequence of observed Network TTPs and Endpoint
    signals for an IP, produce a probability distribution Pi_A over the
    attacker's *next* likely TTPs using a two-stage pipeline:

    Stage 1 — TTPTransformerPredictor (small, AEGIS-native, 9-class):
        Predicts next TTP from last 10 events (Network + Endpoint one-hot).

    Stage 2 — XDRTransformerBridge (large, 36M-sample pre-trained):
        Amplifies Stage 1 output using cross-domain behavioral signals.
        Falls back to statistically-grounded heuristics if not yet trained.

    Research Reference
    ------------------
    AEGIS Paper Section IV.B — Adversarial Intent Simulator (AIS)
    XDR Bridge: Pre-trained on 36,067,363 behavioral sessions (Phase 5 Pipeline).
    """

    def __init__(self) -> None:
        # Stage 1: AEGIS-native Transformer (9-class TTP predictor)
        # Raises RuntimeError on inference if model file is missing.
        self._transformer = TTPTransformerPredictor()

        # Stage 2: XDR Multi-Modal Bridge (36M-sample pre-trained)
        # Gracefully operates in heuristic mode if model not yet trained.
        self._xdr_bridge = XDRTransformerBridge(xdr_blend_weight=0.40)

        # Per-IP history buffers
        self._hist_len = self._transformer.window_size
        self._ip_history: dict[str, deque]          = {}  # Network TTPs
        self._ip_endpoint_history: dict[str, deque] = {}  # Endpoint signals
        self._ip_xdr_events: dict[str, deque]       = {}  # Raw XDR tokens

        self._lock             = threading.Lock()
        self._prediction_count = 0
        self._correct_count    = 0

        xdr_mode = self._xdr_bridge.get_status()["mode"]
        _log.info(
            "AdversarialIntentSimulator ready — Mode: Transformer + XDR Bridge (%s)",
            xdr_mode,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def predict_ttp_distribution(
        self,
        src_ip: str,
        top_n: int = 9,
    ) -> list[TTPPrediction]:
        """
        Compute the attacker TTP distribution using the two-stage pipeline.

        Stage 1: TTPTransformerPredictor (AEGIS-native, 9-class)
        Stage 2: XDRTransformerBridge amplification (36M-sample signal)

        Parameters
        ----------
        src_ip : str
            The attacker IP address.
        top_n : int
            Number of TTPs to return, sorted by probability descending.
        """
        history          = list(self._ip_history.get(src_ip, []))
        endpoint_history = list(self._ip_endpoint_history.get(src_ip, []))
        xdr_events       = list(self._ip_xdr_events.get(src_ip, []))

        # Stage 1: AEGIS-native Transformer (raises RuntimeError if not ready)
        probs_dict = self._transformer.predict(history, endpoint_history)

        # Stage 2: XDR Bridge amplification
        probs_dict = self._xdr_bridge.predict_xdr_amplification(
            base_probs=probs_dict,
            event_sequence=xdr_events,
        )

        # Build sorted result
        sorted_items = sorted(probs_dict.items(), key=lambda x: x[1], reverse=True)
        predictions = [
            TTPPrediction(ttp, float(prob))
            for ttp, prob in sorted_items[:top_n]
        ]

        _log.debug(
            "AIS: ip=%s -> top_ttp=%s (p=%.3f) | xdr_events=%d",
            src_ip,
            predictions[0].ttp if predictions else "-",
            predictions[0].probability if predictions else 0.0,
            len(xdr_events),
        )

        with self._lock:
            self._prediction_count += 1

        return predictions

    def get_attention_explanation(self, src_ip: str) -> dict:
        """
        Extract attention weights from the Transformer for XAI explanation.
        Also returns XDR Bridge status for transparency.
        """
        history          = list(self._ip_history.get(src_ip, []))
        endpoint_history = list(self._ip_endpoint_history.get(src_ip, []))
        xdr_events       = list(self._ip_xdr_events.get(src_ip, []))

        attn_weights = self._transformer.get_attention_weights(history, endpoint_history)
        xdr_status   = self._xdr_bridge.get_status()

        return {
            "history":             history,
            "endpoint_history":    endpoint_history,
            "xdr_event_count":     len(xdr_events),
            "attention_available": attn_weights is not None,
            "xdr_bridge_mode":     xdr_status["mode"],
            "xdr_model_loaded":    xdr_status["xdr_model_loaded"],
        }

    def observe_real_ttp(
        self,
        ttp_name: str,
        src_ip: str,
        is_endpoint_signal: bool = False,
    ) -> None:
        """
        Updates per-IP TTP/Endpoint history and XDR event buffer.

        The XDR event buffer stores raw tokens in the format expected
        by the XDR Bridge: 'network:<ttp>' or 'endpoint:<signal>'.
        """
        if not src_ip:
            return

        with self._lock:
            if is_endpoint_signal:
                # Endpoint history for small Transformer
                if src_ip not in self._ip_endpoint_history:
                    self._ip_endpoint_history[src_ip] = deque(maxlen=self._hist_len)
                self._ip_endpoint_history[src_ip].append(ttp_name.upper())
                # XDR buffer with endpoint prefix
                if src_ip not in self._ip_xdr_events:
                    self._ip_xdr_events[src_ip] = deque(maxlen=50)
                self._ip_xdr_events[src_ip].append(f"endpoint:{ttp_name.lower()}")
            else:
                # Network TTP history for small Transformer
                if src_ip not in self._ip_history:
                    self._ip_history[src_ip] = deque(maxlen=self._hist_len)
                self._ip_history[src_ip].append(ttp_name.upper())
                # XDR buffer with network prefix
                if src_ip not in self._ip_xdr_events:
                    self._ip_xdr_events[src_ip] = deque(maxlen=50)
                self._ip_xdr_events[src_ip].append(f"network:{ttp_name.lower()}")

    def record_prediction_accuracy(self, predicted_top_ttp: str, actual_ttp: str) -> None:
        """Track prediction accuracy for the API transparency endpoint."""
        if predicted_top_ttp.upper() == actual_ttp.upper():
            with self._lock:
                self._correct_count += 1

    def get_accuracy_report(self) -> dict:
        """Return current AIS prediction accuracy metrics."""
        with self._lock:
            total   = self._prediction_count
            correct = self._correct_count

        return {
            "total_predictions":   total,
            "correct_predictions": correct,
            "top1_accuracy":       round(correct / total, 4) if total else None,
            "model_type":          "Transformer + XDR Bridge (36M-sample pre-trained)",
            "ready":               self._transformer.is_ready if hasattr(self._transformer, "is_ready") else False,
            "xdr_bridge":          self._xdr_bridge.get_status(),
        }
