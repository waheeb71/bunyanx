"""
bunyanx NGFW — AEGIS Engine: TTP Transformer Sequence Predictor
====================================================================

Transformer Encoder with Multi-Head Self-Attention that predicts the
next TTP given the last N observed TTPs.

Problem Solved
--------------
The Transformer's self-attention mechanism directly connects any two
positions in the sequence with O(1) path length, enabling:
  - Direct correlation between early reconnaissance and late exfiltration
  - Interpretable attention weight matrices showing which past events
    most influenced the current prediction

Multi-Modal Support (XDR-Ready)
-------------------------------
The model accepts both Network TTPs (L4-L7) and Endpoint Signals
(e.g., process creation, memory injection). The Transformer learns the
joint representation to predict the next stage.

Architecture
------------
  Input:  last 10 events (Network + Endpoint one-hot) → shape (batch, 10, 14)
  ↓
  Positional Encoding (sinusoidal)
  ↓
  Linear projection: 14 → d_model=64
  ↓
  Transformer Encoder (2 layers, 4 heads, d_ff=256, dropout=0.1)
  ↓
  Classification head: Linear(64) → ReLU → Dropout(0.1) → Linear(9) (predicts network TTP)
  ↓
  Output: softmax distribution over 9 Network TTPs

STRICT ENFORCEMENT
------------------
This module raises an explicit `RuntimeError` if PyTorch or the model
file is missing. Silent fallbacks are strictly prohibited to ensure
scientific validity.

Research Reference
------------------
  Vaswani et al., "Attention Is All You Need," NeurIPS 2017.
  AEGIS Paper — §IV.B Layer 3 (AIS Transformer Upgrade)
"""

from __future__ import annotations

import logging
import math
from pathlib import Path
from typing import Optional

_log = logging.getLogger(__name__)

_MODEL_PATH = Path(__file__).resolve().parent.parent.parent.parent / "models" / "ttp_transformer.pt"
_WINDOW_SIZE = 10  # Expanded from LSTM's 5

TTP_NAMES = [
    "SCAN", "WAF_EXPLOIT", "MALWARE", "DGA_C2", "DLP_EXFIL",
    "LATERAL", "PRIV_ESC", "PERSISTENCE", "RANSOMWARE",
]
TTP_INDEX = {t: i for i, t in enumerate(TTP_NAMES)}
N_TTPS    = len(TTP_NAMES)

ENDPOINT_SIGNALS = [
    "PROC_CREATE", "FILE_MOD", "REG_EDIT", "NET_CONN", "MEM_INJECT"
]
ENDPOINT_INDEX = {t: i for i, t in enumerate(ENDPOINT_SIGNALS)}
N_ENDPOINT = len(ENDPOINT_SIGNALS)

N_FEATURES = N_TTPS + N_ENDPOINT


# ---------------------------------------------------------------------------
# Positional Encoding (Sinusoidal)
# ---------------------------------------------------------------------------

def _build_positional_encoding(d_model: int, max_len: int = 512):
    """
    Create sinusoidal positional encoding matrix.

    PE(pos, 2i)   = sin(pos / 10000^(2i/d_model))
    PE(pos, 2i+1) = cos(pos / 10000^(2i/d_model))
    """
    import torch

    pe = torch.zeros(max_len, d_model)
    position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
    div_term = torch.exp(
        torch.arange(0, d_model, 2, dtype=torch.float)
        * (-math.log(10000.0) / d_model)
    )
    pe[:, 0::2] = torch.sin(position * div_term)
    pe[:, 1::2] = torch.cos(position * div_term)
    return pe.unsqueeze(0)  # (1, max_len, d_model)


# ---------------------------------------------------------------------------
# Transformer Model Definition
# ---------------------------------------------------------------------------

def _build_transformer_model(
    d_model:  int = 64,
    n_heads:  int = 4,
    n_layers: int = 2,
    d_ff:     int = 256,
    dropout:  float = 0.1,
):
    """Build the Transformer Encoder model (requires torch)."""
    import torch
    import torch.nn as nn

    class _TTPTransformerModel(nn.Module):
        """
        Transformer Encoder for TTP sequence prediction.

        Architecture:
          Input projection (9 → d_model) → Positional Encoding
          → N x TransformerEncoderLayer(d_model, n_heads, d_ff)
          → Classification head (d_model → 9)
        """

        def __init__(self):
            super().__init__()
            self.d_model = d_model

            # Input projection: Features (14) → d_model (64)
            self.input_projection = nn.Linear(N_FEATURES, d_model)

            # Positional encoding (registered as buffer, not parameter)
            pe = _build_positional_encoding(d_model)
            self.register_buffer("pe", pe)

            # Transformer encoder layers
            encoder_layer = nn.TransformerEncoderLayer(
                d_model=d_model,
                nhead=n_heads,
                dim_feedforward=d_ff,
                dropout=dropout,
                batch_first=True,
                activation="gelu",
            )
            self.transformer_encoder = nn.TransformerEncoder(
                encoder_layer,
                num_layers=n_layers,
            )

            # Classification head
            self.head = nn.Sequential(
                nn.Linear(d_model, d_model // 2),
                nn.ReLU(),
                nn.Dropout(dropout),
                nn.Linear(d_model // 2, N_TTPS),
            )

            # Store attention weights for interpretability
            self._attention_weights: Optional[list] = None

        def forward(self, x):
            """
            Forward pass.

            Parameters
            ----------
            x : Tensor, shape (batch, seq_len, 9)
                One-hot encoded TTP sequence.

            Returns
            -------
            logits : Tensor, shape (batch, 9)
                Raw scores for each TTP class.
            """
            seq_len = x.size(1)

            # Project to d_model dimensions
            h = self.input_projection(x)  # (B, S, d_model)

            # Add positional encoding
            h = h + self.pe[:, :seq_len, :]

            # Transformer encoder
            h = self.transformer_encoder(h)  # (B, S, d_model)

            # Use last position's output for classification
            h_last = h[:, -1, :]  # (B, d_model)

            return self.head(h_last)  # (B, 9)

        def forward_with_attention(self, x):
            """
            Forward pass that also returns attention weights.

            Returns (logits, attention_weights_list).
            Each element is shape (batch, n_heads, seq_len, seq_len).
            """
            seq_len = x.size(1)
            h = self.input_projection(x)
            h = h + self.pe[:, :seq_len, :]

            # Manually pass through each layer to capture attention
            attn_weights_all = []
            for layer in self.transformer_encoder.layers:
                # Self-attention sub-layer
                h2, attn_w = layer.self_attn(
                    h, h, h,
                    need_weights=True,
                    average_attn_weights=False,
                )
                attn_weights_all.append(attn_w.detach())
                # Complete the residual + feedforward path
                h = layer(h)

            h_last = h[:, -1, :]
            logits = self.head(h_last)
            return logits, attn_weights_all

    return _TTPTransformerModel()


# ---------------------------------------------------------------------------
# TTPTransformerPredictor
# ---------------------------------------------------------------------------

class TTPTransformerPredictor:
    """
    Transformer-based TTP predictor with interpretable attention.

    Drop-in replacement for TTPSequencePredictor (LSTM version).
    Uses Multi-Head Self-Attention to model long-range dependencies
    in attack sequences.

    Parameters
    ----------
    model_path : Path | None
        Override path to ttp_transformer.pt.
    window_size : int
        Number of past TTPs to consider. Default: 10.
    """

    def __init__(
        self,
        model_path: Optional[Path] = None,
        window_size: int = _WINDOW_SIZE,
    ) -> None:
        self._path        = model_path or _MODEL_PATH
        self._window_size = window_size
        self._model       = None
        self._loaded      = False
        self._device      = "cpu"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def is_ready(self) -> bool:
        """True if model file exists and loads successfully. Otherwise raises."""
        if not self._path.exists():
            raise RuntimeError(f"Transformer model file missing at {self._path}. Must train model first.")
        if not self._loaded:
            self._load_model()
        return self._model is not None

    @property
    def window_size(self) -> int:
        """The input sequence window size."""
        return self._window_size

    def predict(
        self, 
        history: list[str], 
        endpoint_history: Optional[list[str]] = None
    ) -> dict[str, float]:
        """
        Given a history of TTPs and optional endpoint signals, return probability 
        distribution over all 9 Network TTPs for the NEXT step.

        Parameters
        ----------
        history : list[str]
            Observed Network TTP sequence.
        endpoint_history : list[str], optional
            Observed Endpoint signals. Padded/truncated alongside TTP history.

        Returns
        -------
        dict[str, float]
            TTP name → probability (sums to 1.0).
        """
        if not self.is_ready:
            raise RuntimeError("TTPTransformerPredictor not ready.")

        import torch
        import torch.nn.functional as F

        endpoint_history = endpoint_history or []
        window_ttps, window_endpoints = self._build_windows(history, endpoint_history)
        x_onehot = self._to_onehot(window_ttps, window_endpoints)

        self._model.eval()
        with torch.no_grad():
            logits = self._model(x_onehot)
            probs = F.softmax(logits, dim=-1).squeeze(0).tolist()

        return dict(zip(TTP_NAMES, probs))

    def predict_top_k(
        self, 
        history: list[str], 
        endpoint_history: Optional[list[str]] = None, 
        k: int = 3
    ) -> list[tuple[str, float]]:
        """Return top-k most likely next TTPs."""
        probs = self.predict(history, endpoint_history)
        return sorted(probs.items(), key=lambda x: x[1], reverse=True)[:k]

    def get_attention_weights(
        self, 
        history: list[str],
        endpoint_history: Optional[list[str]] = None
    ) -> list:
        """
        Return attention weight matrices for interpretability analysis (XAI).

        Returns a list of tensors, one per encoder layer.
        Each tensor has shape (1, n_heads, seq_len, seq_len).
        """
        if not self.is_ready:
            raise RuntimeError("TTPTransformerPredictor not ready.")

        import torch

        endpoint_history = endpoint_history or []
        window_ttps, window_endpoints = self._build_windows(history, endpoint_history)
        x_onehot = self._to_onehot(window_ttps, window_endpoints)

        self._model.eval()
        with torch.no_grad():
            _, attn_weights = self._model.forward_with_attention(x_onehot)

        return attn_weights

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _load_model(self) -> None:
        """Load model weights from disk. Raises RuntimeError on failure."""
        import torch
        if getattr(self, "_loading", False):
            return
        self._loading = True
        
        try:
            model = _build_transformer_model()
            state = torch.load(self._path, map_location="cpu", weights_only=True)
            if "pos_encoder.pe" in state and "pe" not in state:
                state["pe"] = state.pop("pos_encoder.pe")
            model.load_state_dict(state)
            model.eval()
            self._model  = model
            self._loaded = True
            _log.info("TTPTransformerPredictor: loaded from %s", self._path)
        except Exception as exc:
            raise RuntimeError(f"Failed to load Transformer model from {self._path}: {exc}")
        finally:
            self._loading = False

    def _build_windows(
        self, 
        history: list[str], 
        endpoint_history: list[str]
    ) -> tuple[list[int], list[int]]:
        """Convert histories to padded index windows."""
        indices = []
        for t in history:
            t_upper = t.upper()
            t_norm = t_upper.replace("LATERAL_MOVEMENT", "LATERAL")
            indices.append(TTP_INDEX.get(t_norm, 0))
            
        ep_indices = []
        for t in endpoint_history:
            ep_indices.append(ENDPOINT_INDEX.get(t.upper(), 0))

        # Pad TTP
        if len(indices) >= self._window_size:
            w_ttps = indices[-self._window_size:]
        else:
            w_ttps = [0] * (self._window_size - len(indices)) + indices
            
        # Pad Endpoint
        if len(ep_indices) >= self._window_size:
            w_endpoints = ep_indices[-self._window_size:]
        else:
            w_endpoints = [0] * (self._window_size - len(ep_indices)) + ep_indices
            
        return w_ttps, w_endpoints

    def _to_onehot(self, w_ttps: list[int], w_endpoints: list[int]):
        """Convert index windows to joint one-hot tensor (1, W, N_FEATURES)."""
        import torch
        t = torch.zeros(1, self._window_size, N_FEATURES)
        for i in range(self._window_size):
            ttp_idx = w_ttps[i]
            ep_idx = w_endpoints[i]
            if 0 <= ttp_idx < N_TTPS:
                t[0, i, ttp_idx] = 1.0
            if 0 <= ep_idx < N_ENDPOINT:
                # Offset endpoint index by N_TTPS
                t[0, i, N_TTPS + ep_idx] = 1.0
        return t
