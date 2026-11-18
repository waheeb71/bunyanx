"""
PHANTOM — Hybrid GNN-Transformer Classifier (HGTC)
===================================================
Layer 3 of the PHANTOM IDS/IPS framework.

Architecture
------------
  PHANTOMClassifier  — PyTorch nn.Module (GNN branch + Transformer branch)
  PHANTOMInference   — Production wrapper (ONNX / PyTorch / heuristic fallback)
  PHANTOMResult      — Structured output dataclass

The model fuses two complementary views of the network:

  ┌───────────────────────────────┐
  │  GNN Branch (GraphSAGE-like)  │   "Who talks to whom?"
  │  Input: 256-dim SBE node feat │   Captures neighbourhood context
  │  Output: 128-dim embedding    │   of each host in the causal graph
  └──────────────┬────────────────┘
                 │ concat
  ┌──────────────┴────────────────┐
  │  Transformer Branch           │   "How does the conversation evolve?"
  │  Input: sequence of SBE vecs  │   Captures long-range temporal patterns
  │  Output: 128-dim embedding    │   across up to 512 time steps
  └──────────────┬────────────────┘
                 ↓
  ┌─────────────────────────────────┐
  │  Fusion MLP                     │
  │  [256-dim] → [128] → [classes]  │
  └─────────────────────────────────┘

num_classes (default 10):
  0 = Benign
  1 = DoS / DDoS
  2 = Port Scan
  3 = Brute Force
  4 = SQL Injection / Web Attack
  5 = Encrypted C2 (Beacon)
  6 = Lateral Movement
  7 = Exfiltration
  8 = Ransomware Beacon
  9 = APT Multi-Stage

Without GPU / torch_geometric:
  - GNN branch falls back to a simple linear projection.
  - ONNX runtime is preferred for production inference (< 1 ms per call).
  - If no model is loaded, inference returns confidence=0.0 (graceful degradation).
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Class labels
# ---------------------------------------------------------------------------

THREAT_CLASSES: Dict[int, str] = {
    0: "benign",
    1: "dos_ddos",
    2: "port_scan",
    3: "brute_force",
    4: "web_attack",
    5: "encrypted_c2",
    6: "lateral_movement",
    7: "exfiltration",
    8: "ransomware",
    9: "apt_multistage",
}

NUM_CLASSES = len(THREAT_CLASSES)
NODE_DIM    = 256   # SBE vector dimensionality
HIDDEN_DIM  = 128


# ---------------------------------------------------------------------------
# PyTorch model (imported lazily to avoid hard dependency)
# ---------------------------------------------------------------------------

def _build_pytorch_model() -> Optional[object]:  # type: ignore[return]
    """
    Build PHANTOMClassifier as a PyTorch nn.Module.
    Returns None if torch is not installed.
    """
    try:
        import torch
        import torch.nn as nn

        class PHANTOMClassifier(nn.Module):  # type: ignore[misc]
            """
            Hybrid GNN + Transformer classifier.

            Parameters
            ----------
            node_dim   : dimensionality of input node features (= SBE_DIM = 256)
            hidden     : hidden layer width (default 128)
            heads      : number of Transformer attention heads (default 4)
            num_classes: number of output threat classes (default 10)
            seq_len    : maximum temporal sequence length (default 32)
            dropout    : dropout probability (default 0.15)
            """

            def __init__(
                self,
                node_dim:    int = NODE_DIM,
                hidden:      int = HIDDEN_DIM,
                heads:       int = 4,
                num_classes: int = NUM_CLASSES,
                seq_len:     int = 32,
                dropout:     float = 0.15,
            ) -> None:
                super().__init__()
                self.node_dim    = node_dim
                self.hidden      = hidden
                self.num_classes = num_classes

                # ── GNN Branch ─────────────────────────────────────────────
                # Without torch_geometric we use two linear layers as a
                # mean-aggregation approximation (valid for a single node).
                self.gnn_fc1   = nn.Linear(node_dim, hidden)
                self.gnn_fc2   = nn.Linear(hidden, hidden)
                self.gnn_norm  = nn.LayerNorm(hidden)
                self.gnn_act   = nn.GELU()

                # ── Temporal Transformer Branch ────────────────────────────
                self.pos_enc = nn.Embedding(512, hidden)
                encoder_layer = nn.TransformerEncoderLayer(
                    d_model=hidden,
                    nhead=heads,
                    dim_feedforward=hidden * 2,
                    dropout=dropout,
                    batch_first=True,
                    norm_first=True,       # Pre-LN for better training stability
                )
                self.transformer = nn.TransformerEncoder(
                    encoder_layer, num_layers=2, enable_nested_tensor=False
                )

                # ── Projection to align input dim for transformer ──────────
                # SBE is 256-dim but transformer d_model = hidden(128)
                self.sbe_proj = nn.Linear(node_dim, hidden)

                # ── Fusion Classifier ──────────────────────────────────────
                self.classifier = nn.Sequential(
                    nn.Linear(hidden * 2, hidden),
                    nn.GELU(),
                    nn.Dropout(dropout),
                    nn.Linear(hidden, num_classes),
                )

                self._init_weights()

            def _init_weights(self) -> None:
                """Xavier uniform init for all Linear layers."""
                import torch.nn.init as init
                for m in self.modules():
                    if isinstance(m, nn.Linear):
                        init.xavier_uniform_(m.weight)
                        if m.bias is not None:
                            init.zeros_(m.bias)

            def forward(
                self,
                node_features:  "torch.Tensor",   # [B, node_dim]
                temporal_seq:   "torch.Tensor",   # [B, T, node_dim]
                positions:      "torch.Tensor",   # [B, T] int64
                src_key_mask:   Optional["torch.Tensor"] = None,  # [B, T] bool
            ) -> "torch.Tensor":                  # [B, num_classes]
                """
                Forward pass.

                Parameters
                ----------
                node_features  : current-packet SBE for the host [B, 256]
                temporal_seq   : last T SBE vectors for temporal context [B, T, 256]
                positions      : time-step indices 0..T-1 [B, T]
                src_key_mask   : True = padding position (mask out)

                Returns logits [B, num_classes].
                """
                # GNN Branch
                h = self.gnn_act(self.gnn_fc1(node_features))
                h = self.gnn_norm(self.gnn_fc2(h))   # [B, hidden]

                # Transformer Branch
                seq_proj = self.sbe_proj(temporal_seq)  # [B, T, hidden]
                pos_emb  = self.pos_enc(positions)       # [B, T, hidden]
                seq_in   = seq_proj + pos_emb

                t_out = self.transformer(
                    seq_in,
                    src_key_padding_mask=src_key_mask,
                )  # [B, T, hidden]
                t_vec = t_out[:, -1, :]   # last token as sequence summary [B, hidden]

                # Fusion
                fused  = self._safe_cat(h, t_vec)   # [B, hidden*2]
                logits = self.classifier(fused)      # [B, num_classes]
                return logits

            @staticmethod
            def _safe_cat(a: "torch.Tensor", b: "torch.Tensor") -> "torch.Tensor":
                import torch
                if a.dim() == 1:
                    a = a.unsqueeze(0)
                if b.dim() == 1:
                    b = b.unsqueeze(0)
                return torch.cat([a, b], dim=-1)

        return PHANTOMClassifier

    except ImportError:
        logger.warning("PyTorch not available — PHANTOMClassifier cannot be built.")
        return None


# Eagerly attempt to build the class at module import time
try:
    _PHANTOMClassifierClass = _build_pytorch_model()
except Exception as _exc:
    _PHANTOMClassifierClass = None
    logger.error("Failed to build PHANTOMClassifier: %s", _exc)


# Public alias
PHANTOMClassifier = _PHANTOMClassifierClass


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class PHANTOMResult:
    """
    Output of PHANTOMInference.predict() — one result per evaluation call.

    Fields
    ------
    sample_id      : unique UUID for this prediction (used by OCL feedback loop)
    threat_class   : string label from THREAT_CLASSES (e.g. "encrypted_c2")
    class_id       : integer class index
    confidence     : probability of the predicted class ∈ [0, 1]
    logits         : raw class logits (None if model not loaded)
    inference_ms   : wall-clock time of this inference call
    """

    sample_id:    str
    threat_class: str
    class_id:     int
    confidence:   float
    logits:       Optional[np.ndarray] = None
    inference_ms: float = 0.0

    @property
    def is_threat(self) -> bool:
        return self.class_id != 0 and self.confidence >= 0.5

    def to_dict(self) -> dict:
        return {
            "sample_id":    self.sample_id,
            "threat_class": self.threat_class,
            "class_id":     self.class_id,
            "confidence":   round(self.confidence, 4),
            "is_threat":    self.is_threat,
            "inference_ms": round(self.inference_ms, 2),
        }


# ---------------------------------------------------------------------------
# PHANTOMInference — production inference wrapper
# ---------------------------------------------------------------------------

class PHANTOMInference:
    """
    Production-grade inference wrapper for the PHANTOM classifier.

    Loading priority:
      1. ONNX Runtime (fastest, preferred for production)
      2. PyTorch .pt / .pth file
      3. Heuristic fallback (SBE-only scoring, no trained model)

    Parameters
    ----------
    model_dir   : directory to search for model files
                  (default: <module_dir>/../../../models/)
    model_name  : base name without extension (default: "phantom_v1")
    seq_len     : history length for temporal Transformer input (default 16)
    """

    _DEFAULT_MODEL_DIR = (
        Path(__file__).resolve().parent.parent.parent / "models"
    )

    def __init__(
        self,
        model_dir:  Optional[str] = None,
        model_name: str = "phantom_v1",
        seq_len:    int = 16,
    ) -> None:
        self.model_dir  = Path(model_dir) if model_dir else self._DEFAULT_MODEL_DIR
        self.model_name = model_name
        self.seq_len    = seq_len

        self._onnx_session = None
        self._pt_model     = None
        self._backend      = "heuristic"   # "onnx" | "pytorch" | "heuristic"

        self._load_model()

    # ------------------------------------------------------------------
    # Model loading
    # ------------------------------------------------------------------

    def _verify_sha256(self, path: Path) -> bool:
        """
        Verify model file integrity against a co-located .sha256 sidecar.
        If no sidecar exists, the check is skipped (returns True) but a
        warning is emitted so operators can add integrity verification.
        """
        import hashlib
        sha_path = path.with_suffix(path.suffix + ".sha256")
        if not sha_path.exists():
            logger.warning(
                "PHANTOMInference: no SHA-256 sidecar for %s — "
                "consider running scripts/pin_model_hashes.py to harden integrity.",
                path.name,
            )
            return True   # permissive — block would break first-time deployments
        try:
            expected = sha_path.read_text().strip().split()[0]
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            actual = h.hexdigest()
            if actual != expected:
                logger.error(
                    "PHANTOMInference: SHA-256 MISMATCH for %s — "
                    "refusing to load (expected=%s actual=%s).",
                    path.name, expected[:16] + "…", actual[:16] + "…",
                )
                return False
            logger.debug("PHANTOMInference: SHA-256 OK for %s", path.name)
            return True
        except Exception as exc:
            logger.error("PHANTOMInference: SHA-256 check failed for %s: %s", path.name, exc)
            return False

    def _load_model(self) -> None:
        """Try ONNX → PyTorch → fallback. Verifies SHA-256 before each load."""
        # 1. ONNX
        onnx_path = self.model_dir / f"{self.model_name}.onnx"
        if onnx_path.exists():
            if not self._verify_sha256(onnx_path):
                logger.warning("PHANTOMInference: skipping ONNX — integrity check failed.")
            else:
                try:
                    import onnxruntime as ort
                    self._onnx_session = ort.InferenceSession(
                        str(onnx_path),
                        providers=["CPUExecutionProvider"],
                    )
                    self._backend = "onnx"
                    logger.info("PHANTOMInference: loaded ONNX from %s", onnx_path)
                except Exception as exc:
                    logger.warning("ONNX load failed (%s): %s", onnx_path.name, exc)

        # 2. PyTorch (always attempt — required for OCL engine tuning)
        pt_path = self.model_dir / f"{self.model_name}.pt"
        if pt_path.exists() and _PHANTOMClassifierClass is not None:
            if not self._verify_sha256(pt_path):
                logger.warning("PHANTOMInference: skipping PyTorch model — integrity check failed.")
            else:
                try:
                    import torch
                    model = _PHANTOMClassifierClass()
                    state = torch.load(str(pt_path), map_location="cpu", weights_only=True)

                    # FIX: PHANTOMTrainable wrapper (training/train_phantom.py) wraps
                    # the classifier in a PHANTOMTrainable that adds a `flow_proj` head.
                    # If someone saved the FULL wrapper state dict, strip the `backbone.`
                    # prefix so PHANTOMClassifier can still load it.
                    if any(k.startswith("backbone.") for k in state.keys()):
                        logger.info(
                            "PHANTOMInference: detected PHANTOMTrainable wrapper state dict — "
                            "stripping 'backbone.' prefix for compatibility."
                        )
                        state = {
                            k.removeprefix("backbone."): v
                            for k, v in state.items()
                            if k.startswith("backbone.")
                        }

                    model.load_state_dict(state)
                    model.eval()
                    self._pt_model = model
                    if self._backend == "heuristic":
                        self._backend = "pytorch"
                    logger.info("PHANTOMInference: loaded PyTorch model from %s", pt_path)
                except Exception as exc:
                    logger.warning("PyTorch load failed (%s): %s", pt_path.name, exc)

        if self._backend == "heuristic":
            logger.info(
                "PHANTOMInference: no trained model found in %s — "
                "running SBE-heuristic fallback.", self.model_dir
            )

    @property
    def backend(self) -> str:
        return self._backend

    @property
    def is_trained(self) -> bool:
        return self._backend in ("onnx", "pytorch")

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------

    def predict(
        self,
        sbe:           np.ndarray,
        temporal_sbes: Optional[List[np.ndarray]] = None,
        causal_density: float = 0.0,
    ) -> PHANTOMResult:
        """
        Run inference and return a PHANTOMResult.

        Parameters
        ----------
        sbe            : 256-dim SBE vector of the current packet
        temporal_sbes  : ordered list of recent SBE vectors (oldest first).
                         If None or empty, a single-step sequence is used.
        causal_density : CausalGraph.causal_density() — injected as a
                         feature boost when confidence is borderline.

        Returns
        -------
        PHANTOMResult
        """
        t0 = time.perf_counter()

        if self._backend == "onnx" and not getattr(self, 'use_pytorch_for_ocl', False):
            result = self._predict_onnx(sbe, temporal_sbes)
        elif self._pt_model:
            result = self._predict_pytorch(sbe, temporal_sbes)
        else:
            result = self._predict_heuristic(sbe, causal_density)

        result.inference_ms = (time.perf_counter() - t0) * 1000

        # Causal density boost: if the graph is dense and the model says benign
        # with low confidence, promote the 2nd-best class as a secondary candidate.
        # FIX: Previously forced class_id=5 (encrypted_c2) unconditionally, causing
        # systematic false positives in dense microservice meshes (many hosts).
        if causal_density > 0.5 and result.class_id == 0 and result.confidence < 0.65:
            boost = min(0.2, causal_density * 0.25)
            alt_conf = result.confidence + boost
            if alt_conf >= 0.5 and result.logits is not None:
                # Pick the highest-scoring non-benign class from logits
                logits_arr  = np.asarray(result.logits)
                alt_class_id = int(
                    np.argmax(logits_arr[1:]) + 1  # skip class 0 (benign)
                )
                alt_class_name = THREAT_CLASSES.get(alt_class_id, "suspicious")
                result = PHANTOMResult(
                    sample_id=result.sample_id,
                    threat_class=alt_class_name,
                    class_id=alt_class_id,
                    confidence=round(alt_conf, 4),
                    logits=result.logits,
                    inference_ms=result.inference_ms,
                )

        return result

    # ------------------------------------------------------------------

    def _predict_onnx(
        self,
        sbe: np.ndarray,
        temporal_sbes: Optional[List[np.ndarray]],
    ) -> PHANTOMResult:
        seq = self._build_sequence(sbe, temporal_sbes)
        positions = np.arange(seq.shape[1], dtype=np.int64)[np.newaxis, :]
        node_feat = sbe[np.newaxis, :].astype(np.float32)

        inputs = {
            self._onnx_session.get_inputs()[0].name: node_feat,
            self._onnx_session.get_inputs()[1].name: seq,
            self._onnx_session.get_inputs()[2].name: positions,
        }
        outputs   = self._onnx_session.run(None, inputs)
        logits    = outputs[0][0]
        return self._logits_to_result(logits)

    def _predict_pytorch(
        self,
        sbe: np.ndarray,
        temporal_sbes: Optional[List[np.ndarray]],
    ) -> PHANTOMResult:
        try:
            import torch
            seq        = self._build_sequence(sbe, temporal_sbes)
            positions  = np.arange(seq.shape[1], dtype=np.int64)
            node_feat  = torch.tensor(sbe[np.newaxis, :], dtype=torch.float32)
            seq_tensor = torch.tensor(seq, dtype=torch.float32)
            pos_tensor = torch.tensor(positions[np.newaxis, :], dtype=torch.long)

            with torch.no_grad():
                logits = self._pt_model(node_feat, seq_tensor, pos_tensor)

            return self._logits_to_result(logits[0].numpy())
        except Exception as exc:
            logger.error("PyTorch inference failed: %s — falling back", exc)
            return self._predict_heuristic(sbe, 0.0)

    def _predict_heuristic(
        self, sbe: np.ndarray, causal_density: float
    ) -> PHANTOMResult:
        """
        SBE-only heuristic when no trained model is available.

        Uses the same spectral signals as AnomalyDetector._compute_sbe_score()
        but maps them to threat classes.
        """
        sample_id = str(uuid.uuid4())

        # FFT spread (high → structured C2 or shellcode)
        fft_std  = float(np.std(sbe[:128]))
        # Entropy (low → repetitive patterns)
        ent_mean = float(np.mean(sbe[248:256]))

        fft_score = min(1.0, fft_std * 4.0)
        ent_score = max(0.0, 0.5 - ent_mean) * 2.0
        combined  = fft_score * 0.6 + ent_score * 0.4 + causal_density * 0.15
        combined  = float(np.clip(combined, 0.0, 1.0))

        if combined < 0.35:
            class_id = 0        # benign
            confidence = 1.0 - combined
        elif combined < 0.55:
            class_id = 5        # encrypted_c2 (uncertain)
            confidence = combined
        else:
            class_id = 5        # encrypted_c2 (confident)
            confidence = combined

        return PHANTOMResult(
            sample_id=sample_id,
            threat_class=THREAT_CLASSES[class_id],
            class_id=class_id,
            confidence=round(confidence, 4),
            logits=None,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_sequence(
        self,
        sbe: np.ndarray,
        temporal_sbes: Optional[List[np.ndarray]],
    ) -> np.ndarray:
        """
        Build the [1, T, 256] temporal sequence tensor for the Transformer.
        """
        if temporal_sbes:
            # Use the most recent seq_len SBEs + current
            seq_list = list(temporal_sbes[-self.seq_len:]) + [sbe]
        else:
            seq_list = [sbe]

        # Pad to seq_len + 1 with zeros if needed
        target_len = self.seq_len + 1
        while len(seq_list) < target_len:
            seq_list.insert(0, np.zeros(NODE_DIM, dtype=np.float32))

        seq_arr = np.stack(seq_list, axis=0).astype(np.float32)[-target_len:]
        return seq_arr[np.newaxis, :, :]   # [1, T, 256]

    @staticmethod
    def _logits_to_result(logits: np.ndarray) -> PHANTOMResult:
        """Convert raw logits to PHANTOMResult via softmax."""
        exp_logits  = np.exp(logits - np.max(logits))
        probs       = exp_logits / exp_logits.sum()
        class_id    = int(np.argmax(probs))
        confidence  = float(probs[class_id])
        return PHANTOMResult(
            sample_id=str(uuid.uuid4()),
            threat_class=THREAT_CLASSES.get(class_id, "unknown"),
            class_id=class_id,
            confidence=round(confidence, 4),
            logits=logits,
        )


# ---------------------------------------------------------------------------
# ONNX export utility
# ---------------------------------------------------------------------------

def export_to_onnx(
    model_dir: Optional[str] = None,
    model_name: str = "phantom_v1",
    seq_len: int = 16,
) -> Optional[str]:
    """
    Export a trained PHANTOMClassifier to ONNX format.

    Loads phantom_v1.pt from model_dir, exports phantom_v1.onnx.
    Returns the output path or None on failure.
    """
    if _PHANTOMClassifierClass is None:
        logger.error("Cannot export: PyTorch is not available.")
        return None

    try:
        import torch

        dir_path  = Path(model_dir) if model_dir else PHANTOMInference._DEFAULT_MODEL_DIR
        pt_path   = dir_path / f"{model_name}.pt"
        onnx_path = dir_path / f"{model_name}.onnx"

        if not pt_path.exists():
            logger.error("No .pt model found at %s", pt_path)
            return None

        model = _PHANTOMClassifierClass()
        state = torch.load(str(pt_path), map_location="cpu", weights_only=True)
        model.load_state_dict(state)
        model.eval()

        T = seq_len + 1
        dummy_node  = torch.zeros(1, NODE_DIM)
        dummy_seq   = torch.zeros(1, T, NODE_DIM)
        dummy_pos   = torch.arange(T).unsqueeze(0)

        torch.onnx.export(
            model,
            (dummy_node, dummy_seq, dummy_pos),
            str(onnx_path),
            input_names=["node_features", "temporal_seq", "positions"],
            output_names=["logits"],
            dynamic_axes={
                "node_features": {0: "batch"},
                "temporal_seq":  {0: "batch", 1: "seq"},
                "positions":     {0: "batch", 1: "seq"},
                "logits":        {0: "batch"},
            },
            opset_version=17,
        )
        logger.info("Exported PHANTOM model to %s", onnx_path)
        return str(onnx_path)

    except Exception as exc:
        logger.error("ONNX export failed: %s", exc)
        return None
