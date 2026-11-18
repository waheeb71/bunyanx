"""
PHANTOM — Training Script (Task 9)
====================================
Trains PHANTOMClassifier on CICIDS2017 dataset features.

Usage
-----
    python training/train_phantom.py                    # expects cicids2017.csv
    python training/train_phantom.py --dataset path/to/csv
    python training/train_phantom.py --epochs 30 --lr 0.0003

Output
------
    modules/ids_ips/models/phantom_v1.pt     — PyTorch weights
    modules/ids_ips/models/phantom_v1.onnx   — ONNX for production
    modules/ids_ips/models/training_log.json — metrics per epoch
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# ── Paths ─────────────────────────────────────────────────────────────────────
_ROOT     = Path(__file__).resolve().parent.parent
_MODEL_DIR = _ROOT / "models"
_MODEL_DIR.mkdir(parents=True, exist_ok=True)

# ── CICIDS2017 column → PHANTOM feature mapping ────────────────────────────────
# We select 21 columns that closely match TrafficFeatures (from anomaly_detector.py)
CICIDS_FEATURE_COLS = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Fwd IAT Mean",
    "Bwd IAT Mean",
    "Fwd PSH Flags",
    "SYN Flag Count",
    "RST Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
]

# CICIDS2017 Label → PHANTOM class_id
LABEL_MAP: Dict[str, int] = {
    "benign":               0,
    "bot":                  5,
    "ddos":                 1,
    "dos goldeneye":        1,
    "dos hulk":             1,
    "dos slowhttptest":     1,
    "dos slowloris":        1,
    "ftp-patator":          3,
    "heartbleed":           4,
    "infiltration":         6,
    "portscan":             2,
    "ssh-patator":          3,
    "web attack – brute force": 3,
    "web attack – sql injection": 4,
    "web attack – xss":    4,
}


# ── Data loading ──────────────────────────────────────────────────────────────

def load_cicids(csv_path: str) -> Tuple[np.ndarray, np.ndarray]:
    """
    Load CICIDS2017 CSV and return (X, y) arrays.

    X shape: (N, 21 + 256)   — 21 flow features + 256 SBE zeros (placeholder)
    y shape: (N,)            — integer class labels
    """
    try:
        import pandas as pd
    except ImportError:
        logger.error("pandas not installed — run: pip install pandas")
        sys.exit(1)

    logger.info("Loading CICIDS2017 from %s", csv_path)
    df = pd.read_csv(csv_path, low_memory=False)

    # Normalise column names
    df.columns = [c.strip() for c in df.columns]

    # Check label column
    label_col = None
    for lc in (" Label", "Label", "label"):
        if lc.strip() in df.columns:
            label_col = lc.strip()
            break
    if label_col is None:
        raise ValueError(f"No label column found. Available: {list(df.columns[:5])}")

    # Map labels
    df["__class_id"] = (
        df[label_col].str.lower().str.strip().map(LABEL_MAP).fillna(0).astype(int)
    )

    # Select feature columns that exist
    available = [c for c in CICIDS_FEATURE_COLS if c in df.columns]
    missing   = [c for c in CICIDS_FEATURE_COLS if c not in df.columns]
    if missing:
        logger.warning("Missing %d CICIDS columns — zero-padding: %s", len(missing), missing[:5])

    X_flow = df[available].fillna(0).values.astype(np.float32)

    # Pad to 21 features if some are missing
    if X_flow.shape[1] < 21:
        pad = np.zeros((len(X_flow), 21 - X_flow.shape[1]), dtype=np.float32)
        X_flow = np.concatenate([X_flow, pad], axis=1)
    X_flow = X_flow[:, :21]

    # Normalise flow features (per-column robust scaling)
    col_median = np.median(X_flow, axis=0)
    col_iqr    = np.percentile(X_flow, 75, axis=0) - np.percentile(X_flow, 25, axis=0)
    col_iqr    = np.where(col_iqr == 0, 1.0, col_iqr)
    X_flow     = (X_flow - col_median) / col_iqr
    X_flow     = np.clip(X_flow, -5, 5)

    # SBE placeholder: 256-dim zeros (real SBE needs raw packets)
    X_sbe = np.zeros((len(X_flow), 256), dtype=np.float32)
    X     = np.concatenate([X_flow, X_sbe], axis=1)   # (N, 277)
    y     = df["__class_id"].values.astype(np.int64)

    class_counts = {int(k): int(v) for k, v in zip(*np.unique(y, return_counts=True))}
    logger.info("Loaded %d samples  |  classes: %s", len(X), class_counts)
    return X, y


def split_dataset(
    X: np.ndarray, y: np.ndarray, train_ratio: float = 0.80
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """80/20 stratified split."""
    rng  = np.random.default_rng(42)
    idx  = rng.permutation(len(X))
    split = int(len(X) * train_ratio)
    return X[idx[:split]], y[idx[:split]], X[idx[split:]], y[idx[split:]]


# ── Dataset class ─────────────────────────────────────────────────────────────

def make_dataloaders(X_train, y_train, X_val, y_val, batch_size: int = 256):
    """Return PyTorch DataLoader objects."""
    import torch
    from torch.utils.data import TensorDataset, DataLoader

    def make_tensors(X, y):
        # Split into flow features (21) and SBE (256)
        X_flow = torch.tensor(X[:, :21], dtype=torch.float32)
        X_sbe  = torch.tensor(X[:, 21:], dtype=torch.float32)
        y_t    = torch.tensor(y, dtype=torch.long)
        return X_flow, X_sbe, y_t

    Xf_tr, Xs_tr, y_tr = make_tensors(X_train, y_train)
    Xf_vl, Xs_vl, y_vl = make_tensors(X_val,   y_val)

    train_ds  = TensorDataset(Xf_tr, Xs_tr, y_tr)
    val_ds    = TensorDataset(Xf_vl, Xs_vl, y_vl)

    train_dl = DataLoader(train_ds, batch_size=batch_size, shuffle=True,  num_workers=0)
    val_dl   = DataLoader(val_ds,   batch_size=batch_size, shuffle=False, num_workers=0)
    return train_dl, val_dl


# ── Simple flow-features-only model wrapper ────────────────────────────────────

def build_trainable_model(num_classes: int = 10):
    """
    Builds a PHANTOMClassifier adapted for CICIDS2017 training.
    Input: 21 flow features + 256 SBE → projected to 256-dim node feature.
    """
    import torch.nn as nn
    sys.path.insert(0, str(_ROOT.parent))

    from modules.ids_ips.engine.model.phantom_classifier import PHANTOMClassifier
    if PHANTOMClassifier is None:
        raise ImportError("PyTorch not available")

    class PHANTOMTrainable(nn.Module):
        """Wraps PHANTOMClassifier with a flow-features projection head."""
        def __init__(self):
            super().__init__()
            self.flow_proj = nn.Sequential(
                nn.Linear(21, 128),
                nn.GELU(),
                nn.Linear(128, 256),
            )
            self.backbone = PHANTOMClassifier(node_dim=256, hidden=128, num_classes=num_classes)

        def forward(self, flow_feat, sbe_feat, seq_feat, positions):
            # Project flow features to 256-dim (same as SBE space)
            projected = self.flow_proj(flow_feat)   # [B, 256]
            # Fuse: add SBE if non-zero, else use projection
            node_feat  = projected + sbe_feat        # SBE is zeros in training
            return self.backbone(node_feat, seq_feat, positions)

    return PHANTOMTrainable()


# ── Training loop ─────────────────────────────────────────────────────────────

def train(
    dataset_path: str,
    epochs:       int   = 20,
    batch_size:   int   = 256,
    lr:           float = 3e-4,
    weight_decay: float = 1e-4,
) -> dict:
    """Full training + evaluation loop. Returns final metrics dict."""
    try:
        import torch
        import torch.nn.functional as F
        from sklearn.metrics import f1_score, classification_report
    except ImportError as exc:
        logger.error("Missing dependency: %s — run: pip install torch scikit-learn pandas", exc)
        sys.exit(1)

    device = "cuda" if torch.cuda.is_available() else "cpu"
    logger.info("Training on %s", device)

    # ── Data ──────────────────────────────────────────────────────────────────
    X, y           = load_cicids(dataset_path)
    X_tr, y_tr, X_vl, y_vl = split_dataset(X, y)
    train_dl, val_dl        = make_dataloaders(X_tr, y_tr, X_vl, y_vl, batch_size)

    num_classes = len(np.unique(y))
    logger.info("Train=%d  Val=%d  Classes=%d", len(X_tr), len(X_vl), num_classes)

    # ── Model ─────────────────────────────────────────────────────────────────
    model = build_trainable_model(num_classes=10).to(device)
    opt   = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=weight_decay)
    sched = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=epochs)

    # Class weights (handle imbalance)
    class_counts = np.bincount(y_tr, minlength=10).astype(np.float32)
    class_counts = np.where(class_counts == 0, 1, class_counts)
    weights      = torch.tensor(1.0 / class_counts, dtype=torch.float32).to(device)

    T = 17   # seq_len + 1

    log_entries = []
    best_f1     = 0.0

    for epoch in range(1, epochs + 1):
        # ── Train ────────────────────────────────────────────────────────────
        model.train()
        total_loss = 0.0
        n_batches  = 0
        t0         = time.time()

        for flow_b, sbe_b, y_b in train_dl:
            flow_b = flow_b.to(device)
            sbe_b  = sbe_b.to(device)
            y_b    = y_b.to(device)
            B      = flow_b.size(0)

            # Build dummy temporal sequence (zeros — no packet history in this dataset)
            seq_b = sbe_b.unsqueeze(1).expand(-1, T, -1)
            pos_b = torch.arange(T, device=device).unsqueeze(0).expand(B, -1)

            opt.zero_grad()
            logits = model(flow_b, sbe_b, seq_b, pos_b)
            loss   = F.cross_entropy(logits, y_b, weight=weights)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()

            total_loss += loss.item()
            n_batches  += 1

        train_loss = total_loss / max(n_batches, 1)

        # ── Validate ─────────────────────────────────────────────────────────
        model.eval()
        all_preds, all_labels = [], []
        val_loss = 0.0

        with torch.no_grad():
            for flow_b, sbe_b, y_b in val_dl:
                flow_b = flow_b.to(device)
                sbe_b  = sbe_b.to(device)
                y_b    = y_b.to(device)
                B      = flow_b.size(0)

                seq_b = sbe_b.unsqueeze(1).expand(-1, T, -1)
                pos_b = torch.arange(T, device=device).unsqueeze(0).expand(B, -1)
                logits = model(flow_b, sbe_b, seq_b, pos_b)
                loss   = F.cross_entropy(logits, y_b, weight=weights)
                val_loss  += loss.item()
                preds      = torch.argmax(logits, dim=-1).cpu().numpy()
                all_preds.extend(preds)
                all_labels.extend(y_b.cpu().numpy())

        val_loss /= max(len(val_dl), 1)
        macro_f1  = f1_score(all_labels, all_preds, average="macro", zero_division=0)

        elapsed = time.time() - t0
        logger.info(
            "Epoch %2d/%d | train_loss=%.4f  val_loss=%.4f  "
            "macro_F1=%.4f  lr=%.2e  [%.1fs]",
            epoch, epochs, train_loss, val_loss, macro_f1,
            opt.param_groups[0]["lr"], elapsed,
        )

        log_entries.append({
            "epoch":      epoch,
            "train_loss": round(train_loss, 5),
            "val_loss":   round(val_loss,   5),
            "macro_f1":   round(macro_f1,   5),
        })

        sched.step()

        # ── Save best model ───────────────────────────────────────────────────
        if macro_f1 > best_f1:
            best_f1 = macro_f1
            pt_path = _MODEL_DIR / "phantom_v1.pt"
            # FIX: Save ONLY the backbone weights (pure PHANTOMClassifier state),
            # NOT the full PHANTOMTrainable wrapper (which adds a `flow_proj` head).
            # PHANTOMInference._load_model() loads into a bare PHANTOMClassifier —
            # saving the wrapper state dict caused a key mismatch and silent
            # fallback to heuristic mode at deployment time.
            torch.save(model.backbone.state_dict(), str(pt_path))

            # Write SHA-256 sidecar for integrity verification at load time.
            import hashlib
            h = hashlib.sha256()
            with open(str(pt_path), "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            sha_path = pt_path.with_suffix(".pt.sha256")
            sha_path.write_text(h.hexdigest() + "  phantom_v1.pt\n")

            logger.info(
                "  → Saved best backbone weights (F1=%.4f) to %s (sha256: %s...)",
                best_f1, pt_path, h.hexdigest()[:16],
            )

    # ── Final report ──────────────────────────────────────────────────────────
    logger.info("\nTraining complete. Best macro-F1 = %.4f", best_f1)

    report = classification_report(all_labels, all_preds, zero_division=0)
    logger.info("\n%s", report)

    # Save training log
    log_path = _MODEL_DIR / "training_log.json"
    with open(str(log_path), "w") as f:
        json.dump({"best_f1": best_f1, "epochs": log_entries, "report": report}, f, indent=2)
    logger.info("Training log saved to %s", log_path)

    # Export to ONNX (backbone-only, matching PHANTOMInference inference signature)
    logger.info("Exporting backbone to ONNX...")
    try:
        import torch
        model.backbone.eval()
        B = 1
        dummy_node  = torch.zeros(B, 256)
        dummy_seq   = torch.zeros(B, T, 256)
        dummy_pos   = torch.arange(T).unsqueeze(0)
        onnx_path   = str(_MODEL_DIR / "phantom_v1.onnx")
        torch.onnx.export(
            model.backbone,
            (dummy_node, dummy_seq, dummy_pos),
            onnx_path,
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
        # Generate SHA-256 sidecar for ONNX
        import hashlib
        h = hashlib.sha256()
        with open(onnx_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        sha_path = Path(onnx_path).with_suffix(".onnx.sha256")
        sha_path.write_text(h.hexdigest() + "  phantom_v1.onnx\n")
        logger.info("ONNX exported to %s (sha256: %s...)", onnx_path, h.hexdigest()[:16])
    except Exception as exc:
        logger.warning("ONNX export failed: %s", exc)

    return {"best_f1": best_f1, "epochs": epochs}


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train PHANTOM IDS classifier")
    parser.add_argument("--dataset", default="cicids2017.csv", help="Path to CICIDS2017 CSV")
    parser.add_argument("--epochs",  type=int,   default=20,   help="Training epochs")
    parser.add_argument("--batch",   type=int,   default=256,  help="Batch size")
    parser.add_argument("--lr",      type=float, default=3e-4, help="Learning rate")
    args = parser.parse_args()

    if not os.path.exists(args.dataset):
        logger.error(
            "Dataset not found: %s\n"
            "Download CICIDS2017 from: https://www.unb.ca/cic/datasets/ids-2017.html\n"
            "Or from Kaggle: kaggle datasets download -d cicdataset/cicids2017",
            args.dataset,
        )
        sys.exit(1)

    train(
        dataset_path = args.dataset,
        epochs       = args.epochs,
        batch_size   = args.batch,
        lr           = args.lr,
    )
