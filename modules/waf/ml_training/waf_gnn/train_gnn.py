"""
Enterprise bunyanx — WAF GNN (Graph Convolutional Network) Training Script

Trains a 2-layer GCN (WAFGNNModel) on session log graphs for session-level
threat classification (benign=0 / attack=1).

Dataset: session_logs.csv (collected by SessionLogCollector at runtime)
Each session → a directed graph where nodes are HTTP requests and
edges connect temporally adjacent requests.

Node features (7-dim — matches WAFGNNInference):
    0  request_length      (payload_bytes)
    1  payload_entropy     (Shannon entropy of path)
    2  special_char_ratio  (special chars in path / path length)
    3  sql_keyword_count   (SQL keywords in path)
    4  xss_keyword_count   (XSS patterns in path)
    5  encoding_layer_count (response_code > 400 proxy)
    6  has_null_byte        (latency_ms outlier proxy)
"""

import os
import sys
import time
import math
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader

# ── Path resolution ──────────────────────────────────────────────────────────
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from modules.waf.ml_training.waf_gnn.model import WAFGNNModel

SESSION_CSV = os.path.join(project_root, "modules/waf/ml_training/waf_gnn/datasets/session_logs.csv")
SAVE_PATH   = os.path.join(project_root, "ml/models/waf/gnn_model.pt")

# SQL / XSS keyword lists for feature engineering
_SQL_KW = ["select", "union", "insert", "drop", "where", "from", "exec", "--", "/*", "xp_"]
_XSS_KW = ["<script", "javascript:", "onerror", "onload", "alert(", "document.cookie"]


# ── Feature engineering ──────────────────────────────────────────────────────

def _entropy(s: str) -> float:
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def extract_node_features(row: pd.Series) -> np.ndarray:
    """Map a session log row to a 7-dim node feature vector."""
    path   = str(row.get("path", "/"))
    pl     = float(row.get("payload_bytes", 0))
    rc     = float(row.get("response_code", 200))
    lat    = float(row.get("latency_ms", 0))
    plen   = max(len(path), 1)

    f0 = min(pl, 10000.0) / 10000.0                              # request_length (norm)
    f1 = _entropy(path)                                           # payload_entropy
    f2 = sum(1 for c in path if not c.isalnum() and c not in "/-_.") / plen  # special_char_ratio
    f3 = float(sum(kw in path.lower() for kw in _SQL_KW))        # sql_keyword_count
    f4 = float(sum(kw in path.lower() for kw in _XSS_KW))        # xss_keyword_count
    f5 = 1.0 if rc >= 400 else 0.0                               # encoding_layer_count proxy
    f6 = 1.0 if lat > 200.0 else 0.0                             # has_null_byte / outlier proxy

    return np.array([f0, f1, f2, f3, f4, f5, f6], dtype=np.float32)


# ── Dataset ──────────────────────────────────────────────────────────────────

class SessionGraphDataset(Dataset):
    """
    Groups session_logs by session_id, builds a graph per session,
    and labels it based on response codes (≥400 → attack).
    """
    def __init__(self, csv_path: str, max_seq_len: int = 50):
        self.max_seq_len = max_seq_len
        self.graphs: list[tuple[np.ndarray, np.ndarray, int]] = []  # (X, A_norm, label)
        self._build(csv_path)

    def _build(self, csv_path: str):
        df = pd.read_csv(csv_path)
        sessions = df.groupby("session_id")

        for sid, grp in sessions:
            grp = grp.sort_values("timestamp") if "timestamp" in grp.columns else grp
            rows = [extract_node_features(row) for _, row in grp.iterrows()]
            seq_len = len(rows)

            # Pad / truncate to max_seq_len
            X = np.zeros((self.max_seq_len, 7), dtype=np.float32)
            n = min(seq_len, self.max_seq_len)
            X[:n] = np.stack(rows[:n])

            # Build temporal adjacency matrix (sequential edges + self-loops)
            A = np.eye(self.max_seq_len, dtype=np.float32)
            for i in range(n - 1):
                A[i, i + 1] = 1.0
                A[i + 1, i] = 1.0

            # Symmetric normalisation: D^{-1/2} A D^{-1/2}
            row_sum = A.sum(axis=1)
            inv_sqrt = np.where(row_sum > 0, np.power(row_sum, -0.5), 0.0)
            D_inv = np.diag(inv_sqrt)
            A_norm = D_inv @ A @ D_inv

            # Label: session is an attack if any request returned 4xx/5xx
            has_attack = int((grp["response_code"] >= 400).any())
            self.graphs.append((X, A_norm, has_attack))

    def __len__(self) -> int:
        return len(self.graphs)

    def __getitem__(self, idx: int):
        X, A, label = self.graphs[idx]
        return (
            torch.tensor(X, dtype=torch.float32),
            torch.tensor(A, dtype=torch.float32),
            torch.tensor(float(label), dtype=torch.float32),
        )


# ── Training loop ─────────────────────────────────────────────────────────────

def train_gnn(epochs: int = 20, batch_size: int = 32, lr: float = 1e-3):
    print("=" * 60)
    print("  bunyanx WAF GNN — Session Graph Training")
    print("=" * 60)
    t0 = time.time()

    # ── Dataset ──────────────────────────────────────────────────
    print("\n[1/4] Building session graphs...")
    dataset = SessionGraphDataset(SESSION_CSV, max_seq_len=50)
    n = len(dataset)
    print(f"  Total sessions: {n}")
    if n < 5:
        print("  ⚠  Dataset too small — generating synthetic sessions for training...")
        dataset = _augment_dataset(dataset, target=200)
        n = len(dataset)
        print(f"  Augmented to {n} sessions")

    # ── Train / val split ─────────────────────────────────────────
    split = max(1, int(0.8 * n))
    train_ds = torch.utils.data.Subset(dataset, range(split))
    val_ds   = torch.utils.data.Subset(dataset, range(split, n))

    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
    val_loader   = DataLoader(val_ds,   batch_size=batch_size, shuffle=False)
    print(f"  Train: {len(train_ds)} | Val: {len(val_ds)}")

    # ── Model ─────────────────────────────────────────────────────
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"\n[2/4] Training on device: {device}")
    model = WAFGNNModel(in_features=7, hidden_dim=32, out_features=1).to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=lr)
    loss_fn   = nn.BCELoss()

    best_val_loss = float("inf")

    for epoch in range(epochs):
        model.train()
        total_loss = 0.0; correct = 0; total = 0

        for X_batch, A_batch, y_batch in train_loader:
            X_batch = X_batch.to(device)
            A_batch = A_batch.to(device)
            y_batch = y_batch.unsqueeze(1).to(device)

            optimizer.zero_grad()
            preds = model(X_batch, A_batch)
            loss  = loss_fn(preds, y_batch)
            loss.backward()
            optimizer.step()

            total_loss += loss.item()
            correct    += ((preds >= 0.5).float() == y_batch).sum().item()
            total      += y_batch.size(0)

        train_acc = correct / max(total, 1)

        # Validation
        model.eval()
        val_loss = 0.0; vc = 0; vt = 0
        with torch.no_grad():
            for X_b, A_b, y_b in val_loader:
                X_b = X_b.to(device); A_b = A_b.to(device)
                y_b = y_b.unsqueeze(1).to(device)
                p   = model(X_b, A_b)
                val_loss += loss_fn(p, y_b).item()
                vc += ((p >= 0.5).float() == y_b).sum().item()
                vt += y_b.size(0)

        val_acc  = vc / max(vt, 1)
        avg_vl   = val_loss / max(len(val_loader), 1)
        print(f"  Epoch {epoch+1:2d}/{epochs} | "
              f"Train Acc: {train_acc*100:.1f}% | "
              f"Val Acc: {val_acc*100:.1f}% | "
              f"Val Loss: {avg_vl:.4f}")

        if avg_vl < best_val_loss:
            best_val_loss = avg_vl
            os.makedirs(os.path.dirname(SAVE_PATH), exist_ok=True)
            checkpoint = {
                "model_state": model.state_dict(),
                "in_features": 7,
                "hidden_dim":  32,
                "epoch":       epoch + 1,
                "val_acc":     val_acc,
            }
            torch.save(checkpoint, SAVE_PATH)
            print(f"    [OK] Checkpoint saved (val_acc={val_acc*100:.1f}%)")

    elapsed = time.time() - t0
    print(f"\n{'=' * 60}")
    print(f"  GNN training complete in {elapsed:.1f}s")
    print(f"  Best val loss: {best_val_loss:.4f}")
    print(f"  Model saved: {SAVE_PATH}")
    print(f"{'=' * 60}")


def _augment_dataset(dataset: SessionGraphDataset, target: int = 200) -> SessionGraphDataset:
    """Generate synthetic sessions when real dataset is too small."""
    rng = np.random.default_rng(42)
    while len(dataset.graphs) < target:
        is_attack = rng.integers(0, 2)
        seq_len   = rng.integers(3, 20)
        X = rng.random((50, 7)).astype(np.float32)
        if is_attack:
            # Boost SQL/XSS features for attacks
            X[:seq_len, 3] = rng.uniform(1, 5, seq_len)
            X[:seq_len, 4] = rng.uniform(0, 3, seq_len)
            X[:seq_len, 5] = 1.0
        A = np.eye(50, dtype=np.float32)
        for i in range(seq_len - 1):
            A[i, i+1] = A[i+1, i] = 1.0
        row_sum = A.sum(1)
        inv_sq  = np.where(row_sum > 0, row_sum ** -0.5, 0.0)
        A_norm  = np.diag(inv_sq) @ A @ np.diag(inv_sq)
        dataset.graphs.append((X, A_norm, int(is_attack)))
    return dataset


if __name__ == "__main__":
    epochs = int(sys.argv[1]) if len(sys.argv) > 1 else 20
    train_gnn(epochs=epochs)
