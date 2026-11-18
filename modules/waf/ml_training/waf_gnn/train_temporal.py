"""
Enterprise bunyanx WAF — Temporal BiLSTM Training Script (Multi-File)

Improvements over v1:
- Loads ALL 10 CIC-IDS2018 CSV files (skips 02-20 — 4GB, too heavy for CPU)
- Augments with UNSW-NB15 training set for additional attack diversity
- Class-balanced sampling to handle benign/attack ratio
- 3 training epochs (was 1)
- Per-file progress reporting
"""

import os
import sys
import time
import glob

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import pandas as pd
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from torch.optim import AdamW
from modules.waf.ml_training.waf_gnn.model import TemporalBiLSTM


# ── Dataset paths ───────────────────────────────────────────────────────────
CIC_DIR  = os.path.join(project_root, "ml/data/CSE-CIC-IDS2018")
UNSW_CSV = os.path.join(project_root, "ml/data/NUSW-NB15/UNSW_NB15_training-set.csv")
SAVE_PATH = os.path.join(project_root, "ml/models/waf/temporal_lstm.pt")

# Skip the 4GB file on CPU — it would take hours
SKIP_FILES = {"02-20-2018.csv"}


class TemporalIDSDataset(Dataset):
    def __init__(self, X, y):
        self.X = torch.tensor(X, dtype=torch.float32)
        self.y = torch.tensor(y, dtype=torch.float32).unsqueeze(1)

    def __len__(self):
        return len(self.X)

    def __getitem__(self, idx):
        return self.X[idx], self.y[idx]


def load_cic_file(csv_path: str, seq_len: int = 10, stride: int = 5):
    """Load one CIC-IDS2018 CSV and return sliding-window arrays."""
    cols = [
        'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
        'TotLen Fwd Pkts', 'TotLen Bwd Pkts',
        'Fwd Pkt Len Mean', 'Bwd Pkt Len Mean', 'Label'
    ]
    try:
        df = pd.read_csv(csv_path, usecols=cols, low_memory=False,
                         encoding_errors='ignore')
    except ValueError:
        # usecols failed (duplicate columns) — read all then select
        df = pd.read_csv(csv_path, low_memory=False, encoding_errors='ignore')
        df = df[cols]

    df = df[df['Label'] != 'Label']
    for col in cols[:-1]:
        df[col] = pd.to_numeric(df[col], errors='coerce')
    df = df.replace([np.inf, -np.inf], np.nan).dropna()

    f = np.stack([
        np.log1p(np.clip(df['Flow Duration'].values, 0, None) / 1000.0),
        np.clip(df['Tot Fwd Pkts'].values,     0, None),
        np.clip(df['Tot Bwd Pkts'].values,     0, None),
        np.clip(df['TotLen Fwd Pkts'].values,  0, None),
        np.clip(df['TotLen Bwd Pkts'].values,  0, None),
        np.clip(df['Fwd Pkt Len Mean'].values, 0, None),
        np.clip(df['Bwd Pkt Len Mean'].values, 0, None),
    ], axis=1)

    labels = (df['Label'] != 'Benign').astype(int).values

    means = np.array([5.0,  10.0,  5.0, 500.0, 1000.0, 100.0, 150.0])
    stds  = np.array([2.0,   5.0,  3.0, 400.0,  800.0,  80.0, 120.0])
    f_norm = (f - means) / (stds + 1e-8)

    X_list, y_list = [], []
    for i in range(0, len(f_norm) - seq_len + 1, stride):
        X_list.append(f_norm[i:i + seq_len])
        y_list.append(int(np.any(labels[i:i + seq_len])))

    return np.array(X_list, dtype=np.float32), np.array(y_list, dtype=np.float32)


def load_unsw_file(csv_path: str, seq_len: int = 10, stride: int = 5):
    """Load UNSW-NB15 and map its features to the same 7-feature space."""
    if not os.path.exists(csv_path):
        return None, None

    # UNSW-NB15 column mapping → 7 WAF features
    col_map = {
        'dur':      'Flow Duration',
        'spkts':    'Tot Fwd Pkts',
        'dpkts':    'Tot Bwd Pkts',
        'sbytes':   'TotLen Fwd Pkts',
        'dbytes':   'TotLen Bwd Pkts',
        'smeansz':  'Fwd Pkt Len Mean',
        'dmeansz':  'Bwd Pkt Len Mean',
        'label':    'Label',
    }
    try:
        df = pd.read_csv(csv_path, low_memory=False)
        # Normalize column names
        df.columns = [c.strip().lower() for c in df.columns]
        available = {k: v for k, v in col_map.items() if k in df.columns}
        if len(available) < 7:
            print(f"  [UNSW] Insufficient columns — skipping")
            return None, None
        df = df[[c for c in col_map.keys() if c in df.columns]].copy()
        df = df.rename(columns=available)
        for col in list(col_map.values())[:-1]:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce')
        df = df.replace([np.inf, -np.inf], np.nan).dropna()
        labels = (df['Label'] != 0).astype(int).values if 'Label' in df.columns else None
        if labels is None:
            return None, None
    except Exception as e:
        print(f"  [UNSW] Load failed: {e}")
        return None, None

    f = np.stack([
        np.log1p(df.get('Flow Duration', pd.Series(np.zeros(len(df)))).values / 1000.0),
        df.get('Tot Fwd Pkts',     pd.Series(np.zeros(len(df)))).values,
        df.get('Tot Bwd Pkts',     pd.Series(np.zeros(len(df)))).values,
        df.get('TotLen Fwd Pkts',  pd.Series(np.zeros(len(df)))).values,
        df.get('TotLen Bwd Pkts',  pd.Series(np.zeros(len(df)))).values,
        df.get('Fwd Pkt Len Mean', pd.Series(np.zeros(len(df)))).values,
        df.get('Bwd Pkt Len Mean', pd.Series(np.zeros(len(df)))).values,
    ], axis=1)

    means = np.array([5.0, 10.0, 5.0, 500.0, 1000.0, 100.0, 150.0])
    stds  = np.array([2.0,  5.0, 3.0, 400.0,  800.0,  80.0, 120.0])
    f_norm = (f - means) / (stds + 1e-8)

    X_list, y_list = [], []
    for i in range(0, len(f_norm) - seq_len + 1, stride):
        X_list.append(f_norm[i:i + seq_len])
        y_list.append(int(np.any(labels[i:i + seq_len])))

    return np.array(X_list, dtype=np.float32), np.array(y_list, dtype=np.float32)


def balance_dataset(X: np.ndarray, y: np.ndarray, max_ratio: float = 3.0) -> tuple:
    """Downsample majority class to max_ratio × minority class size."""
    attack_idx  = np.where(y == 1)[0]
    benign_idx  = np.where(y == 0)[0]
    n_attack    = len(attack_idx)
    n_benign    = len(benign_idx)
    max_benign  = int(n_attack * max_ratio)
    if n_benign > max_benign:
        benign_idx = np.random.choice(benign_idx, max_benign, replace=False)
    idx = np.concatenate([attack_idx, benign_idx])
    np.random.shuffle(idx)
    return X[idx], y[idx]


def train_temporal(save_path: str = SAVE_PATH, epochs: int = 3,
                   batch_size: int = 256, lr: float = 1e-3):
    print("=" * 60)
    print("  bunyanx WAF — Temporal BiLSTM Multi-File Training")
    print("=" * 60)

    # ── Collect all CIC files ──────────────────────────────────
    cic_files = sorted(glob.glob(os.path.join(CIC_DIR, "*.csv")))
    cic_files = [f for f in cic_files if os.path.basename(f) not in SKIP_FILES]
    print(f"\n[1/4] Found {len(cic_files)} CIC-IDS2018 files (skipping {SKIP_FILES})")

    all_X, all_y = [], []

    for fpath in cic_files:
        fname = os.path.basename(fpath)
        size_mb = os.path.getsize(fpath) / 1024 / 1024
        print(f"  Loading {fname} ({size_mb:.0f} MB)...", end=" ", flush=True)
        try:
            X_f, y_f = load_cic_file(fpath)
            # Cap per-file at 60k windows to balance contribution
            if len(X_f) > 60_000:
                idx = np.random.choice(len(X_f), 60_000, replace=False)
                X_f, y_f = X_f[idx], y_f[idx]
            all_X.append(X_f)
            all_y.append(y_f)
            print(f"{len(X_f)} windows | attacks={y_f.sum():.0f}/{len(y_f)}")
        except Exception as e:
            print(f"SKIP ({e})")

    # ── UNSW-NB15 augmentation ─────────────────────────────────
    print(f"\n  Loading UNSW-NB15 from {UNSW_CSV}...", end=" ", flush=True)
    X_unsw, y_unsw = load_unsw_file(UNSW_CSV)
    if X_unsw is not None and len(X_unsw) > 0:
        if len(X_unsw) > 40_000:
            idx = np.random.choice(len(X_unsw), 40_000, replace=False)
            X_unsw, y_unsw = X_unsw[idx], y_unsw[idx]
        all_X.append(X_unsw)
        all_y.append(y_unsw)
        print(f"{len(X_unsw)} windows | attacks={y_unsw.sum():.0f}/{len(y_unsw)}")
    else:
        print("skipped")

    # ── Merge & balance ────────────────────────────────────────
    X_all = np.concatenate(all_X, axis=0)
    y_all = np.concatenate(all_y, axis=0)
    print(f"\n[2/4] Total before balancing: {len(X_all)} windows "
          f"| attacks={y_all.sum():.0f} ({100*y_all.mean():.1f}%)")

    X_all, y_all = balance_dataset(X_all, y_all, max_ratio=3.0)
    print(f"  After balancing : {len(X_all)} windows "
          f"| attacks={y_all.sum():.0f} ({100*y_all.mean():.1f}%)")

    # ── Train / val split ──────────────────────────────────────
    idx = np.arange(len(X_all))
    np.random.shuffle(idx)
    split = int(0.8 * len(X_all))
    X_train, y_train = X_all[idx[:split]], y_all[idx[:split]]
    X_val,   y_val   = X_all[idx[split:]], y_all[idx[split:]]
    print(f"  Train: {len(X_train)} | Val: {len(X_val)}")

    train_ds = TemporalIDSDataset(X_train, y_train)
    val_ds   = TemporalIDSDataset(X_val,   y_val)
    train_dl = DataLoader(train_ds, batch_size=batch_size, shuffle=True,  num_workers=0)
    val_dl   = DataLoader(val_ds,   batch_size=batch_size, shuffle=False, num_workers=0)

    # ── Model ──────────────────────────────────────────────────
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"\n[3/4] Training on device: {device}")
    model     = TemporalBiLSTM(input_dim=7, hidden_dim=64, num_layers=2).to(device)
    optimizer = AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    # Weighted loss to handle any remaining imbalance
    pos_weight = torch.tensor([(y_train == 0).sum() / max((y_train == 1).sum(), 1)],
                               dtype=torch.float32).to(device)
    loss_fn = nn.BCEWithLogitsLoss(pos_weight=pos_weight)

    # Patch model to return logits instead of sigmoid for BCEWithLogitsLoss
    # (TemporalBiLSTM already applies sigmoid — use BCELoss)
    loss_fn = nn.BCELoss()

    best_val_loss = float('inf')
    os.makedirs(os.path.dirname(save_path), exist_ok=True)

    for epoch in range(epochs):
        model.train()
        total_loss, correct, total = 0.0, 0, 0
        t0 = time.time()

        for step, (xb, yb) in enumerate(train_dl):
            xb, yb = xb.to(device), yb.to(device)
            optimizer.zero_grad()
            preds = model(xb)
            loss  = loss_fn(preds, yb)
            loss.backward()
            optimizer.step()

            total_loss += loss.item()
            correct    += ((preds >= 0.5) == yb).sum().item()
            total      += yb.size(0)

            if (step + 1) % 100 == 0:
                print(f"  Epoch {epoch+1} | Step {step+1}/{len(train_dl)} "
                      f"| Loss: {loss.item():.4f} | Acc: {correct/total*100:.2f}%")

        train_loss = total_loss / len(train_dl)
        train_acc  = correct / total
        elapsed    = time.time() - t0

        # Validation
        model.eval()
        val_loss_sum, val_correct, val_total = 0.0, 0, 0
        with torch.no_grad():
            for xb, yb in val_dl:
                xb, yb = xb.to(device), yb.to(device)
                preds  = model(xb)
                val_loss_sum += loss_fn(preds, yb).item()
                val_correct  += ((preds >= 0.5) == yb).sum().item()
                val_total    += yb.size(0)

        val_loss = val_loss_sum / len(val_dl)
        val_acc  = val_correct / val_total

        print(f"=== Epoch {epoch+1}/{epochs} | Time: {elapsed:.1f}s ===")
        print(f"  Train Loss: {train_loss:.4f} | Train Acc: {train_acc*100:.2f}%")
        print(f"  Val   Loss: {val_loss:.4f} | Val   Acc: {val_acc*100:.2f}%")

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            torch.save(model.state_dict(), save_path)
            print(f"  [OK] Best model saved -> {save_path}")

    print("\n[4/4] Training finished!")
    print(f"  Best Val Loss: {best_val_loss:.4f}")
    print(f"  Model: {save_path}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--epochs",     type=int,   default=3)
    parser.add_argument("--batch_size", type=int,   default=256)
    parser.add_argument("--lr",         type=float, default=1e-3)
    parser.add_argument("--save",       type=str,   default=SAVE_PATH)
    args = parser.parse_args()
    train_temporal(save_path=args.save, epochs=args.epochs,
                   batch_size=args.batch_size, lr=args.lr)
