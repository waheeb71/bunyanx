"""
Fix C3 — BiLSTM Independent Test Set Evaluation
================================================
Uses CIC-IDS2018 with temporal day-based split:
  Train:      Days 02-14, 02-15, 02-16, 02-20, 02-21, 02-22
  Validation: Day  02-23
  Test:       Days 02-28, 03-01, 03-02  (INDEPENDENT — never seen during training)
"""

import os, random, warnings
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import (accuracy_score, roc_auc_score,
                             classification_report, confusion_matrix)
warnings.filterwarnings("ignore")

# ── Reproducibility ──────────────────────────────────────────────────────────
SEED = 42
random.seed(SEED); np.random.seed(SEED); torch.manual_seed(SEED)
torch.backends.cudnn.deterministic = True
torch.backends.cudnn.benchmark     = False
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"Device: {DEVICE}")

# ── Config ────────────────────────────────────────────────────────────────────
DATA_DIR    = r"F:\enterprise_ngfw\modules\waf\data\CSE-CIC-IDS2018"
MODEL_OUT   = r"F:\enterprise_ngfw\modules\waf\config\bilstm_temporal.pt"
RESULTS_OUT = r"F:\enterprise_ngfw\modules\waf\config\bilstm_test_results.txt"

WINDOW_SIZE = 10
N_FEATURES  = 7
BATCH       = 256
EPOCHS      = 3
LR          = 1e-3
GRAD_CLIP   = 1.0
MAX_ROWS_PER_FILE = 600_000  # cap per day file to avoid OOM
CHUNK_SIZE = 200_000        # rows per CSV chunk

TRAIN_DAYS = ["02-14-2018.csv","02-15-2018.csv","02-16-2018.csv",
              "02-20-2018.csv","02-21-2018.csv","02-22-2018.csv"]
VAL_DAYS   = ["02-23-2018.csv"]
TEST_DAYS  = ["02-28-2018.csv","03-01-2018.csv","03-02-2018.csv"]

FEATURE_COLS = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Flow Bytes/s", "Flow Packets/s", "Fwd IAT Mean", "Bwd IAT Mean"
]
LABEL_COL = "Label"

# ── Helpers ───────────────────────────────────────────────────────────────────
def load_days(day_files, data_dir):
    dfs = []
    for f in day_files:
        path = os.path.join(data_dir, f)
        if not os.path.exists(path):
            print("  [SKIP] " + f + " not found")
            continue
        chunks_list = []
        row_count = 0
        try:
            for chunk in pd.read_csv(path, encoding="latin-1", low_memory=False, chunksize=CHUNK_SIZE):
                chunk.columns = chunk.columns.str.strip()
                chunks_list.append(chunk)
                row_count += len(chunk)
                if row_count >= MAX_ROWS_PER_FILE:
                    break
            df_f = pd.concat(chunks_list, ignore_index=True)
            del chunks_list
            dfs.append(df_f)
            print("  Loaded " + f + ": " + str(row_count) + " rows")
        except Exception as e:
            print("  [WARN] Could not load " + f + ": " + str(e))
    return pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()

def preprocess(df, scaler=None, le=None, fit=False):
    available = [c for c in FEATURE_COLS if c in df.columns]
    for m in set(FEATURE_COLS) - set(available):
        df[m] = 0.0
    available = FEATURE_COLS
    df = df[available + [LABEL_COL]].copy()
    # Remove duplicate header rows (CIC-IDS2018 CSVs often contain repeated header lines)
    for col in available:
        df = df[df[col] != col]
    for col in available:
        df[col] = pd.to_numeric(df[col], errors='coerce')
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)
    # Binary labeling: BENIGN=0, anything else=1 (robust across all days & attack types)
    raw_labels = df[LABEL_COL].astype(str).str.strip()
    y = (raw_labels != "BENIGN").astype(int).values
    if fit:
        scaler = StandardScaler()
        df[available] = scaler.fit_transform(df[available])
        le = None  # not needed for binary classification
    else:
        df[available] = scaler.transform(df[available])
    X = df[available].values.astype(np.float32)
    return X, y, scaler, le

def make_windows(X, y, window=WINDOW_SIZE):
    Xw, yw = [], []
    for i in range(len(X) - window + 1):
        Xw.append(X[i:i+window])
        yw.append(int(y[i:i+window].mean() >= 0.5))
    return np.array(Xw, dtype=np.float32), np.array(yw, dtype=np.int64)

def make_loader(X, y, shuffle=True):
    ds = TensorDataset(torch.tensor(X), torch.tensor(y))
    return DataLoader(ds, batch_size=BATCH, shuffle=shuffle, num_workers=0)

# ── Model ─────────────────────────────────────────────────────────────────────
class TemporalBiLSTM(nn.Module):
    def __init__(self, in_dim=N_FEATURES, hidden=128, layers=2, dropout=0.3):
        super().__init__()
        self.lstm = nn.LSTM(in_dim, hidden, num_layers=layers,
                            batch_first=True, bidirectional=True,
                            dropout=dropout)
        self.head = nn.Sequential(
            nn.Linear(hidden*2, 64), nn.ReLU(), nn.Dropout(0.2),
            nn.Linear(64, 1), nn.Sigmoid()
        )
    def forward(self, x):
        out, _ = self.lstm(x)
        return self.head(out[:, -1, :]).squeeze(-1)

# ── Main ──────────────────────────────────────────────────────────────────────
print("\n=== Loading Training Days ===")
train_raw = load_days(TRAIN_DAYS, DATA_DIR)
print(f"Train total: {len(train_raw):,} rows")

print("\n=== Loading Validation Day ===")
val_raw = load_days(VAL_DAYS, DATA_DIR)

print("\n=== Loading Independent Test Days ===")
test_raw = load_days(TEST_DAYS, DATA_DIR)

print("\n=== Preprocessing ===")
X_tr, y_tr, scaler, le = preprocess(train_raw, fit=True)
X_va, y_va, _,      _  = preprocess(val_raw,  scaler=scaler, le=le)
X_te, y_te, _,      _  = preprocess(test_raw, scaler=scaler, le=le)
print(f"Train: {X_tr.shape} | Val: {X_va.shape} | Test: {X_te.shape}")

print("\n=== Building Windows ===")
Xw_tr, yw_tr = make_windows(X_tr, y_tr)
Xw_va, yw_va = make_windows(X_va, y_va)
Xw_te, yw_te = make_windows(X_te, y_te)
print(f"Train: {len(Xw_tr):,} | Val: {len(Xw_va):,} | Test: {len(Xw_te):,}")

tr_loader = make_loader(Xw_tr, yw_tr, shuffle=True)
va_loader = make_loader(Xw_va, yw_va, shuffle=False)
te_loader = make_loader(Xw_te, yw_te, shuffle=False)

print("\n=== Training ===")
model     = TemporalBiLSTM(in_dim=N_FEATURES).to(DEVICE)
optimizer = torch.optim.Adam(model.parameters(), lr=LR)
criterion = nn.BCELoss()
scheduler = torch.optim.lr_scheduler.OneCycleLR(
    optimizer, max_lr=LR, epochs=EPOCHS, steps_per_epoch=len(tr_loader))

best_val_acc, best_state = 0.0, None
history = []

for epoch in range(1, EPOCHS+1):
    model.train(); tr_loss = 0.0
    for Xb, yb in tr_loader:
        Xb, yb = Xb.to(DEVICE), yb.float().to(DEVICE)
        optimizer.zero_grad()
        loss = criterion(model(Xb), yb)
        loss.backward()
        nn.utils.clip_grad_norm_(model.parameters(), GRAD_CLIP)
        optimizer.step(); scheduler.step()
        tr_loss += loss.item() * len(Xb)

    model.eval(); pv, tv = [], []
    with torch.no_grad():
        for Xb, yb in va_loader:
            pv.extend(model(Xb.to(DEVICE)).cpu().numpy())
            tv.extend(yb.numpy())
    va_acc = accuracy_score(tv, (np.array(pv)>=0.5).astype(int))
    tr_loss /= len(Xw_tr)
    history.append({"epoch":epoch,"loss":tr_loss,"val_acc":va_acc})
    print(f"  Epoch {epoch} | Loss={tr_loss:.4f} | Val Acc={va_acc*100:.2f}%")
    if va_acc > best_val_acc:
        best_val_acc = va_acc
        best_state   = {k: v.clone() for k,v in model.state_dict().items()}

print("\n=== Independent Test Evaluation ===")
model.load_state_dict(best_state)
torch.save(best_state, MODEL_OUT)

model.eval(); pt, tt = [], []
with torch.no_grad():
    for Xb, yb in te_loader:
        pt.extend(model(Xb.to(DEVICE)).cpu().numpy())
        tt.extend(yb.numpy())

pt = np.array(pt); tt = np.array(tt)
te_acc = accuracy_score(tt, (pt>=0.5).astype(int))
try: te_auc = roc_auc_score(tt, pt)
except: te_auc = float("nan")

report = classification_report(tt,(pt>=0.5).astype(int),target_names=["BENIGN","ATTACK"])
cm     = confusion_matrix(tt, (pt>=0.5).astype(int))

print(f"\n{'='*55}")
print(f"  Best Val Accuracy:          {best_val_acc*100:.2f}%")
print(f"  Independent Test Accuracy:  {te_acc*100:.2f}%")
print(f"  Independent Test AUC:       {te_auc:.4f}")
print(f"  Val-Test Gap:               {abs(best_val_acc-te_acc)*100:.2f} pp")
print(f"{'='*55}")
print(f"\n{report}")
print(f"Confusion Matrix:\n{cm}")

history_str = "\n".join(f"  {r['epoch']} | {r['loss']:.4f} | {r['val_acc']*100:.2f}%" for r in history)
results = f"""BILSTM INDEPENDENT TEST RESULTS (Fix C3)
==========================================
Best Val Accuracy        : {best_val_acc*100:.2f}%
Independent Test Accuracy: {te_acc*100:.2f}%
Independent Test AUC     : {te_auc:.4f}
Val-Test Gap             : {abs(best_val_acc-te_acc)*100:.2f} pp

Train Days : 02-14,02-15,02-16,02-20,02-21,02-22 ({len(Xw_tr):,} windows)
Val Day    : 02-23 ({len(Xw_va):,} windows)
Test Days  : 02-28,03-01,03-02 ({len(Xw_te):,} windows)

Classification Report:
{report}

Confusion Matrix:
{cm}

Training History (Epoch | Loss | Val Acc):
{history_str}
"""
with open(RESULTS_OUT,"w") as f: f.write(results)
print("Results saved")
print("✅ Fix C3 COMPLETE")
