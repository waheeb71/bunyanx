"""
Temporal BiLSTM - Full Evaluation on ALL 10 CIC-IDS2018 files
"""
import os, sys, json, time
import numpy as np
import pandas as pd
import torch
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
from sklearn.calibration import calibration_curve
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

PROJECT_ROOT = r"F:\enterprise_ngfw"
sys.path.insert(0, PROJECT_ROOT)

np.random.seed(42)
torch.manual_seed(42)

from modules.waf.ml_training.waf_gnn.model import TemporalBiLSTM

model = TemporalBiLSTM(input_dim=7, hidden_dim=64, num_layers=2)
model.load_state_dict(torch.load(os.path.join(PROJECT_ROOT, "ml/models/waf/temporal_lstm.pt"), map_location='cpu'))
model.eval()

DATA_DIR = os.path.join(PROJECT_ROOT, "modules/waf/data/CSE-CIC-IDS2018")
csv_files = sorted([f for f in os.listdir(DATA_DIR) if f.endswith('.csv')])
print(f"Found {len(csv_files)} CSV files")

feature_cols = ['Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts', 'Flow Byts/s', 'Flow Pkts/s', 'Fwd Pkt Len Mean', 'Bwd Pkt Len Mean']
means = np.array([5,10,5,500,1000,100,150])
stds = np.array([2,5,3,400,800,80,120])

all_windows = []
all_labels = []

for csv_file in csv_files:
    path = os.path.join(DATA_DIR, csv_file)
    size_mb = os.path.getsize(path) / 1e6
    print(f"\nProcessing {csv_file} ({size_mb:.0f} MB)...")
    
    try:
        # Read in chunks for large files
        chunks = pd.read_csv(path, chunksize=200000, low_memory=False)
        file_windows = 0
        
        for chunk_idx, df in enumerate(chunks):
            df.columns = [c.strip() for c in df.columns]
            
            for c in feature_cols:
                if c in df.columns:
                    df[c] = pd.to_numeric(df[c], errors='coerce').fillna(0)
                    df[c] = df[c].replace([np.inf, -np.inf], 0)
                else:
                    df[c] = 0.0
            
            src_ip_col = 'Src IP' if 'Src IP' in df.columns else df.columns[0]
            label_col = 'Label' if 'Label' in df.columns else df.columns[-1]
            
            grouped = df.groupby(src_ip_col)
            for name, group in grouped:
                if len(group) >= 10:
                    features = group[feature_cols].values
                    features = (features - means) / stds
                    lbls = group[label_col].values
                    for i in range(len(features) - 10 + 1):
                        all_windows.append(features[i:i+10])
                        wl = 0
                        for l in lbls[i:i+10]:
                            if str(l).strip().lower() != 'benign':
                                wl = 1
                                break
                        all_labels.append(wl)
                        file_windows += 1
            
            print(f"  Chunk {chunk_idx+1}: {file_windows} windows so far...")
        
        print(f"  {csv_file}: {file_windows} windows")
    except Exception as e:
        print(f"  ERROR in {csv_file}: {e}")

print(f"\n{'='*60}")
print(f"TOTAL WINDOWS: {len(all_windows)}")
print(f"Attack windows: {sum(all_labels)}")
print(f"Benign windows: {len(all_labels) - sum(all_labels)}")

# Run inference
windows = np.array(all_windows, dtype=np.float32)
labels = np.array(all_labels)

preds = []
probs = []
batch_size = 512

print(f"\nRunning inference on {len(windows)} windows...")
with torch.no_grad():
    for i in range(0, len(windows), batch_size):
        batch_x = torch.tensor(windows[i:i+batch_size], dtype=torch.float32)
        out = model(batch_x)
        batch_probs = out.squeeze(-1).numpy()
        batch_preds = (batch_probs > 0.5).astype(int)
        preds.extend(batch_preds)
        probs.extend(batch_probs)
        if (i // batch_size) % 100 == 0:
            print(f"  Inference: {min(i+batch_size, len(windows))}/{len(windows)}...")

preds = np.array(preds)
probs = np.array(probs, dtype=np.float64)
probs = np.nan_to_num(probs, nan=0.5, posinf=1.0, neginf=0.0)
probs = np.clip(probs, 0.0, 1.0)

acc = accuracy_score(labels, preds)
prec = precision_score(labels, preds, zero_division=0)
rec = recall_score(labels, preds, zero_division=0)
f1 = f1_score(labels, preds, zero_division=0)
auc_val = roc_auc_score(labels, probs) if len(np.unique(labels)) > 1 else 0.0

results = {
    'total_windows': int(len(windows)),
    'accuracy': float(acc),
    'precision': float(prec),
    'recall': float(rec),
    'f1': float(f1),
    'auc_roc': float(auc_val),
    'attack_windows': int(sum(labels)),
    'benign_windows': int(len(labels) - sum(labels)),
    'files_processed': len(csv_files)
}

print(f"\n{'='*60}")
print("TEMPORAL BiLSTM - FULL EVALUATION RESULTS")
print(f"{'='*60}")
for k, v in results.items():
    print(f"  {k}: {v}")

# Save
out_path = os.path.join(PROJECT_ROOT, "modules/waf/config/evaluation/results_temporal_full.json")
with open(out_path, 'w') as f:
    json.dump(results, f, indent=4)
print(f"\nSaved to {out_path}")

# Generate calibration curve
if len(np.unique(labels)) > 1:
    prob_true, prob_pred = calibration_curve(labels, probs, n_bins=10)
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(7, 8), gridspec_kw={'height_ratios': [3, 1]})
    ax1.plot(prob_pred, prob_true, marker='o', lw=2, color='#2563EB', label='Temporal BiLSTM')
    ax1.plot([0, 1], [0, 1], ls='--', color='gray', label='Perfect calibration')
    ax1.fill_between(prob_pred, prob_true, [p for p in prob_pred], alpha=0.1, color='#2563EB')
    ax1.set_ylabel('Fraction of Positives (Empirical)')
    ax1.set_title(f'Fig. 3 — Temporal BiLSTM Calibration Curve\nCSE-CIC-IDS2018 | {len(windows):,} windows | Val Acc = {acc*100:.2f}%', fontweight='bold')
    ax1.legend()
    ax2.hist(probs, bins=10, color='#93C5FD', edgecolor='#2563EB')
    ax2.set_xlabel('Mean Predicted Probability')
    ax2.set_ylabel('Count')
    fig.tight_layout()
    fig.savefig(os.path.join(PROJECT_ROOT, "modules/waf/config/evaluation/figures/fig_calibration_curve.png"), dpi=300, bbox_inches='tight')
    plt.close()
    print("Calibration curve saved.")
