import os
import sys
import glob
import logging
import argparse
from pathlib import Path
from typing import Tuple
import pandas as pd
import numpy as np

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# Map 2018 columns to 2017 array format
COLS_2018 = [
    "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts", 
    "TotLen Fwd Pkts", "TotLen Bwd Pkts", "Fwd Pkt Len Mean", "Bwd Pkt Len Mean",
    "Flow Byts/s", "Flow Pkts/s", "Flow IAT Mean", "Flow IAT Std",
    "Fwd IAT Mean", "Bwd IAT Mean", "Fwd PSH Flags", "SYN Flag Cnt",
    "RST Flag Cnt", "ACK Flag Cnt", "URG Flag Cnt",
    "Pkt Size Avg", "Fwd Seg Size Avg", "Bwd Seg Size Avg"
]

def map_label_2018(lbl: str) -> int:
    lbl = str(lbl).lower()
    if "benign" in lbl: return 0
    if "dos" in lbl: return 1
    if "ddos" in lbl: return 1
    if "portscan" in lbl: return 2
    if "bruteforce" in lbl: return 3
    if "web" in lbl or "sql" in lbl or "xss" in lbl: return 4
    if "bot" in lbl: return 5
    if "infilteration" in lbl or "infiltration" in lbl: return 6
    return 0

def load_2018_directory(dir_path: str, max_rows_per_file: int = 50000) -> Tuple[np.ndarray, np.ndarray]:
    csv_files = glob.glob(os.path.join(dir_path, "*.csv"))
    if not csv_files:
        raise ValueError(f"No CSVs found in {dir_path}")
    
    logger.info(f"Found {len(csv_files)} CSV files in CSE-CIC-IDS2018. Sampling {max_rows_per_file} rows/file to avoid OOM.")
    
    all_x = []
    all_y = []
    
    for f in csv_files:
        try:
            logger.info(f"Reading {os.path.basename(f)}...")
            # Sample to prevent going out of memory on 6GB
            df = pd.read_csv(f, nrows=max_rows_per_file, low_memory=False)
            df.columns = [c.strip() for c in df.columns]
            
            # Label
            label_col = next((c for c in df.columns if c.lower() == 'label'), None)
            if not label_col:
                continue
                
            y = df[label_col].apply(map_label_2018).values
            
            # Features
            available = [c for c in COLS_2018 if c in df.columns]
            x_raw = df[available].fillna(0).replace([np.inf, -np.inf], 0).values.astype(np.float32)
            
            if x_raw.shape[1] < 21:
                pad = np.zeros((len(x_raw), 21 - x_raw.shape[1]), dtype=np.float32)
                x_raw = np.concatenate([x_raw, pad], axis=1)
            
            all_x.append(x_raw)
            all_y.append(y)
        except Exception as e:
            logger.error(f"Failed to read {f}: {e}")
            
    X_flow = np.concatenate(all_x, axis=0)
    y = np.concatenate(all_y, axis=0)
    
    # Scale robustly
    logger.info("Scaling features...")
    med = np.median(X_flow, axis=0)
    iqr = np.percentile(X_flow, 75, axis=0) - np.percentile(X_flow, 25, axis=0)
    iqr = np.where(iqr == 0, 1.0, iqr)
    X_flow = (X_flow - med) / iqr
    X_flow = np.clip(X_flow, -5, 5)
    
    # 256 padding for SBE mapping
    X_sbe = np.zeros((len(X_flow), 256), dtype=np.float32)
    X = np.concatenate([X_flow, X_sbe], axis=1)
    
    return X, y

if __name__ == "__main__":
    from modules.ids_ips.training.train_phantom import split_dataset, make_dataloaders, build_trainable_model, train
    
    dir_path = r"F:\enterprise_ngfw\modules\ids_ips\dataset\CSE-CIC-IDS2018"
    X, y = load_2018_directory(dir_path)
    
    counts = {int(k): int(v) for k, v in zip(*np.unique(y, return_counts=True))}
    logger.info(f"Loaded total {len(X)} records. Distribution: {counts}")
    
    train_dl, val_dl = make_dataloaders(*split_dataset(X, y), batch_size=256)
    
    import torch
    device = "cuda" if torch.cuda.is_available() else "cpu"
    
    model = build_trainable_model(num_classes=10).to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=3e-4, weight_decay=1e-4)
    loss_fn = torch.nn.CrossEntropyLoss()
    
    # Simple training loop inside script
    epochs = 5
    best_f1 = 0
    from sklearn.metrics import f1_score
    for epoch in range(epochs):
        model.train()
        for xf, xs, yt in train_dl:
            xf, xs, yt = xf.to(device), xs.to(device), yt.to(device)
            bs = xf.size(0)
            seq = torch.zeros((bs, 1, 256), device=device)
            pos = torch.zeros((bs, 1), dtype=torch.long, device=device)
            
            optimizer.zero_grad()
            logits = model(xf, xs, seq, pos)
            loss = loss_fn(logits, yt)
            loss.backward()
            optimizer.step()
            
        model.eval()
        preds, trues = [], []
        with torch.no_grad():
            for xf, xs, yt in val_dl:
                xf, xs, yt = xf.to(device), xs.to(device), yt.to(device)
                bs = xf.size(0)
                seq = torch.zeros((bs, 1, 256), device=device)
                pos = torch.zeros((bs, 1), dtype=torch.long, device=device)
                logits = model(xf, xs, seq, pos)
                preds.extend(logits.argmax(-1).cpu().tolist())
                trues.extend(yt.cpu().tolist())
                
        f1 = f1_score(trues, preds, average='macro', zero_division=0)
        logger.info(f"Epoch {epoch+1}/{epochs} | Val Macro-F1 = {f1:.4f}")
        if f1 > best_f1:
            best_f1 = f1
            torch.save(model.backbone.state_dict(), r"F:\enterprise_ngfw\modules\ids_ips\models\phantom_v1.pt")
            logger.info("Saved best model.")
    
    logger.info("Done.")
