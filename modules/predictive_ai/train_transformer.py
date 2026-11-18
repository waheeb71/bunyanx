import os
import json
import glob
import re
import math
import random
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG & PATHS
# ─────────────────────────────────────────────────────────────────────────────
DATA_DIR    = r"F:\enterprise_ngfw\modules\predictive_ai\outputs\stage5_transformer_dataset"
MODELS_DIR  = r"F:\enterprise_ngfw\modules\predictive_ai\models"
MODEL_PATH  = os.path.join(MODELS_DIR, "ttp_transformer.pt")

WINDOW_SIZE = 10
BATCH_SIZE  = 64
EPOCHS      = 20
LR          = 1e-3
DEVICE      = "cuda" if torch.cuda.is_available() else "cpu"

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

# ─────────────────────────────────────────────────────────────────────────────
# PARSING UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

def map_net_ttp(attack_type: str) -> int:
    atk = attack_type.upper().replace(" ", "_")
    mapping = {
        "RECONNAISSANCE": "SCAN", "SCAN": "SCAN", "PROBE": "SCAN",
        "EXPLOIT": "WAF_EXPLOIT", "EXPLOITATION": "WAF_EXPLOIT", "WEB_ATTACK": "WAF_EXPLOIT", "FUZZING": "WAF_EXPLOIT", "ANALYSIS": "WAF_EXPLOIT",
        "MALWARE": "MALWARE", "VIRUS": "MALWARE",
        "DGA_C2": "DGA_C2", "BOTNET": "DGA_C2", "C2": "DGA_C2",
        "DLP_EXFIL": "DLP_EXFIL", "EXFIL": "DLP_EXFIL", "EXFILTRATION": "DLP_EXFIL",
        "LATERAL": "LATERAL", "LATERAL_MOVEMENT": "LATERAL", "WORMS": "LATERAL", "WORM": "LATERAL", "INFILTRATION": "LATERAL",
        "PRIV_ESC": "PRIV_ESC", "BRUTE_FORCE": "PRIV_ESC", "CREDENTIAL_ACCESS": "PRIV_ESC",
        "PERSISTENCE": "PERSISTENCE", "BACKDOOR": "PERSISTENCE",
        "RANSOMWARE": "RANSOMWARE", "DOS": "RANSOMWARE", "DDOS": "RANSOMWARE", "IMPACT": "RANSOMWARE"
    }
    ttp_name = mapping.get(atk)
    if ttp_name in TTP_INDEX:
        return TTP_INDEX[ttp_name]
    return -1

def map_ep_signal(action: str) -> int:
    act = action.upper().replace(" ", "_")
    mapping = {
        "PROC_CREATE": "PROC_CREATE",
        "FILE_MOD": "FILE_MOD",
        "REG_EDIT": "REG_EDIT",
        "NET_CONN": "NET_CONN",
        "MEM_INJECT": "MEM_INJECT",
        "EP_LOGON": "NET_CONN",
        "EP_DEVICE": "PROC_CREATE",
        "EP_EMAIL": "NET_CONN",
        "EP_FILE": "FILE_MOD",
        "EP_HTTP": "NET_CONN",
        "EP_PROFILE": "PROC_CREATE",
    }
    sig_name = mapping.get(act)
    if sig_name in ENDPOINT_INDEX:
        return ENDPOINT_INDEX[sig_name]
    return -1

def parse_token_to_feature(token: str):
    token = token.strip()
    if not token.startswith("[") or "]" not in token:
        return None
    
    parts = token.split("]", 1)
    src_type = parts[0][1:].strip().upper()
    rest = parts[1].strip()
    
    action = rest
    attack_type = ""
    if "[" in rest and rest.endswith("]"):
        action_parts = rest.split("[", 1)
        action = action_parts[0].strip()
        attack_type = action_parts[1][:-1].strip()
        
    if src_type == "NET":
        if attack_type:
            val = map_net_ttp(attack_type)
            if val != -1:
                return ("NET", val)
        return ("NET", 0)
    elif src_type == "EP":
        val = map_ep_signal(action)
        if val != -1:
            return ("EP", val)
        return ("EP", 0)
    return None

# ─────────────────────────────────────────────────────────────────────────────
# DATASET GENERATOR WITH SELF-TRANSITION FILTERING
# ─────────────────────────────────────────────────────────────────────────────

def build_training_data():
    print("  Scanning dataset files...")
    files = sorted(glob.glob(os.path.join(DATA_DIR, "transformer_dataset_part_*.jsonl")))
    if not files:
        raise FileNotFoundError(f"No dataset files found in {DATA_DIR}. Run stage 5 first.")
    
    inputs = []
    targets = []
    self_transitions_skipped = 0
    
    print(f"  Found {len(files)} dataset parts. Extracting transition sequences...")
    for fpath in files:
        with open(fpath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    sample = json.loads(line)
                except Exception:
                    continue
                
                is_attack = sample.get("labels", {}).get("is_attack", 0)
                if not is_attack:
                    continue
                
                tokens = sample.get("input_sequence", [])
                if len(tokens) < WINDOW_SIZE + 1:
                    continue
                
                # Parse all tokens in the sequence
                parsed_seq = []
                for tok in tokens:
                    feature = parse_token_to_feature(tok)
                    parsed_seq.append(feature)
                
                # Extract sliding windows of size WINDOW_SIZE + 1
                for i in range(len(parsed_seq) - WINDOW_SIZE):
                    window = parsed_seq[i : i + WINDOW_SIZE + 1]
                    target_event = window[-1]
                    
                    # Target must be a network event with an active attack TTP (not benign/0)
                    if target_event and target_event[0] == "NET" and target_event[1] > 0:
                        
                        # Build one-hot encoding and find the last active network TTP in the input
                        one_hot = torch.zeros(WINDOW_SIZE, N_FEATURES)
                        last_active_input_ttp = -1
                        for j in range(WINDOW_SIZE):
                            evt = window[j]
                            if evt:
                                src, val = evt
                                if src == "NET":
                                    one_hot[j, val] = 1.0
                                    if val > 0:
                                        last_active_input_ttp = val
                                elif src == "EP":
                                    one_hot[j, N_TTPS + val] = 1.0
                        
                        # FILTER: Skip if target is the same as the last active input TTP (self-copy bias)
                        if target_event[1] == last_active_input_ttp:
                            self_transitions_skipped += 1
                            continue
                            
                        inputs.append(one_hot)
                        targets.append(target_event[1])
                        
    print(f"  Extracted {len(inputs):,} active transition windows.")
    print(f"  Filtered out {self_transitions_skipped:,} self-transition sequences (copy bias eliminated).")
    return inputs, targets

class TTPDataset(Dataset):
    def __init__(self, inputs, targets):
        self.inputs = inputs
        self.targets = targets
        
    def __len__(self):
        return len(self.inputs)
        
    def __getitem__(self, idx):
        return self.inputs[idx], self.targets[idx]

# ─────────────────────────────────────────────────────────────────────────────
# MODEL ARCHITECTURE (Matches attention_predictor.py exactly)
# ─────────────────────────────────────────────────────────────────────────────

class PositionalEncoding(nn.Module):
    def __init__(self, d_model: int, max_len: int = 512):
        super().__init__()
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(
            torch.arange(0, d_model, 2, dtype=torch.float)
            * (-math.log(10000.0) / d_model)
        )
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        self.register_buffer("pe", pe.unsqueeze(0))

    def forward(self, x):
        return x + self.pe[:, :x.size(1), :]

class TTPTransformerModel(nn.Module):
    def __init__(self, d_model=64, n_heads=4, n_layers=2, d_ff=256, dropout=0.1):
        super().__init__()
        self.input_projection = nn.Linear(N_FEATURES, d_model)
        self.pos_encoder = PositionalEncoding(d_model)
        
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
        
        self.head = nn.Sequential(
            nn.Linear(d_model, d_model // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(d_model // 2, N_TTPS),
        )

    def forward(self, x):
        h = self.input_projection(x)
        h = self.pos_encoder(h)
        h = self.transformer_encoder(h)
        h_last = h[:, -1, :]
        return self.head(h_last)

# ─────────────────────────────────────────────────────────────────────────────
# MAIN TRAINING LOOP
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("  AEGIS XDR Transformer Model Training (Enhanced)")
    print("=" * 70)
    
    os.makedirs(MODELS_DIR, exist_ok=True)
    
    try:
        inputs, targets = build_training_data()
    except Exception as e:
        print(f"  [!] Error building dataset: {e}")
        return
        
    if not inputs:
        print("  [!] No valid training samples extracted after filtering.")
        return
        
    # Class Distribution Analysis & Weighting
    class_counts = [0] * N_TTPS
    for t in targets:
        class_counts[t] += 1
        
    print("\n  [Transition Target Class Distribution]")
    for idx, name in enumerate(TTP_NAMES):
        print(f"    Class {idx} ({name:<12}): {class_counts[idx]:<6}")
        
    # Calculate square root inverse frequency class weights to counter imbalance smoothly
    total_samples = len(targets)
    class_weights = []
    for count in class_counts:
        if count > 0:
            class_weights.append(math.sqrt(total_samples / count))
        else:
            class_weights.append(1.0)
            
    # Normalize weights
    weight_sum = sum(class_weights)
    class_weights = [w / weight_sum * N_TTPS for w in class_weights]
    print(f"\n  Calculated Class Weights (Smoothed): {[round(w, 2) for w in class_weights]}")
    
    # Shuffle and split into Train / Val
    dataset_size = len(inputs)
    indices = list(range(dataset_size))
    random.shuffle(indices)
    
    split = int(0.8 * dataset_size)
    train_indices = indices[:split]
    val_indices   = indices[split:]
    
    train_inputs  = [inputs[i] for i in train_indices]
    train_targets = [targets[i] for i in train_indices]
    val_inputs    = [inputs[i] for i in val_indices]
    val_targets   = [targets[i] for i in val_indices]
    
    train_dataset = TTPDataset(train_inputs, train_targets)
    val_dataset   = TTPDataset(val_inputs, val_targets)
    
    train_loader  = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)
    val_loader    = DataLoader(val_dataset, batch_size=BATCH_SIZE, shuffle=False)
    
    print(f"\n  Train samples: {len(train_dataset):,}")
    print(f"  Val samples  : {len(val_dataset):,}")
    
    # Initialize Model, Weighted Loss, Optimizer, Scheduler
    model = TTPTransformerModel().to(DEVICE)
    class_weights_tensor = torch.FloatTensor(class_weights).to(DEVICE)
    criterion = nn.CrossEntropyLoss(weight=class_weights_tensor)
    optimizer = optim.AdamW(model.parameters(), lr=LR, weight_decay=1e-4)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=EPOCHS, eta_min=1e-5)
    
    print(f"\n  Starting training on {DEVICE} for {EPOCHS} epochs...")
    
    best_val_loss = float("inf")
    
    for epoch in range(1, EPOCHS + 1):
        # Training Phase
        model.train()
        train_loss = 0.0
        train_correct = 0
        train_total = 0
        
        for batch_x, batch_y in train_loader:
            batch_x = batch_x.to(DEVICE)
            batch_y = batch_y.to(DEVICE)
            
            optimizer.zero_grad()
            outputs = model(batch_x)
            loss = criterion(outputs, batch_y)
            loss.backward()
            optimizer.step()
            
            train_loss += loss.item() * batch_x.size(0)
            _, preds = torch.max(outputs, 1)
            train_correct += (preds == batch_y).sum().item()
            train_total += batch_x.size(0)
            
        train_loss /= train_total
        train_acc = train_correct / train_total
        
        # Validation Phase
        model.eval()
        val_loss = 0.0
        val_correct = 0
        val_total = 0
        
        with torch.no_grad():
            for batch_x, batch_y in val_loader:
                batch_x = batch_x.to(DEVICE)
                batch_y = batch_y.to(DEVICE)
                
                outputs = model(batch_x)
                loss = criterion(outputs, batch_y)
                
                val_loss += loss.item() * batch_x.size(0)
                _, preds = torch.max(outputs, 1)
                val_correct += (preds == batch_y).sum().item()
                val_total += batch_x.size(0)
                
        val_loss /= val_total
        val_acc = val_correct / val_total
        
        scheduler.step()
        
        print(f"  Epoch {epoch:02d}/{EPOCHS} | Train Loss: {train_loss:.4f} Acc: {train_acc*100:.2f}% | Val Loss: {val_loss:.4f} Acc: {val_acc*100:.2f}%")
        
        # Save Best Model
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            torch.save(model.state_dict(), MODEL_PATH)
            
    print("\n" + "=" * 70)
    print("  TRAINING COMPLETE")
    print(f"  Best Val Loss : {best_val_loss:.4f}")
    print(f"  Model saved to: {MODEL_PATH}")
    print("=" * 70)

if __name__ == "__main__":
    main()
