import os
import sys
import time
import random
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader, WeightedRandomSampler
from torch.optim import AdamW
from torch.optim.lr_scheduler import OneCycleLR
from collections import Counter
from modules.waf.ml_training.waf_nlp.model import CharacterTokenizer, WAFNLPModel, WAFNLPInference

def parse_csic_requests(file_path):
    print(f"Parsing CSIC 2010 file: {file_path}...")
    if not os.path.exists(file_path):
        print(f"Error: {file_path} does not exist.")
        return []
        
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    # Split by double newlines to separate requests
    raw_reqs = content.split('\n\n')
    requests = []
    for raw in raw_reqs:
        raw = raw.strip()
        if not raw:
            continue
        lines = raw.split('\n')
        req_line = lines[0].strip()
        parts = req_line.split(' ')
        if len(parts) < 2:
            continue
        method = parts[0]
        url = parts[1]
        
        # Extract path and query
        if "http://" in url:
            url_part = url.split("http://")[1]
            if "/" in url_part:
                url_path_query = "/" + "/".join(url_part.split("/")[1:])
            else:
                url_path_query = "/"
        else:
            url_path_query = url
            
        body = ""
        if method == "POST":
            # Find the blank line that separates headers from body
            blank_idx = -1
            for idx, line in enumerate(lines):
                if line.strip() == "":
                    blank_idx = idx
                    break
            if blank_idx != -1 and blank_idx + 1 < len(lines):
                body = "\n".join(lines[blank_idx+1:]).strip()
        
        payload = url_path_query
        if body:
            payload += " " + body
        requests.append(payload)
    return requests

class NLPDataset(Dataset):
    def __init__(self, payloads, labels, tokenizer, perturb_prob=0.3, perturb_rate=0.05):
        self.payloads = payloads
        self.labels = labels
        self.tokenizer = tokenizer
        self.perturb_prob = perturb_prob
        self.perturb_rate = perturb_rate
        self.inference_wrapper = WAFNLPInference(model_path="", max_len=tokenizer.max_len)

    def __len__(self):
        return len(self.payloads)

    def __getitem__(self, idx):
        payload = str(self.payloads[idx])
        label = self.labels[idx]

        # Adversarial Augmentation: random character perturbation during training
        if self.perturb_prob > 0 and random.random() < self.perturb_prob:
            payload = self.inference_wrapper.random_perturb(payload, self.perturb_rate)

        tokens = self.tokenizer.tokenize(payload)
        return torch.tensor(tokens, dtype=torch.long), torch.tensor(label, dtype=torch.long)

def build_unified_dataset():
    print("Building unified WAF NLP dataset (target: 136,710 samples)...")
    
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
    # 1. Web-Attacks dataset (all.csv has 53,910 rows)
    web_attacks_path = os.path.join(project_root, "modules/waf/ml_training/data/web-attacks/all.csv")
    web_df = pd.read_csv(web_attacks_path)
    # columns: ['Payload', 'Label']
    web_payloads = web_df['Payload'].astype(str).tolist()
    # map Labels: 0 -> 0 (benign), 1 -> 1 (XSS), 2 -> 2 (SQLi)
    web_labels = web_df['Label'].tolist()
    print(f"Loaded {len(web_payloads)} samples from Web-Attacks.")

    # 2. Rule-Based SQL Injection (RbSQLi) (take 50,000 samples)
    sqli_path = os.path.join(project_root, "modules/waf/ml_training/data/Rule-Based SQL Injection (RbSQLi) Dataset/sqli_dataset.csv")
    sqli_df = pd.read_csv(sqli_path, nrows=50000)
    sqli_payloads = sqli_df['SQL_Query'].astype(str).tolist()
    # All of these are SQL injections -> label 2
    sqli_labels = [2] * len(sqli_payloads)
    print(f"Loaded {len(sqli_payloads)} samples from RbSQLi.")

    # 3. CSIC 2010 (target: 32,800 samples)
    # Benign: 20,000 samples from normalTrafficTraining.txt
    csic_normal_path = os.path.join(project_root, "modules/waf/ml_training/data/csic_2010/normalTrafficTraining.txt")
    csic_normal_reqs = parse_csic_requests(csic_normal_path)
    csic_normal_reqs = csic_normal_reqs[:20000]
    csic_normal_labels = [0] * len(csic_normal_reqs)
    
    # Anomalous: 12,800 samples from anomalousTrafficTest.txt
    csic_anomaly_path = os.path.join(project_root, "modules/waf/ml_training/data/csic_2010/anomalousTrafficTest.txt")
    csic_anomaly_reqs = parse_csic_requests(csic_anomaly_path)
    csic_anomaly_reqs = csic_anomaly_reqs[:12800]
    
    csic_anomaly_labels = []
    # Classify anomalous requests based on simple keywords to map to SQLi/XSS
    xss_keywords = ['<script>', 'javascript', 'onload', 'onerror', '%3Cscript', 'alert(']
    for req in csic_anomaly_reqs:
        is_xss = any(kw in req.lower() for kw in xss_keywords)
        if is_xss:
            csic_anomaly_labels.append(1) # XSS
        else:
            csic_anomaly_labels.append(2) # SQLi
            
    print(f"Loaded {len(csic_normal_reqs)} normal and {len(csic_anomaly_reqs)} anomalous samples from CSIC 2010.")

    # Combine all
    all_payloads = web_payloads + sqli_payloads + csic_normal_reqs + csic_anomaly_reqs
    all_labels = web_labels + sqli_labels + csic_normal_labels + csic_anomaly_labels

    # ── Class balance report ──────────────────────────────────────────────────
    counts = Counter(all_labels)
    total = len(all_labels)
    print(f"Total unified samples: {total}")
    for cls, name in [(0,'Benign'), (1,'XSS'), (2,'SQLi')]:
        print(f"  {name:8s}: {counts[cls]:6d} ({100*counts[cls]/total:.1f}%)")

    # ── Oversample benign to reach 33% of dataset ─────────────────────────────
    # Goal: each class ≈ 33%. Oversample the minority (benign) class.
    target_benign = int(total * 0.33)
    current_benign = counts[0]
    if current_benign < target_benign:
        need = target_benign - current_benign
        benign_idx = [i for i, l in enumerate(all_labels) if l == 0]
        extra_idx = np.random.choice(benign_idx, size=need, replace=True)
        extra_payloads = [all_payloads[i] for i in extra_idx]
        extra_labels   = [0] * need
        all_payloads = all_payloads + extra_payloads
        all_labels   = all_labels   + extra_labels
        print(f"  [Oversample] Added {need} benign samples -> new total: {len(all_labels)}")
        counts_new = Counter(all_labels)
        print(f"  After: Benign={counts_new[0]} ({100*counts_new[0]/len(all_labels):.1f}%)"
              f" | XSS={counts_new[1]} ({100*counts_new[1]/len(all_labels):.1f}%)"
              f" | SQLi={counts_new[2]} ({100*counts_new[2]/len(all_labels):.1f}%)")

    return all_payloads, all_labels

def train_nlp(epochs=3, batch_size=256, lr=1e-3):
    payloads, labels = build_unified_dataset()
    
    # Shuffle and split (80% train, 10% val, 10% test)
    indices = np.arange(len(payloads))
    np.random.shuffle(indices)
    
    train_size = int(0.8 * len(payloads))
    val_size = int(0.1 * len(payloads))
    
    train_idx = indices[:train_size]
    val_idx = indices[train_size:train_size+val_size]
    test_idx = indices[train_size+val_size:]
    
    train_payloads = [payloads[i] for i in train_idx]
    train_labels = [labels[i] for i in train_idx]
    
    val_payloads = [payloads[i] for i in val_idx]
    val_labels = [labels[i] for i in val_idx]
    
    print(f"Train size: {len(train_payloads)} | Val size: {len(val_payloads)}")

    # ── Class weights (inverse frequency) ────────────────────────────────────
    train_counts = Counter(train_labels)
    n_total = len(train_labels)
    n_classes = 3
    class_weights = torch.zeros(n_classes)
    for cls in range(n_classes):
        class_weights[cls] = n_total / (n_classes * max(train_counts[cls], 1))
    print(f"  Class weights: Benign={class_weights[0]:.3f} | XSS={class_weights[1]:.3f} | SQLi={class_weights[2]:.3f}")

    tokenizer = CharacterTokenizer(max_len=256)
    train_dataset = NLPDataset(train_payloads, train_labels, tokenizer, perturb_prob=0.3)
    val_dataset   = NLPDataset(val_payloads,   val_labels,   tokenizer, perturb_prob=0.0)

    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True,  num_workers=0)
    val_loader   = DataLoader(val_dataset,   batch_size=batch_size, shuffle=False, num_workers=0)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Training on device: {device}")

    model     = WAFNLPModel(vocab_size=128, embed_dim=64, num_classes=3).to(device)
    optimizer = AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = OneCycleLR(optimizer, max_lr=lr,
                           steps_per_epoch=len(train_loader), epochs=epochs,
                           pct_start=0.1, anneal_strategy='cos')
    # Weighted loss — gives more penalty for misclassifying rare benign class
    loss_fn   = nn.CrossEntropyLoss(weight=class_weights.to(device))
    
    best_val_acc = 0.0
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
    model_save_path = os.path.join(project_root, "ml/models/waf/waf_nlp_model.pt")
    os.makedirs(os.path.dirname(model_save_path), exist_ok=True)
    
    for epoch in range(epochs):
        model.train()
        total_loss = 0.0
        correct = 0
        total = 0
        start_time = time.time()
        
        for step, (x, y) in enumerate(train_loader):
            x, y = x.to(device), y.to(device)

            optimizer.zero_grad()
            logits = model(x)
            loss = loss_fn(logits, y)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()

            total_loss += loss.item()
            _, preds = torch.max(logits, dim=-1)
            correct += torch.sum(preds == y).item()
            total += y.size(0)

            if (step + 1) % 100 == 0:
                print(f"Epoch {epoch+1} | Step {step+1}/{len(train_loader)} | Loss: {loss.item():.4f} | Acc: {(correct/total)*100:.2f}%")
                
        train_loss = total_loss / len(train_loader)
        train_acc = correct / total
        elapsed = time.time() - start_time
        
        # Validation — with per-class recall
        model.eval()
        val_correct = 0
        val_total   = 0
        val_loss    = 0.0
        all_preds_v, all_labels_v = [], []

        with torch.no_grad():
            for x, y in val_loader:
                x, y = x.to(device), y.to(device)
                logits = model(x)
                loss_v = loss_fn(logits, y)
                val_loss += loss_v.item()
                _, preds = torch.max(logits, dim=-1)
                val_correct += torch.sum(preds == y).item()
                val_total   += y.size(0)
                all_preds_v.extend(preds.cpu().tolist())
                all_labels_v.extend(y.cpu().tolist())

        val_acc  = val_correct / val_total
        val_loss = val_loss / len(val_loader)

        # Per-class recall
        for cls, name in [(0,'Benign'),(1,'XSS'),(2,'SQLi')]:
            true_cls  = [1 for p,l in zip(all_preds_v,all_labels_v) if l==cls]
            hit_cls   = [1 for p,l in zip(all_preds_v,all_labels_v) if l==cls and p==cls]
            recall_cls = len(hit_cls)/max(len(true_cls),1)*100
            print(f"  [{name}] Recall: {recall_cls:.1f}% ({len(hit_cls)}/{len(true_cls)})")
        
        print(f"=== Epoch {epoch+1} Finished | Time: {elapsed:.1f}s ===")
        print(f"Train Loss: {train_loss:.4f} | Train Acc: {train_acc*100:.2f}%")
        print(f"Val Loss: {val_loss:.4f} | Val Acc: {val_acc*100:.2f}%")
        
        if val_acc > best_val_acc:
            best_val_acc = val_acc
            print(f"Saving best model checkpoint to {model_save_path}...")
            torch.save(model.state_dict(), model_save_path)
            
    print("Training finished!")

if __name__ == "__main__":
    epochs = 3
    if len(sys.argv) > 1:
        epochs = int(sys.argv[1])
    train_nlp(epochs=epochs)
