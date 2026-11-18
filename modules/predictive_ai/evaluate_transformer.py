import os
import json
import glob
import torch
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix
from torch.utils.data import DataLoader

# Import dataset building from train script
from train_transformer import (
    build_training_data, TTPDataset, TTPTransformerModel,
    TTP_NAMES, N_TTPS, BATCH_SIZE, DEVICE, MODEL_PATH
)

def main():
    print("=" * 70)
    print("  AEGIS XDR Transformer Model Evaluation")
    print("=" * 70)
    
    if not os.path.exists(MODEL_PATH):
        print(f"  [!] Model checkpoint not found at {MODEL_PATH}. Train the model first.")
        return
        
    # Build validation set
    try:
        inputs, targets = build_training_data()
    except Exception as e:
        print(f"  [!] Error loading dataset: {e}")
        return
        
    if not inputs:
        print("  [!] No valid validation samples extracted.")
        return
        
    # Reproducible split (same as training)
    dataset_size = len(inputs)
    indices = list(range(dataset_size))
    # Fix seed to get the exact same validation set
    np.random.seed(42)
    np.random.shuffle(indices)
    
    split = int(0.8 * dataset_size)
    val_indices = indices[split:]
    
    val_inputs = [inputs[i] for i in val_indices]
    val_targets = [targets[i] for i in val_indices]
    
    # Analyze class distribution in validation targets
    target_counts = np.bincount(val_targets, minlength=N_TTPS)
    print("\n  [Target Class Distribution in Validation Set]")
    for idx, name in enumerate(TTP_NAMES):
        count = target_counts[idx]
        pct = (count / len(val_targets)) * 100
        print(f"    Class {idx} ({name:<12}): {count:<6} ({pct:.2f}%)")
        
    # Load Model
    model = TTPTransformerModel().to(DEVICE)
    try:
        model.load_state_dict(torch.load(MODEL_PATH, map_location=DEVICE))
        model.eval()
        print(f"\n  Loaded model checkpoint from {MODEL_PATH}")
    except Exception as e:
        print(f"  [!] Failed to load model: {e}")
        return
        
    val_dataset = TTPDataset(val_inputs, val_targets)
    val_loader = DataLoader(val_dataset, batch_size=BATCH_SIZE, shuffle=False)
    
    all_preds = []
    all_targets = []
    
    with torch.no_grad():
        for batch_x, batch_y in val_loader:
            batch_x = batch_x.to(DEVICE)
            outputs = model(batch_x)
            _, preds = torch.max(outputs, 1)
            
            all_preds.extend(preds.cpu().numpy())
            all_targets.extend(batch_y.numpy())
            
    # Calculate metrics
    print("\n" + "=" * 70)
    print("  CLASSIFICATION REPORT")
    print("=" * 70)
    
    # We filter target names to match classes present in evaluation
    present_classes = sorted(list(set(all_targets).union(set(all_preds))))
    present_names = [TTP_NAMES[c] for c in present_classes]
    
    report = classification_report(
        all_targets, 
        all_preds, 
        labels=present_classes, 
        target_names=present_names,
        zero_division=0
    )
    print(report)
    
    # Check for self-transition bias (How often model predicts the last input state)
    same_as_last = 0
    for idx, x_seq in enumerate(val_inputs):
        # x_seq shape: (WINDOW_SIZE, N_FEATURES)
        # Find the active net TTP in the last position (index 9)
        last_step = x_seq[-1, :N_TTPS]
        last_ttp = torch.argmax(last_step).item()
        
        # Check if prediction is same as the last input TTP
        pred = all_preds[idx]
        if pred == last_ttp:
            same_as_last += 1
            
    self_trans_pct = (same_as_last / len(val_inputs)) * 100
    print("=" * 70)
    print(f"  Self-Transition Prediction Bias: {self_trans_pct:.2f}%")
    print("  (Percentage of predictions matching the last observed state in input)")
    print("=" * 70)

if __name__ == "__main__":
    main()
