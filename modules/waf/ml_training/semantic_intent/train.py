import os
import sys
import time
import pandas as pd
import torch
from torch.utils.data import Dataset, DataLoader
from transformers import AutoTokenizer, AutoModelForSequenceClassification, get_linear_schedule_with_warmup
from torch.optim import AdamW

class WAFTextDataset(Dataset):
    def __init__(self, texts, labels, tokenizer, max_len=128):
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_len = max_len

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, idx):
        text = str(self.texts[idx])
        label = self.labels[idx]

        encoding = self.tokenizer(
            text,
            add_special_tokens=True,
            max_length=self.max_len,
            padding='max_length',
            truncation=True,
            return_attention_mask=True,
            return_tensors='pt'
        )

        return {
            'input_ids': encoding['input_ids'].flatten(),
            'attention_mask': encoding['attention_mask'].flatten(),
            'label': torch.tensor(label, dtype=torch.long)
        }

def train_model(train_path, val_path, save_path, epochs=1, batch_size=32, lr=5e-5):
    print(f"Loading datasets...")
    # Use utf-8 and ignore errors to prevent encoding crashes
    train_df = pd.read_csv(train_path, encoding='utf-8', encoding_errors='ignore')
    val_df = pd.read_csv(val_path, encoding='utf-8', encoding_errors='ignore')

    print(f"Train samples: {len(train_df)}")
    print(f"Val samples: {len(val_df)}")

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using device: {device}")

    model_name = "sentence-transformers/all-MiniLM-L6-v2"
    print(f"Loading pre-trained tokenizer and model: {model_name}...")
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)
    model = model.to(device)

    train_dataset = WAFTextDataset(
        texts=train_df['text'].values,
        labels=train_df['label'].values,
        tokenizer=tokenizer
    )

    val_dataset = WAFTextDataset(
        texts=val_df['text'].values,
        labels=val_df['label'].values,
        tokenizer=tokenizer
    )

    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size)

    optimizer = AdamW(model.parameters(), lr=lr)
    total_steps = len(train_loader) * epochs
    scheduler = get_linear_schedule_with_warmup(
        optimizer,
        num_warmup_steps=int(0.1 * total_steps),
        num_training_steps=total_steps
    )

    loss_fn = torch.nn.CrossEntropyLoss()

    best_accuracy = 0.0

    for epoch in range(epochs):
        print(f"=== Epoch {epoch + 1}/{epochs} ===")
        model.train()
        total_loss = 0
        correct_predictions = 0
        total_samples = 0

        for step, batch in enumerate(train_loader):
            input_ids = batch['input_ids'].to(device)
            attention_mask = batch['attention_mask'].to(device)
            labels = batch['label'].to(device)

            optimizer.zero_grad()
            outputs = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels)
            loss = outputs.loss
            logits = outputs.logits

            _, preds = torch.max(logits, dim=1)
            correct_predictions += torch.sum(preds == labels).item()
            total_samples += labels.size(0)
            total_loss += loss.item()

            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()
            scheduler.step()

            if (step + 1) % 50 == 0:
                print(f"Step {step+1}/{len(train_loader)} | Loss: {loss.item():.4f} | Acc: {(correct_predictions/total_samples)*100:.2f}%")

        epoch_loss = total_loss / len(train_loader)
        epoch_acc = correct_predictions / total_samples
        print(f"Train Loss: {epoch_loss:.4f} | Train Acc: {epoch_acc*100:.2f}%")

        # Validation
        model.eval()
        val_loss = 0
        val_correct = 0
        val_total = 0

        with torch.no_grad():
            for batch in val_loader:
                input_ids = batch['input_ids'].to(device)
                attention_mask = batch['attention_mask'].to(device)
                labels = batch['label'].to(device)

                outputs = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels)
                loss = outputs.loss
                logits = outputs.logits

                _, preds = torch.max(logits, dim=1)
                val_correct += torch.sum(preds == labels).item()
                val_total += labels.size(0)
                val_loss += loss.item()

        val_accuracy = val_correct / val_total
        print(f"Val Loss: {val_loss / len(val_loader):.4f} | Val Acc: {val_accuracy*100:.2f}%")

        if val_accuracy > best_accuracy:
            best_accuracy = val_accuracy
            print(f"Saving best model to {save_path}...")
            os.makedirs(save_path, exist_ok=True)
            model.save_pretrained(save_path)
            tokenizer.save_pretrained(save_path)

    print("Training complete!")

if __name__ == "__main__":
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
    train_csv = os.path.join(project_root, "modules/waf/ml_training/semantic_intent/datasets/train.csv")
    val_csv = os.path.join(project_root, "modules/waf/ml_training/semantic_intent/datasets/val.csv")
    model_save_dir = os.path.join(project_root, "ml/models/waf/semantic_intent")
    
    # We can default to 1 epoch for quick training in testing, but 2 is recommended
    epochs = 1
    if len(sys.argv) > 1:
        epochs = int(sys.argv[1])
        
    train_model(train_csv, val_csv, model_save_dir, epochs=epochs)
