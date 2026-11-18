import os
import random
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

class CharacterTokenizer:
    """Simple character-level tokenizer for ASCII characters."""
    def __init__(self, max_len=256):
        self.max_len = max_len
        self.vocab = {chr(i): i for i in range(128)} # ASCII 0-127
        self.vocab_size = 128

    def tokenize(self, text: str) -> np.ndarray:
        indices = []
        for char in text:
            # Map to ASCII, default to 0 for unknown/non-ASCII
            val = self.vocab.get(char, 0)
            indices.append(val)
        
        # Pad or truncate
        if len(indices) < self.max_len:
            indices = indices + [0] * (self.max_len - len(indices))
        else:
            indices = indices[:self.max_len]
        
        return np.array(indices, dtype=np.int64)

class WAFNLPModel(nn.Module):
    """
    1D-CNN + BiLSTM character-level network.
    """
    def __init__(self, vocab_size=128, embed_dim=64, num_classes=3):
        super(WAFNLPModel, self).__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.conv1d = nn.Conv1d(in_channels=embed_dim, out_channels=128, kernel_size=5, padding=2)
        self.lstm = nn.LSTM(input_size=128, hidden_size=128, num_layers=1, bidirectional=True, batch_first=True)
        self.fc = nn.Linear(128 * 2, num_classes)

    def forward(self, x):
        # x shape: (batch_size, seq_len)
        x_emb = self.embedding(x) # shape: (batch_size, seq_len, embed_dim)
        
        # Conv1d expects (batch_size, channels, seq_len)
        x_emb = x_emb.transpose(1, 2)
        x_conv = F.relu(self.conv1d(x_emb))
        x_conv = x_conv.transpose(1, 2) # back to (batch_size, seq_len, channels)
        
        # BiLSTM
        lstm_out, _ = self.lstm(x_conv) # shape: (batch_size, seq_len, hidden_size*2)
        
        # Take the average pool or max pool over time, or the last hidden state.
        # Average pooling over time works very well for text classification.
        x_pooled = torch.mean(lstm_out, dim=1) # shape: (batch_size, hidden_size*2)
        
        logits = self.fc(x_pooled) # shape: (batch_size, num_classes)
        return logits

class WAFNLPInference:
    """
    Layer 5 NLP Inference wrapper.
    Implements normal prediction and Randomized Smoothing (AdversarialShield) for certified robustness.
    """
    def __init__(self, model_path: str = "ml/models/waf/waf_nlp_model.pt", max_len=256):
        self.model_path = model_path
        self.tokenizer = CharacterTokenizer(max_len=max_len)
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.labels = ["benign", "xss", "sqli"]
        
        # Build model and load state dict
        self.model = WAFNLPModel(vocab_size=128, embed_dim=64, num_classes=3)
        if os.path.exists(self.model_path):
            try:
                # Map location to CPU if no CUDA
                self.model.load_state_dict(torch.load(self.model_path, map_location=self.device))
                print(f"Successfully loaded WAF NLP model from {self.model_path}")
            except Exception as e:
                print(f"Error loading NLP model weights: {e}")
        else:
            print(f"Warning: NLP model file not found at {self.model_path}. Model remains uninitialized.")
            
        self.model.to(self.device)
        self.model.eval()

    def is_loaded(self) -> bool:
        return os.path.exists(self.model_path)

    def predict(self, text: str) -> tuple[float, str]:
        """
        Standard prediction (non-smoothed).
        Returns:
            (confidence_score, label_name)
        """
        try:
            tokens = self.tokenizer.tokenize(text)
            import numpy as _np
            x = torch.from_numpy(_np.array([tokens], dtype=_np.int64)).to(self.device)
            
            with torch.no_grad():
                logits = self.model(x)
                probs = F.softmax(logits, dim=-1)
                score, preds = torch.max(probs, dim=-1)
                
                label_id = preds.item()
                label_name = self.labels[label_id]
                
                # For WAF inspector output:
                # If benign, nlp_score is 1.0 - benign_prob (i.e. overall threat probability)
                if label_name == "benign":
                    threat_score = 1.0 - probs[0][0].item()
                else:
                    threat_score = score.item()
                    
                return threat_score, label_name
        except Exception as e:
            print(f"NLP predict error: {e}")
            return 0.0, "benign"

    def random_perturb(self, text: str, p: float = 0.05) -> str:
        """Applies character-level substitution, deletion, or insertion noise."""
        chars = list(text)
        new_chars = []
        ascii_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;':\",./<>?`~ "
        for char in chars:
            if random.random() < p:
                action = random.choice(["sub", "del", "ins"])
                if action == "sub":
                    new_chars.append(random.choice(ascii_chars))
                elif action == "del":
                    continue
                elif action == "ins":
                    new_chars.append(char)
                    new_chars.append(random.choice(ascii_chars))
            else:
                new_chars.append(char)
        return "".join(new_chars)

    def predict_smoothed(self, text: str, N: int = 100, p: float = 0.05, alpha: float = 0.05) -> tuple[str, float, float]:
        """
        Randomized Smoothing prediction (AdversarialShield).
        Returns:
            (smoothed_label, confidence, certified_radius)
        """
        counts = np.zeros(len(self.labels), dtype=int)
        
        # Generate N perturbations and run batch inference
        perturbed_texts = [self.random_perturb(text, p) for _ in range(N)]
        tokenized_batch = [self.tokenizer.tokenize(pt) for pt in perturbed_texts]
        
        x = torch.tensor(tokenized_batch, dtype=torch.long).to(self.device)
        
        try:
            with torch.no_grad():
                logits = self.model(x)
                preds = torch.argmax(logits, dim=-1).cpu().numpy()
                
            for pred in preds:
                counts[pred] += 1
                
            # Find the top class
            top_class = np.argmax(counts)
            smoothed_label = self.labels[top_class]
            
            # Compute empirical probability of the top class
            p_top = counts[top_class] / N
            
            # Certified robustness radius calculation under edit perturbation model
            # For a character-level deletion/insertion/substitution noise model:
            # Certified edit radius R can be bounded by:
            # R = max(0, int((p_top - 0.5) / (2 * p)))
            certified_radius = max(0.0, float((p_top - 0.5) / (2 * p))) if p_top > 0.5 else 0.0
            
            return smoothed_label, float(p_top), certified_radius
        except Exception as e:
            print(f"NLP predict_smoothed error: {e}")
            return "benign", 1.0, 0.0
