import os
import torch
import torch.nn.functional as F
from transformers import AutoTokenizer, AutoModelForSequenceClassification

class SemanticIntentInspector:
    """
    Layer 4: Generative Application Firewall (GAF)
    Transformer-based semantic classifier using MiniLM to detect Prompt Injection.
    """
    def __init__(self, model_path: str = "ml/models/waf/semantic_intent"):
        self.model_path = model_path
        self.tokenizer = None
        self.model = None
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.labels = ["prompt_injection", "benign_query"]
        
        # Load the model and tokenizer
        if os.path.exists(self.model_path):
            try:
                self.tokenizer = AutoTokenizer.from_pretrained(self.model_path)
                self.model = AutoModelForSequenceClassification.from_pretrained(self.model_path)
                self.model.to(self.device)
                self.model.eval()
            except Exception as e:
                print(f"Error loading trained GAF model from {self.model_path}: {e}")
        
        # Fallback to base model if not trained yet
        if self.model is None or self.tokenizer is None:
            print(f"Warning: Trained GAF model not found at {self.model_path}. Falling back to default 'all-MiniLM-L6-v2'...")
            try:
                fallback_name = "sentence-transformers/all-MiniLM-L6-v2"
                self.tokenizer = AutoTokenizer.from_pretrained(fallback_name)
                # Since all-MiniLM-L6-v2 is an embedding model, we'd need a classification head.
                # However, for sequence classification fallback, we can instantiate it with 2 labels.
                self.model = AutoModelForSequenceClassification.from_pretrained(fallback_name, num_labels=2)
                self.model.to(self.device)
                self.model.eval()
            except Exception as e:
                print(f"Critical: Failed to load fallback GAF model: {e}")

    def is_loaded(self) -> bool:
        return self.model is not None and self.tokenizer is not None

    def predict(self, text: str) -> tuple[float, str]:
        # Fast heuristic check for prompt injection keywords (Defense-in-Depth fallback)
        lower_text = text.lower()
        injection_keywords = [
            "ignore the previous", "ignore previous", "ignore instructions",
            "system instructions", "output the secret", "developer mode",
            "bypass system", "new directions", "forget your instructions"
        ]
        if any(kw in lower_text for kw in injection_keywords):
            return 0.85, "prompt_injection"

        if not self.is_loaded():
            return 0.0, "benign_query"
        
        try:
            inputs = self.tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                max_length=512,
                padding=True
            ).to(self.device)
            
            with torch.no_grad():
                outputs = self.model(**inputs)
                logits = outputs.logits
                probs = F.softmax(logits, dim=-1)
                
                # Get the highest score and label
                score, preds = torch.max(probs, dim=-1)
                label_id = preds.item()
                label_name = self.labels[label_id]
                
                # If label is benign_query (1), return prompt_injection (0) prob as the injection score
                if label_name == "benign_query":
                    injection_score = probs[0][0].item()
                else:
                    injection_score = score.item()
                
                return injection_score, label_name
        except Exception as e:
            print(f"GAF predict error: {e}")
            return 0.0, "benign_query"
