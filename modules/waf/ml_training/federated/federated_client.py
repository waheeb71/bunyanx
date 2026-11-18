import io
import base64
import requests
import torch
import torch.nn as nn
import numpy as np
from modules.waf.ml_training.waf_nlp.model import WAFNLPModel, CharacterTokenizer

def serialize_tensors(state_dict) -> str:
    buffer = io.BytesIO()
    torch.save(state_dict, buffer)
    return base64.b64encode(buffer.getvalue()).decode('utf-8')

def deserialize_tensors(serialized_str) -> dict:
    bytes_data = base64.b64decode(serialized_str.encode('utf-8'))
    buffer = io.BytesIO(bytes_data)
    return torch.load(buffer, map_location="cpu")

class FederatedClient:
    def __init__(self, server_url: str = "http://localhost:8008", client_id: str = "node_1"):
        self.server_url = server_url
        self.client_id = client_id
        self.device = torch.device("cpu") # run on CPU
        self.model = WAFNLPModel(vocab_size=128, embed_dim=64, num_classes=3)
        self.tokenizer = CharacterTokenizer(max_len=256)
        self.loss_fn = nn.CrossEntropyLoss()

    def pull_global_model(self) -> int:
        """Pulls global model from server and updates local weights."""
        print(f"[{self.client_id}] Pulling global model weights from {self.server_url}/model...")
        try:
            r = requests.get(f"{self.server_url}/model")
            r.raise_for_status()
            data = r.json()
            round_num = data["round"]
            weights_b64 = data["model_weights"]
            
            if weights_b64:
                global_weights = deserialize_tensors(weights_b64)
                self.model.load_state_dict(global_weights, strict=False)
                print(f"[{self.client_id}] Global model loaded successfully (Round {round_num}).")
            else:
                print(f"[{self.client_id}] No global model initialized on server yet.")
                
            return round_num
        except Exception as e:
            print(f"Error pulling global model: {e}")
            return -1

    def compute_local_gradients(self, local_payloads: list, local_labels: list) -> dict:
        """Performs a local training step and returns parameter gradients."""
        self.model.train()
        self.model.zero_grad()
        
        # Tokenize local batch
        tokens_list = [self.tokenizer.tokenize(p) for p in local_payloads]
        x = torch.tensor(tokens_list, dtype=torch.long)
        y = torch.tensor(local_labels, dtype=torch.long)
        
        # Forward & backward
        logits = self.model(x)
        loss = self.loss_fn(logits, y)
        loss.backward()
        
        # Extract gradients
        gradients = {}
        for name, param in self.model.named_parameters():
            if param.grad is not None:
                gradients[name] = param.grad.clone()
                
        return gradients

    def apply_differential_privacy(self, gradients: dict, clip_norm: float = 1.0, noise_scale: float = 0.1) -> dict:
        """Applies L2 gradient clipping and adds Gaussian noise for Differential Privacy."""
        dp_gradients = {}
        for name, grad in gradients.items():
            # Calculate L2 norm of the parameter gradient tensor
            l2_norm = torch.norm(grad.view(-1), p=2).item()
            
            # Clip gradient
            clip_coef = min(1.0, clip_norm / (l2_norm + 1e-8))
            clipped_grad = grad * clip_coef
            
            # Add Gaussian noise: N(0, (noise_scale * clip_norm)^2)
            noise = torch.randn_like(clipped_grad) * (noise_scale * clip_norm)
            
            dp_gradients[name] = clipped_grad + noise
            
        return dp_gradients

    def submit_gradients(self, round_num: int, dp_gradients: dict) -> bool:
        """Serializes and posts the DP-protected gradients to the aggregation server."""
        print(f"[{self.client_id}] Submitting DP gradients for Round {round_num}...")
        serialized = serialize_tensors(dp_gradients)
        payload = {
            "client_id": self.client_id,
            "round": round_num,
            "serialized_gradients": serialized
        }
        try:
            r = requests.post(f"{self.server_url}/submit_gradients", json=payload)
            r.raise_for_status()
            res = r.json()
            print(f"[{self.client_id}] Submission status: {res['status']}. Buffer: {res.get('buffer_count')}")
            return True
        except Exception as e:
            print(f"Error submitting gradients: {e}")
            return False

    def run_round(self, local_payloads: list, local_labels: list, clip_norm: float = 1.0, noise_scale: float = 0.1) -> bool:
        """Runs one complete round of Federated learning (pull -> compute -> perturb -> push)."""
        round_num = self.pull_global_model()
        if round_num < 0:
            return False
            
        # Compute local gradients
        raw_grads = self.compute_local_gradients(local_payloads, local_labels)
        
        # Apply Differential Privacy
        dp_grads = self.apply_differential_privacy(raw_grads, clip_norm, noise_scale)
        
        # Submit
        return self.submit_gradients(round_num, dp_grads)

if __name__ == "__main__":
    # Test script: run a dummy round
    import sys
    client_id = sys.argv[1] if len(sys.argv) > 1 else "node_1"
    server_url = sys.argv[2] if len(sys.argv) > 2 else "http://localhost:8008"
    
    client = FederatedClient(server_url=server_url, client_id=client_id)
    
    # Mock data batch
    dummy_payloads = [
        "SELECT * FROM users WHERE id = 1 AND 1=1 --",
        "GET /index.html HTTP/1.1",
        "<script>alert(1)</script>"
    ]
    dummy_labels = [2, 0, 1]  # SQLi, Benign, XSS
    
    client.run_round(dummy_payloads, dummy_labels)
