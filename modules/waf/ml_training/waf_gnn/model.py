import os
import time
import numpy as np
from collections import defaultdict, deque

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    _TORCH_AVAILABLE = True
    _Module = nn.Module
except ImportError:
    torch = None
    nn = None
    F = None
    _TORCH_AVAILABLE = False
    _Module = object

class TemporalBiLSTM(_Module):
    """
    BiLSTM for temporal sequence analysis (APT low-and-slow tracking).
    Input shape: (batch_size, 10, 7) - 10 timesteps, 7 network features.
    """
    def __init__(self, input_dim=7, hidden_dim=64, num_layers=2):
        if not _TORCH_AVAILABLE:
            return
        super(TemporalBiLSTM, self).__init__()
        self.lstm = nn.LSTM(
            input_size=input_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            bidirectional=True,
            batch_first=True,
            dropout=0.2 if num_layers > 1 else 0.0
        )
        self.fc = nn.Linear(hidden_dim * 2, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        # x shape: (batch_size, seq_len, input_dim)
        lstm_out, _ = self.lstm(x) # shape: (batch_size, seq_len, hidden_dim * 2)
        # Take the last time step's output
        last_step = lstm_out[:, -1, :] # shape: (batch_size, hidden_dim * 2)
        out = self.fc(last_step)
        return self.sigmoid(out)

class TemporalSessionTracker:
    """
    Tracks the sliding window of the last 10 requests for each IP in memory,
    maps HTTP request metrics to network flow features, and uses TemporalBiLSTM
    to compute anomaly scores.
    """
    def __init__(self, model_path: str = "ml/models/waf/temporal_lstm.pt", seq_len=10):
        self.seq_len = seq_len
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.buffers = defaultdict(lambda: deque(maxlen=seq_len))
        # TTL: purge IP history after 5 minutes of inactivity
        self._last_seen: dict = {}
        self._SESSION_TTL = 300  # seconds
        self._last_evict_time: float = 0.0
        self._EVICT_INTERVAL = 30.0  # throttle: scan at most every 30s
        self.model = TemporalBiLSTM(input_dim=7, hidden_dim=64, num_layers=2)
        
        if os.path.exists(model_path):
            try:
                self.model.load_state_dict(torch.load(model_path, map_location=self.device))
                print(f"Successfully loaded Temporal BiLSTM model from {model_path}")
            except Exception as e:
                print(f"Error loading Temporal BiLSTM model weights: {e}")
        else:
            print(f"Warning: Temporal BiLSTM model file not found at {model_path}. Model remains untrained.")
            
        self.model.to(self.device)
        self.model.eval()
        
        # Scaling stats (from training dataset)
        self.means = np.array([5.0, 10.0, 5.0, 500.0, 1000.0, 100.0, 150.0])
        self.stds = np.array([2.0, 5.0, 3.0, 400.0, 800.0, 80.0, 120.0])

    def clear_ip(self, ip_address: str) -> None:
        """Manually clear temporal history for an IP after a BLOCK decision."""
        self.buffers.pop(ip_address, None)
        self._last_seen.pop(ip_address, None)

    def _evict_stale(self) -> None:
        """Purge IP histories idle for SESSION_TTL seconds.
        Throttled: O(n) scan runs at most every EVICT_INTERVAL seconds.
        """
        now = time.time()
        if now - self._last_evict_time < self._EVICT_INTERVAL:
            return   # too soon — skip scan
        self._last_evict_time = now
        stale = [ip for ip, ts in self._last_seen.items() if now - ts > self._SESSION_TTL]
        for ip in stale:
            self.buffers.pop(ip, None)
            self._last_seen.pop(ip, None)

    def record_and_predict(self, ip_address: str, latency_ms: float, header_count: int, cookie_count: int, payload_bytes: int) -> float:
        """
        Maps live HTTP request metrics to 7 network features, appends to IP buffer,
        and returns the threat probability score from the Temporal BiLSTM.
        """
        # Evict stale IP histories and update last-seen timestamp
        self._evict_stale()
        self._last_seen[ip_address] = time.time()

        # Map to 7 flow-like features:
        # 1. Flow Duration
        f1 = float(np.log1p(latency_ms))
        # 2. Tot Fwd Pkts
        f2 = float(header_count)
        # 3. Tot Bwd Pkts
        f3 = float(cookie_count + 1)
        # 4. TotLen Fwd Pkts
        f4 = float(payload_bytes)
        # 5. TotLen Bwd Pkts (approximate)
        f5 = float(payload_bytes * 1.5)
        # 6. Fwd Pkt Len Mean
        f6 = float(payload_bytes / max(1, header_count))
        # 7. Bwd Pkt Len Mean
        f7 = float(f5 / max(1, f3))
        
        feature_vector = np.array([f1, f2, f3, f4, f5, f6, f7])
        
        # Normalize
        norm_vector = (feature_vector - self.means) / (self.stds + 1e-8)
        
        # Append to buffer
        self.buffers[ip_address].append(norm_vector)
        
        # If we don't have enough history yet, pad with zeros
        history = list(self.buffers[ip_address])
        if len(history) < self.seq_len:
            pad_len = self.seq_len - len(history)
            history = [np.zeros(7) for _ in range(pad_len)] + history
            
        # Run inference
        try:
            x = torch.tensor([history], dtype=torch.float32).to(self.device)
            with torch.no_grad():
                prob = self.model(x).item()
            return prob
        except Exception as e:
            print(f"Temporal prediction error: {e}")
            return 0.0

class GCNLayer(_Module):
    """
    Standard Graph Convolutional Layer.
    """
    def __init__(self, in_features, out_features):
        if not _TORCH_AVAILABLE:
            return
        super(GCNLayer, self).__init__()
        self.weight = nn.Parameter(torch.FloatTensor(in_features, out_features))
        self.bias = nn.Parameter(torch.FloatTensor(out_features))
        nn.init.xavier_uniform_(self.weight)
        nn.init.zeros_(self.bias)

    def forward(self, x, adj):
        if not _TORCH_AVAILABLE:
            return None
        # x shape: (B, N, F_in)
        # adj shape: (B, N, N)
        support = torch.matmul(x, self.weight)
        output = torch.matmul(adj, support) + self.bias
        return output

class WAFGNNModel(_Module):
    """
    Two-layer GCN for session-based threat classification.
    """
    def __init__(self, in_features=7, hidden_dim=32, out_features=1):
        if not _TORCH_AVAILABLE:
            return
        super(WAFGNNModel, self).__init__()
        self.gcn1 = GCNLayer(in_features, hidden_dim)
        self.gcn2 = GCNLayer(hidden_dim, hidden_dim)
        self.fc = nn.Linear(hidden_dim, out_features)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x, adj):
        h = torch.relu(self.gcn1(x, adj))
        h = torch.relu(self.gcn2(h, adj))
        h_pool = torch.mean(h, dim=1)
        out = self.fc(h_pool)
        return self.sigmoid(out)

class WAFGNNInference:
    """
    Layer 7: Stateful GNN session threat detector.
    Constructs a graph from recent requests in the session and runs a GCN.
    """
    def __init__(self, model_path: str = "ml/models/waf/gnn_model.pt", max_seq_len=50):
        self.model_path = model_path
        self.max_seq_len = max_seq_len
        self.buffers = defaultdict(lambda: deque(maxlen=max_seq_len))
        self._session_last_seen: dict = {}
        self._SESSION_TTL_SECONDS = 300   # 5 minutes idle → clear session
        self._last_evict_time: float = 0.0
        self._EVICT_INTERVAL = 30.0       # scan for stale sessions at most every 30s
        self._session_block_counts: dict = {}
        self.metadata = {}
        self.loaded = False

        if not _TORCH_AVAILABLE:
            self.device = "cpu"
            self.model = None
            return

        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = WAFGNNModel(in_features=7, hidden_dim=32)
        if os.path.exists(self.model_path):
            try:
                import logging
                logger = logging.getLogger(__name__)
                checkpoint = torch.load(self.model_path, map_location=self.device)
                if isinstance(checkpoint, dict):
                    self.metadata = {k: v for k, v in checkpoint.items() if k != "model_state"}
                    state_dict = checkpoint.get("model_state", checkpoint)
                    if state_dict:
                        self.model.load_state_dict(state_dict)
                        logger.info("Successfully loaded WAF GNN model weights from %s", model_path)
                    else:
                        logger.info("WAF GNN model checkpoint has empty state_dict. Model remains untrained.")
                else:
                    self.model.load_state_dict(checkpoint)
                    logger.info("Successfully loaded WAF GNN model weights from %s", model_path)
                self.loaded = True
            except Exception as e:
                import logging
                logger = logging.getLogger(__name__)
                logger.error("Error loading GNN model weights: %s", e)
        else:
            import logging
            logger = logging.getLogger(__name__)
            logger.warning("WAF GNN model file not found at %s. Model remains uninitialized.", model_path)
            
        if self.model:
            self.model.to(self.device)
            self.model.eval()

    def is_loaded(self) -> bool:
        return self.loaded

    def clear_session(self, session_id: str) -> None:
        """Manually clear the GNN session buffer for a specific IP/session.
        Use ONLY for explicit admin-triggered IP reset, NOT for automatic
        post-block cleanup — clearing on block allows attackers to evade
        detection by spacing requests across multiple short sessions.
        """
        self.buffers.pop(session_id, None)
        self._session_last_seen.pop(session_id, None)
        self._session_block_counts.pop(session_id, None)

    def record_block(self, session_id: str) -> None:
        """Record that this session was blocked. The block count is used to
        amplify future GNN scores without erasing the session graph history.
        """
        self._session_block_counts[session_id] = self._session_block_counts.get(session_id, 0) + 1

    def get_block_count(self, session_id: str) -> int:
        """Return number of blocks recorded for this session (within current TTL window)."""
        return self._session_block_counts.get(session_id, 0)

    def _evict_stale_sessions(self) -> None:
        """Remove sessions idle for SESSION_TTL_SECONDS.
        Throttled: runs at most every EVICT_INTERVAL seconds to avoid
        O(n) scans on every request in high-traffic environments.
        """
        now = time.time()
        if now - self._last_evict_time < self._EVICT_INTERVAL:
            return   # too soon — skip scan
        self._last_evict_time = now
        stale = [
            sid for sid, ts in self._session_last_seen.items()
            if now - ts > self._SESSION_TTL_SECONDS
        ]
        for sid in stale:
            self.buffers.pop(sid, None)
            self._session_last_seen.pop(sid, None)
            self._session_block_counts.pop(sid, None)
        
    def predict(self, session_id: str, features: dict) -> float:
        """
        Stateful GNN prediction based on session request sequence graph.
        """
        try:
            # Evict stale sessions periodically to prevent poisoned history
            self._evict_stale_sessions()
            self._session_last_seen[session_id] = time.time()

            # 1. Extract 7-dimensional node feature vector
            f1 = float(features.get("request_length", 0.0))
            f2 = float(features.get("payload_entropy", 0.0))
            f3 = float(features.get("special_char_ratio", 0.0))
            f4 = float(features.get("sql_keyword_count", 0.0))
            f5 = float(features.get("xss_keyword_count", 0.0))
            f6 = float(features.get("encoding_layer_count", 0.0))
            f7 = float(features.get("has_null_byte", 0.0))
            
            node_features = np.array([f1, f2, f3, f4, f5, f6, f7], dtype=np.float32)
            
            # Append node to session buffer
            self.buffers[session_id].append(node_features)
            history = list(self.buffers[session_id])
            seq_len = len(history)
            
            # Construct adjacency matrix and node feature matrix
            # Node features X: (1, max_seq_len, 7)
            # Adjacency A: (1, max_seq_len, max_seq_len)
            X = np.zeros((self.max_seq_len, 7), dtype=np.float32)
            A = np.eye(self.max_seq_len, dtype=np.float32) # Identity matrix (self-loops)
            
            # Copy history to X
            X[:seq_len] = history
            
            # Construct temporal edges (i.e. subsequent requests)
            for i in range(seq_len - 1):
                A[i, i + 1] = 1.0
                A[i + 1, i] = 1.0
                
            # Symmetric normalization of adjacency matrix: D^-1/2 * A * D^-1/2
            row_sum = A.sum(axis=1)
            row_sum_inv_sqrt = np.power(row_sum, -0.5, where=(row_sum > 0))
            row_sum_inv_sqrt[row_sum == 0] = 0.0
            D_inv_sqrt = np.diag(row_sum_inv_sqrt)
            A_norm = D_inv_sqrt.dot(A).dot(D_inv_sqrt)
            
            # Convert to PyTorch tensors — use np.array() wrapper to avoid
            # "Creating a tensor from a list of numpy.ndarrays is extremely slow" warning.
            x_tensor   = torch.from_numpy(np.array([X],      dtype=np.float32)).to(self.device)
            adj_tensor = torch.from_numpy(np.array([A_norm], dtype=np.float32)).to(self.device)
            
            with torch.no_grad():
                prob = self.model(x_tensor, adj_tensor).item()

            # Block-count amplification: if this session was blocked before
            # (within the current TTL window), boost the raw score so repeat
            # attackers are caught faster on subsequent attempts.
            # +15% per prior block, capped at 1.0.
            # Benign IPs never accumulate block counts so this doesn't affect them.
            block_count = self._session_block_counts.get(session_id, 0)
            if block_count > 0:
                prob = min(1.0, prob * (1.0 + 0.15 * block_count))

            return prob

        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error("Stateful GNN prediction error: %s", e)
            return 0.0

