"""
bunyanx NGFW — AEGIS Engine: GNN Lateral Movement Predictor
================================================================

Graph Neural Network that predicts lateral movement targets by
understanding the enterprise network topology.

Problem Solved
--------------
Sequential models (LSTM/Transformer) treat attack events as a linear
sequence. But lateral movement is fundamentally a GRAPH problem — the
attacker exploits network connectivity paths between hosts. A GNN
natively understands:
  - Which hosts are reachable from a compromised node
  - Which paths use vulnerable protocols (SMB, RDP)
  - Which nodes have high criticality scores
  - How belief state propagates along network edges

Architecture: GraphSAGE (2-layer, Pure PyTorch)
-------------------------------------------------
Implementation uses manual message passing with no external dependencies
(no torch-geometric), ensuring lightweight deployment.

  Layer 1: Message Passing
    For each node v:
      m_v = MEAN({h_u : u ∈ N(v)})        # aggregate neighbor features
      h_v' = σ(W1 · CONCAT(h_v, m_v))     # update with self + neighbor info

  Layer 2: Message Passing (same pattern)
    h_v'' = σ(W2 · CONCAT(h_v', m_v'))

  Output: Per-node classification
    P(compromised_next | v) = sigmoid(W_out · h_v'')

Performance Targets
-------------------
  Inference latency: ≤ 2ms for networks up to 1000 nodes
  Lateral movement prediction improvement: +15% over sequential-only

Research Reference
------------------
  Hamilton et al., "Inductive Representation Learning on Large Graphs,"
  NeurIPS 2017 (GraphSAGE).
  AEGIS Paper — §IV.B Layer 2.5 (GNN Lateral Movement Prediction)
"""

from __future__ import annotations

import logging
from typing import Optional

import numpy as np

_log = logging.getLogger(__name__)

# Node feature dimension from network_topology.py
_NODE_FEAT_DIM = 7


# ---------------------------------------------------------------------------
# GraphSAGE Layer (Pure PyTorch — no torch-geometric)
# ---------------------------------------------------------------------------

def _build_gnn_model(
    input_dim:  int = _NODE_FEAT_DIM,
    hidden_dim: int = 32,
    output_dim: int = 1,
    n_layers:   int = 2,
    dropout:    float = 0.1,
):
    """Build the GraphSAGE model using pure PyTorch."""
    import torch
    import torch.nn as nn

    class GraphSAGELayer(nn.Module):
        """
        Single GraphSAGE message-passing layer.

        For each node v:
          1. Aggregate neighbor features: m_v = MEAN({h_u : u ∈ N(v)})
          2. Concatenate with self: z_v = [h_v || m_v]
          3. Transform: h_v' = ReLU(W · z_v + b)
        """

        def __init__(self, in_dim: int, out_dim: int, dropout: float = 0.1):
            super().__init__()
            # Input is CONCAT(self, neighbor_agg) → 2 * in_dim
            self.linear = nn.Linear(in_dim * 2, out_dim)
            self.dropout = nn.Dropout(dropout)
            self.norm = nn.LayerNorm(out_dim)

        def forward(self, x: torch.Tensor, adj: torch.Tensor) -> torch.Tensor:
            """
            Parameters
            ----------
            x : (N, in_dim) — node features
            adj : (N, N) — adjacency matrix (binary, can be weighted)

            Returns
            -------
            h : (N, out_dim) — updated node features
            """
            # Compute degree for normalization (avoid div by zero)
            degree = adj.sum(dim=1, keepdim=True).clamp(min=1.0)  # (N, 1)

            # Aggregate: mean of neighbor features
            neighbor_sum = torch.mm(adj, x)  # (N, in_dim)
            neighbor_mean = neighbor_sum / degree  # (N, in_dim)

            # Concatenate self + neighbor
            z = torch.cat([x, neighbor_mean], dim=1)  # (N, 2*in_dim)

            # Transform
            h = self.linear(z)  # (N, out_dim)
            h = self.norm(h)
            h = torch.relu(h)
            h = self.dropout(h)

            return h

    class GNNLateralModel(nn.Module):
        """
        2-layer GraphSAGE for lateral movement target prediction.

        Input:  node features (N, input_dim) + adjacency (N, N)
        Output: P(compromised_next) per node (N, 1)
        """

        def __init__(self):
            super().__init__()
            self.layers = nn.ModuleList()

            # Layer 1: input_dim → hidden_dim
            self.layers.append(GraphSAGELayer(input_dim, hidden_dim, dropout))

            # Layer 2+: hidden_dim → hidden_dim
            for _ in range(n_layers - 1):
                self.layers.append(GraphSAGELayer(hidden_dim, hidden_dim, dropout))

            # Output: hidden_dim → 1 (sigmoid for probability)
            self.output_head = nn.Sequential(
                nn.Linear(hidden_dim, hidden_dim // 2),
                nn.ReLU(),
                nn.Linear(hidden_dim // 2, output_dim),
            )

        def forward(
            self, x: torch.Tensor, adj: torch.Tensor,
        ) -> torch.Tensor:
            """
            Forward pass.

            Parameters
            ----------
            x : (N, input_dim) — node features
            adj : (N, N) — adjacency matrix

            Returns
            -------
            probs : (N, 1) — P(compromised_next) per node
            """
            h = x
            for layer in self.layers:
                h = layer(h, adj)

            logits = self.output_head(h)  # (N, 1)
            probs = torch.sigmoid(logits)
            return probs

    return GNNLateralModel()


# ---------------------------------------------------------------------------
# GNNLateralPredictor — Main Interface
# ---------------------------------------------------------------------------

class GNNLateralPredictor:
    """
    GNN-based lateral movement target predictor.

    Given a network topology (hosts + connections) and current
    belief states, predicts which hosts are most likely to be
    targeted for lateral movement next.

    Design
    ------
    - Uses a heuristic-initialized model (no pre-training required)
    - Predictions combine GNN structure awareness with node features
    - Can operate in two modes:
        1. Heuristic mode (always available): topology + belief propagation
        2. Learned mode (when model file exists): trained GraphSAGE

    Parameters
    ----------
    use_learned_model : bool
        If True, attempt to load a pre-trained GNN model.
        If False, use heuristic mode only. Default: False.
    """

    def __init__(self, use_learned_model: bool = False) -> None:
        self._use_learned = use_learned_model
        self._model = None
        self._model_loaded = False

        _log.info("GNNLateralPredictor initialized (mode=%s)",
                  "learned" if use_learned_model else "heuristic")

    @property
    def is_ready(self) -> bool:
        """True if running in heuristic mode or if model is loaded successfully."""
        if not self._use_learned:
            return True
        return self._get_model() is not None

    def predict(
        self,
        node_features: np.ndarray,
        adjacency: np.ndarray,
        compromised_mask: Optional[np.ndarray] = None,
    ) -> np.ndarray:
        """
        Predict lateral movement target probabilities for each node.

        Parameters
        ----------
        node_features : np.ndarray, shape (N, 7)
            Node feature matrix from NetworkTopology.node_features.
        adjacency : np.ndarray, shape (N, N)
            Binary adjacency matrix.
        compromised_mask : np.ndarray, shape (N,), optional
            Boolean mask of currently compromised nodes.
            If None, inferred from node belief states.

        Returns
        -------
        probs : np.ndarray, shape (N,)
            P(compromised_next) ∈ [0, 1] for each node.
        """
        n = node_features.shape[0]

        if self._use_learned:
            return self._predict_learned(node_features, adjacency)

        return self._predict_heuristic(
            node_features, adjacency, compromised_mask,
        )

    def predict_top_k(
        self,
        node_features: np.ndarray,
        adjacency: np.ndarray,
        node_ids: list[str],
        k: int = 5,
        compromised_mask: Optional[np.ndarray] = None,
    ) -> list[tuple[str, float]]:
        """
        Return top-k most likely lateral movement targets.

        Returns list of (node_id, probability) sorted descending.
        """
        probs = self.predict(node_features, adjacency, compromised_mask)
        indexed = [(node_ids[i], float(probs[i])) for i in range(len(node_ids))]
        indexed.sort(key=lambda x: x[1], reverse=True)
        return indexed[:k]

    # ------------------------------------------------------------------
    # Heuristic Prediction (always available)
    # ------------------------------------------------------------------

    def _predict_heuristic(
        self,
        node_features: np.ndarray,
        adjacency: np.ndarray,
        compromised_mask: Optional[np.ndarray],
    ) -> np.ndarray:
        """
        Heuristic lateral movement prediction based on topology analysis.

        Score for each node v:
          S(v) = Σ_{u ∈ N(v)} α(u) · connectivity_factor(v)

        where:
          α(u) = belief_state[u] (how likely neighbor u is compromised)
          connectivity_factor(v) = degree(v) / max_degree · criticality(v)

        Intuition: A node is at high risk if:
          1. Its neighbors have high belief/compromise states
          2. It has high connectivity (many paths for attacker to reach it)
          3. It has high criticality (attractive target)
        """
        n = node_features.shape[0]
        if n == 0:
            return np.array([])

        # Extract features
        criticality = node_features[:, 3]   # index 3 = criticality
        epss        = node_features[:, 4]   # index 4 = EPSS
        belief      = node_features[:, 5]   # index 5 = belief_state

        # Infer compromised mask from belief if not provided
        if compromised_mask is None:
            compromised_mask = belief > 0.5

        # Degree centrality (normalized)
        degree = adjacency.sum(axis=1)
        max_degree = max(degree.max(), 1.0)
        degree_norm = degree / max_degree

        # Neighbor risk propagation: belief propagation along edges
        # Risk_from_neighbors(v) = sum of belief(u) for neighbors u
        neighbor_risk = adjacency @ belief  # matrix-vector multiply
        max_nr = max(neighbor_risk.max(), 1e-6)
        neighbor_risk_norm = neighbor_risk / max_nr

        # Vulnerability exposure amplifier
        vuln_factor = 1.0 + epss  # nodes with higher EPSS are easier targets

        # Final score combines:
        #   - neighbor risk (40%) — are neighboring nodes compromised?
        #   - criticality (25%)   — is this a high-value target?
        #   - degree (20%)        — is this a well-connected node?
        #   - vulnerability (15%) — is this an easy target?
        scores = (
            0.40 * neighbor_risk_norm
            + 0.25 * criticality
            + 0.20 * degree_norm
            + 0.15 * (vuln_factor - 1.0)  # normalize EPSS contribution
        )

        # Suppress already-compromised nodes (they're already taken)
        scores[compromised_mask.astype(bool)] *= 0.1

        # Normalize to [0, 1]
        s_max = scores.max()
        if s_max > 1e-6:
            scores = scores / s_max

        return scores.astype(np.float32)

    # ------------------------------------------------------------------
    # Learned Prediction (requires trained model)
    # ------------------------------------------------------------------

    def _predict_learned(
        self,
        node_features: np.ndarray,
        adjacency: np.ndarray,
    ) -> np.ndarray:
        """Predict using the trained GraphSAGE model."""
        import torch

        model = self._get_model()
        if model is None:
            raise RuntimeError("GNN model is not loaded. Cannot use learned mode.")

        x   = torch.from_numpy(node_features).float()
        adj = torch.from_numpy(adjacency).float()

        model.eval()
        with torch.no_grad():
            probs = model(x, adj).squeeze(-1).numpy()

        return probs

    def _get_model(self):
        """Load the trained GNN model. Raises RuntimeError on failure."""
        if self._model_loaded:
            return self._model
        
        self._model_loaded = True

        if not self._use_learned:
            return None

        import torch
        from pathlib import Path
        model_path = Path(__file__).resolve().parent.parent.parent.parent / "models" / "gnn_lateral.pt"
        
        if not model_path.exists():
            raise RuntimeError(f"GNN model file missing at {model_path}. Must train model first.")
            
        try:
            model = _build_gnn_model()
            state = torch.load(model_path, map_location="cpu", weights_only=True)
            model.load_state_dict(state)
            self._model = model
            _log.info("GNNLateralPredictor: loaded trained model from %s", model_path)
        except Exception as exc:
            raise RuntimeError(f"Failed to load GNN model from {model_path}: {exc}")
            
        return self._model

    def summary(self) -> dict:
        """Return diagnostic summary."""
        return {
            "mode": "learned" if self._use_learned else "heuristic",
            "model_loaded": self._model is not None,
            "is_ready": self.is_ready,
        }
