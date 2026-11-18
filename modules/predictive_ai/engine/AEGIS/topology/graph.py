"""
bunyanx NGFW — AEGIS Engine: Network Topology Model
========================================================

Provides graph-based representation of the enterprise network topology
for the GNN Lateral Movement Predictor.

Purpose
-------
Sequential prediction models (LSTM/Transformer) treat attack events as
a linear sequence, ignoring the underlying network graph. An attacker
performing lateral movement traverses a graph of hosts connected by
network paths — not a sequence of independent events.

This module provides:
  NetworkNode       — Single host/device in the enterprise network
  NetworkEdge       — Connection between two hosts
  NetworkTopology   — Full graph representation with adjacency matrix

The GNNLateralPredictor consumes a NetworkTopology to predict which
hosts are most likely targets for lateral movement.

Research Reference
------------------
  AEGIS Paper — §IV.B Layer 2.5 (GNN Lateral Movement Prediction)
  W.L. Hamilton, "Graph Representation Learning," 2020.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Optional

import numpy as np

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Network Node
# ---------------------------------------------------------------------------

@dataclass
class NetworkNode:
    """
    A single host/device in the enterprise network graph.

    Attributes
    ----------
    node_id : str
        Unique identifier (typically IP address).
    os_type : str
        Operating system: "windows" | "linux" | "iot" | "unknown".
    criticality : float
        Business criticality score ∈ [0, 1]. Higher = more critical.
    epss_score : float
        EPSS vulnerability exposure score ∈ [0, 1].
    belief_state : float
        Current ASE belief certainty for this host ∈ [0, 1].
        Updated dynamically from BeliefState.normalised_certainty.
    active_sessions : int
        Number of currently active network sessions.
    is_compromised : bool
        True if the host is known/suspected compromised.
    """

    node_id:          str
    os_type:          str   = "unknown"
    criticality:      float = 0.5
    epss_score:       float = 0.0
    belief_state:     float = 0.0
    active_sessions:  int   = 0
    is_compromised:   bool  = False

    @property
    def feature_vector(self) -> np.ndarray:
        """
        Encode node features as a fixed-size vector for GNN input.

        Returns shape (7,):
          [os_win, os_linux, os_iot, criticality, epss, belief, sessions_norm]
        """
        os_win   = 1.0 if self.os_type == "windows" else 0.0
        os_linux = 1.0 if self.os_type == "linux" else 0.0
        os_iot   = 1.0 if self.os_type == "iot" else 0.0
        sessions_norm = min(self.active_sessions / 100.0, 1.0)

        return np.array([
            os_win, os_linux, os_iot,
            self.criticality,
            self.epss_score,
            self.belief_state,
            sessions_norm,
        ], dtype=np.float32)

    def to_dict(self) -> dict:
        return {
            "node_id":         self.node_id,
            "os_type":         self.os_type,
            "criticality":     round(self.criticality, 4),
            "epss_score":      round(self.epss_score, 4),
            "belief_state":    round(self.belief_state, 4),
            "active_sessions": self.active_sessions,
            "is_compromised":  self.is_compromised,
        }


# ---------------------------------------------------------------------------
# Network Edge
# ---------------------------------------------------------------------------

@dataclass
class NetworkEdge:
    """
    A connection between two hosts in the network graph.

    Attributes
    ----------
    src : str
        Source node ID.
    dst : str
        Destination node ID.
    protocol : str
        Protocol: "smb" | "rdp" | "ssh" | "http" | "other".
    traffic_volume : float
        Normalized traffic volume ∈ [0, 1].
    firewall_allowed : bool
        True if this path is allowed by firewall policy.
    """

    src:              str
    dst:              str
    protocol:         str   = "other"
    traffic_volume:   float = 0.0
    firewall_allowed: bool  = True

    @property
    def feature_vector(self) -> np.ndarray:
        """
        Encode edge features as a fixed-size vector.

        Returns shape (6,):
          [proto_smb, proto_rdp, proto_ssh, proto_http, traffic, fw_allowed]
        """
        proto_smb  = 1.0 if self.protocol == "smb" else 0.0
        proto_rdp  = 1.0 if self.protocol == "rdp" else 0.0
        proto_ssh  = 1.0 if self.protocol == "ssh" else 0.0
        proto_http = 1.0 if self.protocol == "http" else 0.0

        return np.array([
            proto_smb, proto_rdp, proto_ssh, proto_http,
            self.traffic_volume,
            1.0 if self.firewall_allowed else 0.0,
        ], dtype=np.float32)

    def to_dict(self) -> dict:
        return {
            "src":              self.src,
            "dst":              self.dst,
            "protocol":         self.protocol,
            "traffic_volume":   round(self.traffic_volume, 4),
            "firewall_allowed": self.firewall_allowed,
        }


# ---------------------------------------------------------------------------
# Network Topology (Graph)
# ---------------------------------------------------------------------------

# Feature dimensions
NODE_FEATURE_DIM = 7   # See NetworkNode.feature_vector
EDGE_FEATURE_DIM = 6   # See NetworkEdge.feature_vector


class NetworkTopology:
    """
    Enterprise network graph for GNN-based lateral movement prediction.

    The topology consists of:
      - N nodes (hosts/devices), each with a 7-dim feature vector
      - E edges (connections), each with a 6-dim feature vector
      - A binary adjacency matrix A ∈ {0,1}^(N×N)

    Parameters
    ----------
    nodes : list[NetworkNode]
        List of all hosts in the network.
    edges : list[NetworkEdge]
        List of all connections between hosts.
    """

    def __init__(
        self,
        nodes: list[NetworkNode],
        edges: list[NetworkEdge],
    ) -> None:
        self._nodes = {n.node_id: n for n in nodes}
        self._edges = edges
        self._node_list = list(self._nodes.keys())
        self._node_idx  = {nid: i for i, nid in enumerate(self._node_list)}

        # Build adjacency matrix
        n = len(self._node_list)
        self._adj = np.zeros((n, n), dtype=np.float32)
        for edge in edges:
            i = self._node_idx.get(edge.src)
            j = self._node_idx.get(edge.dst)
            if i is not None and j is not None:
                self._adj[i, j] = 1.0
                self._adj[j, i] = 1.0  # undirected graph

        _log.info(
            "NetworkTopology built: %d nodes, %d edges, density=%.2f%%",
            n, len(edges),
            100.0 * self._adj.sum() / max(n * n, 1),
        )

    @property
    def num_nodes(self) -> int:
        return len(self._node_list)

    @property
    def num_edges(self) -> int:
        return len(self._edges)

    @property
    def adjacency_matrix(self) -> np.ndarray:
        """Binary adjacency matrix of shape (N, N)."""
        return self._adj

    @property
    def node_features(self) -> np.ndarray:
        """Node feature matrix of shape (N, NODE_FEATURE_DIM)."""
        return np.array([
            self._nodes[nid].feature_vector
            for nid in self._node_list
        ], dtype=np.float32)

    def get_node(self, node_id: str) -> Optional[NetworkNode]:
        return self._nodes.get(node_id)

    def get_node_index(self, node_id: str) -> Optional[int]:
        return self._node_idx.get(node_id)

    def get_neighbors(self, node_id: str) -> list[str]:
        """Return IDs of all nodes connected to node_id."""
        idx = self._node_idx.get(node_id)
        if idx is None:
            return []
        neighbor_indices = np.where(self._adj[idx] > 0)[0]
        return [self._node_list[i] for i in neighbor_indices]

    def update_node_belief(self, node_id: str, belief: float) -> None:
        """Update the belief state of a node (called by ASE)."""
        node = self._nodes.get(node_id)
        if node:
            node.belief_state = belief

    def mark_compromised(self, node_id: str) -> None:
        """Mark a node as compromised."""
        node = self._nodes.get(node_id)
        if node:
            node.is_compromised = True

    def to_dict(self) -> dict:
        return {
            "num_nodes": self.num_nodes,
            "num_edges": self.num_edges,
            "nodes":     [self._nodes[nid].to_dict() for nid in self._node_list],
            "edges":     [e.to_dict() for e in self._edges],
        }

    def to_json(self) -> str:
        """Serialize topology to JSON."""
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> "NetworkTopology":
        """Deserialize topology from JSON."""
        data = json.loads(json_str)
        nodes = [
            NetworkNode(**n) for n in data["nodes"]
        ]
        edges = [
            NetworkEdge(**e) for e in data["edges"]
        ]
        return cls(nodes, edges)


# ---------------------------------------------------------------------------
# TopologyBuilder — Constructs graph from session/firewall data
# ---------------------------------------------------------------------------

class TopologyBuilder:
    """
    Builds a NetworkTopology from enterprise session table data.

    Usage:
        builder = TopologyBuilder()
        builder.add_host("10.0.0.1", os_type="windows", criticality=0.9)
        builder.add_connection("10.0.0.1", "10.0.0.2", protocol="smb")
        topology = builder.build()
    """

    def __init__(self) -> None:
        self._nodes: dict[str, NetworkNode] = {}
        self._edges: list[NetworkEdge] = []

    def add_host(
        self,
        ip: str,
        os_type: str = "unknown",
        criticality: float = 0.5,
        epss_score: float = 0.0,
    ) -> None:
        """Register a host in the topology."""
        if ip not in self._nodes:
            self._nodes[ip] = NetworkNode(
                node_id=ip,
                os_type=os_type,
                criticality=criticality,
                epss_score=epss_score,
            )

    def add_connection(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: str = "other",
        traffic_volume: float = 0.0,
        firewall_allowed: bool = True,
    ) -> None:
        """Add a network connection between two hosts."""
        # Auto-register hosts if not already known
        if src_ip not in self._nodes:
            self.add_host(src_ip)
        if dst_ip not in self._nodes:
            self.add_host(dst_ip)

        self._edges.append(NetworkEdge(
            src=src_ip,
            dst=dst_ip,
            protocol=protocol.lower(),
            traffic_volume=traffic_volume,
            firewall_allowed=firewall_allowed,
        ))

    def build(self) -> NetworkTopology:
        """Construct the final NetworkTopology graph."""
        return NetworkTopology(
            nodes=list(self._nodes.values()),
            edges=self._edges,
        )
