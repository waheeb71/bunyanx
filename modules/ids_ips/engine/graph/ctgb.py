"""
PHANTOM — Causal Temporal Graph Builder (CTGB)
================================================
Layer 2 of the PHANTOM IDS/IPS framework.

Constructs a dynamic, live causal graph of host interactions
from a stream of (src_ip, dst_ip, payload_sbe, timestamp) tuples.

Architecture
------------

  ┌──────────────────────────────────────────────────────────────────┐
  │  For every incoming flow event:                                  │
  │                                                                  │
  │  1. Add directed edge src→dst (flow edge, weight=1.0)           │
  │  2. Compute spectral similarity between the new SBE vector and  │
  │     the SBE vectors of all recent flows from other hosts         │
  │  3. For each pair (prev_flow, new_flow) whose similarity ×      │
  │     temporal_decay > causal_threshold, add a causal edge        │
  │  4. Return the updated CausalGraph snapshot                     │
  │                                                                  │
  │  Causal edge weight formula:                                     │
  │    ρ(i,j) = cosine(SBE_i, SBE_j) × exp(−Δt / τ)              │
  │                                                                  │
  │  Nodes older than `max_idle_seconds` are pruned automatically.  │
  └──────────────────────────────────────────────────────────────────┘
Key properties
--------------
* Thread-safe — uses RLock for all state mutations.
* Memory-bounded — each host stores at most `max_history` SBE vectors.
* APT-aware — distributed multi-hop attacks produce a dense connected
  subgraph in the causal layer; this density is quantified by
  `CausalGraph.causal_density()` and fed into the PHANTOM score.
* Works with and WITHOUT the SBE module — when no SBE vector is
  available, the engine still builds the flow topology graph.

Usage
-----
    ctgb = CausalTemporalGraphBuilder()
    graph = ctgb.update("10.0.0.1", "8.8.8.8", sbe_vector, time.time())
    print(graph.causal_density())     # 0.0 for first packet
    # … feed more packets …
    risk = ctgb.get_node_risk("10.0.0.1")
"""

from __future__ import annotations

import logging
import math
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

import numpy as np

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_TAU_S: float = 30.0       # causal time window (seconds)
_DEFAULT_THRESHOLD: float = 0.30   # minimum causal edge weight
_DEFAULT_MAX_HISTORY: int = 20     # SBE vectors kept per source IP
_DEFAULT_MAX_IDLE_S: float = 300.0 # prune nodes idle for 5 minutes
_DEFAULT_WINDOW_MS: int = 100      # graph snapshot window (milliseconds, advisory)
_MAX_EDGES: int = 200_000          # hard cap: prune immediately if exceeded


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class CausalEdge:
    """A directed edge in the causal graph."""

    src: str
    dst: str
    weight: float           # ρ(i,j) ∈ [0, 1]
    edge_type: str          # "flow" | "causal"
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "src": self.src,
            "dst": self.dst,
            "weight": round(self.weight, 4),
            "edge_type": self.edge_type,
            "timestamp": self.timestamp,
        }


@dataclass
class CausalNode:
    """A host node in the causal graph."""

    ip: str
    first_seen: float = field(default_factory=time.time)
    last_seen:  float = field(default_factory=time.time)

    # Cumulative risk contribution from causal edges involving this node
    causal_risk: float = 0.0


class CausalGraph:
    """
    Immutable snapshot of the causal graph at a point in time.

    Constructed by CausalTemporalGraphBuilder.update() and passed
    to downstream consumers (PHANTOMClassifier, IPSEngine).
    """

    def __init__(
        self,
        nodes: Dict[str, CausalNode],
        edges: List[CausalEdge],
        snapshot_time: float,
    ) -> None:
        self.nodes = nodes
        self.edges = edges
        self.snapshot_time = snapshot_time

        # Pre-computed indexes
        self._flow_edges   = [e for e in edges if e.edge_type == "flow"]
        self._causal_edges = [e for e in edges if e.edge_type == "causal"]

    # ------------------------------------------------------------------

    def causal_density(self) -> float:
        """
        Fraction of edges that are classified as 'causal'.

        A high density (> 0.5) indicates tightly correlated flows —
        a hallmark of beaconing C2, lateral movement, or APT pivoting.

        Returns float ∈ [0, 1].  Returns 0 if there are no edges.
        """
        total = len(self.edges)
        if total == 0:
            return 0.0
        return len(self._causal_edges) / total

    def mean_causal_weight(self) -> float:
        """Mean weight of all causal edges (0 if none)."""
        if not self._causal_edges:
            return 0.0
        return sum(e.weight for e in self._causal_edges) / len(self._causal_edges)

    def get_node_degree(self, ip: str) -> Tuple[int, int]:
        """Return (in_degree, out_degree) for *ip*."""
        in_d  = sum(1 for e in self.edges if e.dst == ip)
        out_d = sum(1 for e in self.edges if e.src == ip)
        return in_d, out_d

    def get_neighbors(self, ip: str) -> Set[str]:
        """Return all IPs that *ip* has edges to or from."""
        return {
            e.dst if e.src == ip else e.src
            for e in self.edges
            if e.src == ip or e.dst == ip
        }

    def risk_score(self, ip: str) -> float:
        """
        Composite risk score for a node ∈ [0, 1].

        Combines causal density of the **local subgraph** around
        the node with its cumulative causal_risk.
        """
        node = self.nodes.get(ip)
        if node is None:
            return 0.0

        local_edges = [e for e in self.edges if e.src == ip or e.dst == ip]
        local_causal = [e for e in local_edges if e.edge_type == "causal"]

        if not local_edges:
            return 0.0

        local_density = len(local_causal) / len(local_edges)
        mean_w = (
            sum(e.weight for e in local_causal) / len(local_causal)
            if local_causal else 0.0
        )
        return float(np.clip(local_density * 0.6 + mean_w * 0.4, 0.0, 1.0))

    def to_dict(self) -> dict:
        """Serialise to a JSON-compatible dict (for API / telemetry)."""
        return {
            "snapshot_time": self.snapshot_time,
            "node_count":    len(self.nodes),
            "edge_count":    len(self.edges),
            "causal_density": round(self.causal_density(), 4),
            "mean_causal_weight": round(self.mean_causal_weight(), 4),
            "edges": [e.to_dict() for e in self.edges[:50]],  # cap for API
        }

    def __repr__(self) -> str:
        return (
            f"CausalGraph(nodes={len(self.nodes)}, edges={len(self.edges)}, "
            f"causal_density={self.causal_density():.3f})"
        )


# ---------------------------------------------------------------------------
# SBE history entry
# ---------------------------------------------------------------------------

@dataclass
class _SBEEntry:
    """One historical SBE observation for a source IP."""
    sbe:       np.ndarray
    timestamp: float
    dst_ip:    str


# ---------------------------------------------------------------------------
# Causal Temporal Graph Builder
# ---------------------------------------------------------------------------

class CausalTemporalGraphBuilder:
    """
    Builds and maintains a live causal graph of host interactions.

    Parameters
    ----------
    tau              : float  — causal time window in seconds (default 30 s)
    causal_threshold : float  — minimum causal edge weight to materialise (default 0.30)
    max_history      : int    — max SBE vectors kept per source IP (default 20)
    max_idle_seconds : float  — prune nodes idle longer than this (default 300 s)
    """

    def __init__(
        self,
        tau: float = _DEFAULT_TAU_S,
        causal_threshold: float = _DEFAULT_THRESHOLD,
        max_history: int = _DEFAULT_MAX_HISTORY,
        max_idle_seconds: float = _DEFAULT_MAX_IDLE_S,
    ) -> None:
        self.tau = tau
        self.causal_threshold = causal_threshold
        self.max_history = max_history
        self.max_idle_seconds = max_idle_seconds

        self._lock = threading.RLock()

        # ip → deque of _SBEEntry (sliding window)
        self._history: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=self.max_history)
        )
        # ip → CausalNode (live node registry)
        self._nodes: Dict[str, CausalNode] = {}
        # All edges accumulated since last prune (bounded by max_idle_seconds)
        self._edges: List[CausalEdge] = []

        # Stats
        self._total_updates: int = 0
        self._total_causal_edges: int = 0
        self._last_prune_time: float = 0.0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def update(
        self,
        src_ip: str,
        dst_ip: str,
        sbe: Optional[np.ndarray],
        timestamp: Optional[float] = None,
    ) -> CausalGraph:
        """
        Process one flow event and return the updated CausalGraph.

        Parameters
        ----------
        src_ip    : source IP address string
        dst_ip    : destination IP address string
        sbe       : 256-dim SBE vector from Layer 1 (None if not available)
        timestamp : event time (default: time.time())

        Returns
        -------
        CausalGraph snapshot after incorporating this event.
        """
        if timestamp is None:
            timestamp = time.time()

        with self._lock:
            self._total_updates += 1

            # ── Ensure nodes exist ─────────────────────────────────────
            for ip in (src_ip, dst_ip):
                if ip not in self._nodes:
                    self._nodes[ip] = CausalNode(ip=ip, first_seen=timestamp)
                self._nodes[ip].last_seen = timestamp

            # ── Direct flow edge ─────────────────────────────────────
            flow_edge = CausalEdge(
                src=src_ip, dst=dst_ip,
                weight=1.0, edge_type="flow",
                timestamp=timestamp,
            )
            # Hard cap: prune immediately if the edge list would exceed
            # _MAX_EDGES.  Without this, a 100 kpps attack grows the list
            # by millions of entries in the 5-second prune window.
            if len(self._edges) >= _MAX_EDGES:
                logger.warning(
                    "CTGB: edge cap (%d) reached — forcing early prune.", _MAX_EDGES
                )
                self._prune_expired(timestamp)
            self._edges.append(flow_edge)

            # ── Causal edge discovery via spectral similarity ─────────────
            if sbe is not None:
                self._discover_causal_edges(src_ip, sbe, timestamp)
                # Store this SBE in history for future comparisons
                self._history[src_ip].append(
                    _SBEEntry(sbe=sbe, timestamp=timestamp, dst_ip=dst_ip)
                )

            # ── Prune stale nodes and edges (throttled every 5 seconds) ──
            if timestamp - self._last_prune_time > 5.0:
                self._prune_expired(timestamp)
                self._last_prune_time = timestamp

            # ── Build and return snapshot ───────────────────────────────
            return CausalGraph(
                nodes=dict(self._nodes),
                edges=list(self._edges),
                snapshot_time=timestamp,
            )

    def get_node_risk(self, ip: str) -> float:
        """
        Return the latest risk score for *ip* ∈ [0, 1].

        Syntactic sugar over the last graph snapshot's node.causal_risk.
        """
        with self._lock:
            node = self._nodes.get(ip)
            if node is None:
                return 0.0
            return float(np.clip(node.causal_risk, 0.0, 1.0))

    def reset(self) -> None:
        """Clear all state (useful between evaluation epochs)."""
        with self._lock:
            self._history.clear()
            self._nodes.clear()
            self._edges.clear()
            self._total_updates = 0
            self._total_causal_edges = 0
            self._last_prune_time = 0.0

    def stats(self) -> dict:
        with self._lock:
            return {
                "total_updates":       self._total_updates,
                "total_causal_edges":  self._total_causal_edges,
                "active_nodes":        len(self._nodes),
                "active_edges":        len(self._edges),
                "tau":                 self.tau,
                "causal_threshold":    self.causal_threshold,
            }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _discover_causal_edges(
        self,
        src_ip: str,
        sbe: np.ndarray,
        timestamp: float,
    ) -> None:
        """
        Compare *sbe* against all recent SBE vectors from other hosts.

        For each pair whose causal weight exceeds the threshold, a
        causal edge is materialised and added to self._edges.

        Must be called with self._lock held.
        """
        sbe_norm = np.linalg.norm(sbe)
        if sbe_norm < 1e-8:
            return   # zero vector — no spectral information

        # ── Pre-prune expired history entries (temporal decay cutoff) ──────────
        # temporal_decay = exp(-delta_t / tau) < 0.01 => delta_t > tau * 4.60517
        history_cutoff = timestamp - (self.tau * 4.60517)
        expired_ips = []
        for other_ip, history in list(self._history.items()):
            while history and history[0].timestamp < history_cutoff:
                history.popleft()
            if not history:
                expired_ips.append(other_ip)
        for other_ip in expired_ips:
            self._history.pop(other_ip, None)

        for other_ip, history in self._history.items():
            if other_ip == src_ip:
                continue  # skip self-comparison

            for entry in history:
                # Temporal decay
                delta_t = abs(timestamp - entry.timestamp)
                temporal_decay = math.exp(-delta_t / self.tau)
                if temporal_decay < 0.01:
                    continue  # too old — skip for efficiency

                # Cosine similarity
                entry_norm = np.linalg.norm(entry.sbe)
                if entry_norm < 1e-8:
                    continue
                cos_sim = float(np.dot(sbe, entry.sbe) / (sbe_norm * entry_norm))
                cos_sim = max(0.0, cos_sim)  # clamp negatives

                weight = cos_sim * temporal_decay

                if weight >= self.causal_threshold:
                    causal_edge = CausalEdge(
                        src=other_ip, dst=src_ip,
                        weight=weight, edge_type="causal",
                        timestamp=timestamp,
                    )
                    self._edges.append(causal_edge)
                    self._total_causal_edges += 1

                    # Update node causal risk (exponential moving average)
                    node = self._nodes.get(src_ip)
                    if node:
                        node.causal_risk = node.causal_risk * 0.7 + weight * 0.3

    def _prune_expired(self, now: float) -> None:
        """
        Remove nodes and edges that have been idle for too long.

        Keeps the graph memory-bounded for long-running deployments.
        Must be called with self._lock held.
        """
        cutoff = now - self.max_idle_seconds

        # Prune stale nodes
        stale_ips = [
            ip for ip, node in self._nodes.items()
            if node.last_seen < cutoff
        ]
        for ip in stale_ips:
            del self._nodes[ip]
            self._history.pop(ip, None)

        # Prune edges that reference stale nodes or are too old
        alive_ips = set(self._nodes.keys())
        self._edges = [
            e for e in self._edges
            if e.timestamp >= cutoff
            and e.src in alive_ips
            and e.dst in alive_ips
        ]
