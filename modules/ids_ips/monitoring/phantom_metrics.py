"""
PHANTOM IDS/IPS — Prometheus Metrics
=====================================
PHANTOM-specific Prometheus counters, histograms, and gauges.
Integrates with the system-level prometheus_metrics.py.

Metrics exposed:
  phantom_packets_inspected_total       — total packets through PHANTOM
  phantom_threats_detected_total        — threats by class
  phantom_packets_blocked_total         — blocked packets
  phantom_inference_duration_seconds    — per-packet inference latency
  phantom_pipeline_duration_seconds     — full pipeline latency
  phantom_causal_density               — current graph causal density (gauge)
  phantom_sbe_cache_hit_total          — SBE LRU cache hits
  phantom_sbe_cache_miss_total         — SBE LRU cache misses
  phantom_ocl_drifts_total             — ADWIN drift events
  phantom_ocl_memory_size              — SSF episodic memory size (gauge)
  phantom_graph_nodes                  — live hosts in causal graph (gauge)
  phantom_graph_causal_edges           — causal edges in graph (gauge)
"""
from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ── Lazy prometheus_client import (graceful if not installed) ─────────────────

_prom_ok = False
try:
    from prometheus_client import Counter, Histogram, Gauge
    _prom_ok = True
except ImportError:
    logger.warning("PHANTOM metrics: prometheus_client not installed — metrics disabled")

# ── Metric instances (None when prometheus unavailable) ───────────────────────

_packets_inspected:    Optional[object] = None
_threats_detected:     Optional[object] = None
_packets_blocked:      Optional[object] = None
_inference_duration:   Optional[object] = None
_pipeline_duration:    Optional[object] = None
_causal_density:       Optional[object] = None
_sbe_cache_hit:        Optional[object] = None
_sbe_cache_miss:       Optional[object] = None
_ocl_drifts:           Optional[object] = None
_ocl_memory_size:      Optional[object] = None
_graph_nodes:          Optional[object] = None
_graph_causal_edges:   Optional[object] = None

def _init() -> None:
    """Lazy init — called once on first use."""
    global _packets_inspected, _threats_detected, _packets_blocked
    global _inference_duration, _pipeline_duration, _causal_density
    global _sbe_cache_hit, _sbe_cache_miss
    global _ocl_drifts, _ocl_memory_size
    global _graph_nodes, _graph_causal_edges

    if not _prom_ok or _packets_inspected is not None:
        return

    try:
        _packets_inspected = Counter(
            'phantom_packets_inspected_total',
            'Total packets processed by PHANTOM IDS/IPS',
            ['protocol', 'direction'],
        )
        _threats_detected = Counter(
            'phantom_threats_detected_total',
            'Threats detected by PHANTOM, labelled by class',
            ['threat_class', 'severity'],
        )
        _packets_blocked = Counter(
            'phantom_packets_blocked_total',
            'Packets blocked by PHANTOM fusion decision',
            ['threat_class'],
        )
        _inference_duration = Histogram(
            'phantom_inference_duration_seconds',
            'Per-packet HGTC inference latency',
            buckets=[0.0001, 0.0005, 0.001, 0.002, 0.005, 0.010, 0.050],
        )
        _pipeline_duration = Histogram(
            'phantom_pipeline_duration_seconds',
            'Full PHANTOM pipeline latency (SBE+CTGB+HGTC+IPS+Fusion)',
            buckets=[0.0005, 0.001, 0.002, 0.005, 0.010, 0.025, 0.050, 0.100],
        )
        _causal_density = Gauge(
            'phantom_causal_density',
            'Current causal density of the CTGB host interaction graph',
        )
        _sbe_cache_hit = Counter(
            'phantom_sbe_cache_hit_total',
            'SBE LRU cache hits (avoids recomputing spectral encoding)',
        )
        _sbe_cache_miss = Counter(
            'phantom_sbe_cache_miss_total',
            'SBE LRU cache misses (full FFT+wavelet+entropy computed)',
        )
        _ocl_drifts = Counter(
            'phantom_ocl_drifts_total',
            'Number of concept drift events detected by ADWIN',
        )
        _ocl_memory_size = Gauge(
            'phantom_ocl_memory_size',
            'Current size of the SSF episodic memory buffer',
        )
        _graph_nodes = Gauge(
            'phantom_graph_nodes',
            'Number of live host nodes in the CTGB causal graph',
        )
        _graph_causal_edges = Gauge(
            'phantom_graph_causal_edges',
            'Number of causal edges in the CTGB host graph',
        )
        logger.info("PHANTOM Prometheus metrics registered")
    except Exception as exc:
        logger.warning("PHANTOM metrics init failed: %s", exc)


# ── Public recording API ──────────────────────────────────────────────────────

def record_packet(protocol: str = "TCP", direction: str = "inbound") -> None:
    """Call once per packet entering PHANTOM."""
    _init()
    if _packets_inspected:
        _packets_inspected.labels(protocol=protocol, direction=direction).inc()


def record_threat(threat_class: str, severity: str = "HIGH") -> None:
    """Call when PHANTOM marks is_threat=True."""
    _init()
    if _threats_detected:
        _threats_detected.labels(threat_class=threat_class, severity=severity).inc()


def record_block(threat_class: str) -> None:
    """Call when final_action == BLOCK."""
    _init()
    if _packets_blocked:
        _packets_blocked.labels(threat_class=threat_class).inc()


def record_inference_latency(seconds: float) -> None:
    """Record HGTC inference time in seconds."""
    _init()
    if _inference_duration:
        _inference_duration.observe(seconds)


def record_pipeline_latency(seconds: float) -> None:
    """Record full pipeline end-to-end time in seconds."""
    _init()
    if _pipeline_duration:
        _pipeline_duration.observe(seconds)


def set_causal_density(density: float) -> None:
    """Update CTGB causal density gauge (0.0 – 1.0)."""
    _init()
    if _causal_density:
        _causal_density.set(density)


def record_sbe_cache_hit() -> None:
    _init()
    if _sbe_cache_hit:
        _sbe_cache_hit.inc()


def record_sbe_cache_miss() -> None:
    _init()
    if _sbe_cache_miss:
        _sbe_cache_miss.inc()


def record_ocl_drift() -> None:
    """Call when ADWIN fires a drift event."""
    _init()
    if _ocl_drifts:
        _ocl_drifts.inc()


def set_ocl_memory_size(size: int) -> None:
    _init()
    if _ocl_memory_size:
        _ocl_memory_size.set(size)


def set_graph_topology(nodes: int, causal_edges: int) -> None:
    _init()
    if _graph_nodes:
        _graph_nodes.set(nodes)
    if _graph_causal_edges:
        _graph_causal_edges.set(causal_edges)
