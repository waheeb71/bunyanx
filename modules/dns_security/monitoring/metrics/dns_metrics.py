"""
DNS Security — Prometheus Metrics
===================================
Module-scoped metrics. Scraped by the system-wide Prometheus at /metrics.

Metric catalogue:
  dns_queries_total              Counter   — all inspected queries by action/protocol
  dns_blocked_total              Counter   — blocked queries by category/severity
  dns_inspection_latency_seconds Histogram — end-to-end plugin latency
  dart_layer_latency_seconds     Histogram — per-DART-layer latency
  dart_detections_total          Counter   — DART decisions by verdict/layers_fired
  dart_resonance_score           Histogram — distribution of resonance scores
  dart_false_positive_total      Counter   — SOC-reviewed false positives (feedback loop)

All metrics carry the label: module="dns_security" for Grafana dashboard filtering.

If prometheus_client is not installed, all calls become silent no-ops so the
inspection pipeline is never broken by the observability layer.
"""

from __future__ import annotations

from typing import Optional


# ─── Try to import prometheus_client ──────────────────────────────────────────
try:
    from prometheus_client import Counter, Histogram, REGISTRY
    _PROM_AVAILABLE = True
except ImportError:
    _PROM_AVAILABLE = False


# ─── No-op shims (used when prometheus_client is absent) ──────────────────────

class _NoOpLabelled:
    def labels(self, **_) -> "_NoOpLabelled": return self
    def inc(self, _=1) -> None: pass
    def observe(self, _=0.0) -> None: pass

class _NoOpContext:
    def __enter__(self): return self
    def __exit__(self, *_): pass
    def labels(self, **_) -> "_NoOpContext": return self
    def time(self): return _NoOpContext()


# ─── Metric definitions ────────────────────────────────────────────────────────

def _safe_counter(name, doc, labels):
    if not _PROM_AVAILABLE:
        return _NoOpLabelled()
    try:
        return Counter(name, doc, labels)
    except Exception:
        # Already registered (happens during hot-reload in dev)
        return REGISTRY._names_to_collectors.get(name, _NoOpLabelled())


def _safe_histogram(name, doc, labels, buckets=None):
    if not _PROM_AVAILABLE:
        return _NoOpLabelled()
    kwargs = {"labelnames": labels}
    if buckets:
        kwargs["buckets"] = buckets
    try:
        return Histogram(name, doc, **kwargs)
    except Exception:
        return REGISTRY._names_to_collectors.get(name, _NoOpLabelled())


# ─── Singleton ─────────────────────────────────────────────────────────────────

class DNSMetrics:
    """
    Holds all Prometheus metrics for the dns_security module.
    Access via DNSMetrics.get() — guaranteed singleton.
    """

    _instance: Optional["DNSMetrics"] = None

    def __init__(self) -> None:
        # ── Query traffic ──────────────────────────────────────────────────
        self.QUERIES_TOTAL = _safe_counter(
            "dns_queries_total",
            "Total DNS queries inspected by the security plugin.",
            ["action", "protocol", "module"],
        )

        self.BLOCKED_TOTAL = _safe_counter(
            "dns_blocked_total",
            "DNS queries blocked, labelled by category and severity.",
            ["category", "severity", "module"],
        )

        self.INSPECTION_LATENCY = _safe_histogram(
            "dns_inspection_latency_seconds",
            "End-to-end latency of the DNS security inspection pipeline.",
            ["module"],
            buckets=[0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1],
        )

        # ── DART-specific ──────────────────────────────────────────────────
        self.DART_DETECTIONS = _safe_counter(
            "dart_detections_total",
            "DART engine final decisions, by verdict and number of layers triggered.",
            ["verdict", "layers_fired", "module"],
        )

        self.DART_RESONANCE = _safe_histogram(
            "dart_resonance_score",
            "Distribution of DART resonance scores across all queries.",
            ["module"],
            buckets=[0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.55, 0.6, 0.7, 0.8, 0.9, 1.0],
        )

        self.DART_LAYER_LATENCY = _safe_histogram(
            "dart_layer_latency_seconds",
            "Per-layer DART computation latency.",
            ["layer", "module"],
            buckets=[0.000001, 0.000005, 0.00001, 0.00005, 0.0001, 0.001],
        )

        self.DART_FALSE_POSITIVES = _safe_counter(
            "dart_false_positive_total",
            "DART alerts marked as false-positives during SOC review (feedback loop).",
            ["module"],
        )

        # ── Module label shorthand ─────────────────────────────────────────
        self._MODULE = "dns_security"

    # ── Factory ────────────────────────────────────────────────────────────────

    @classmethod
    def get(cls) -> "DNSMetrics":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    # ── Convenience helpers ────────────────────────────────────────────────────

    def record_query(self, action: str, protocol: str = "UDP") -> None:
        self.QUERIES_TOTAL.labels(
            action=action, protocol=protocol, module=self._MODULE
        ).inc()

    def record_block(self, category: str, severity: str = "HIGH") -> None:
        self.BLOCKED_TOTAL.labels(
            category=category, severity=severity, module=self._MODULE
        ).inc()

    def record_dart_decision(
        self, is_malicious: bool, resonance_score: float, layers_fired: int
    ) -> None:
        verdict = "malicious" if is_malicious else "clean"
        self.DART_DETECTIONS.labels(
            verdict=verdict,
            layers_fired=str(layers_fired),
            module=self._MODULE,
        ).inc()
        self.DART_RESONANCE.labels(module=self._MODULE).observe(resonance_score)

    def record_dart_layer_latency(self, layer: str, latency_seconds: float) -> None:
        """layer: 'lexical' | 'temporal' | 'graph' | 'fusion'"""
        self.DART_LAYER_LATENCY.labels(layer=layer, module=self._MODULE).observe(
            latency_seconds
        )

    def record_false_positive(self) -> None:
        """Call when a SOC analyst marks a DART alert as a false positive."""
        self.DART_FALSE_POSITIVES.labels(module=self._MODULE).inc()
