"""
PHANTOM IDS/IPS — OTel Tracing Adapter
=======================================
Wraps system.telemetry.otel_tracer.OTelTracer behind PHANTOM-specific
convenience spans so every pipeline layer appears as a named span in Tempo/Jaeger.

Span naming convention:
    phantom.sbe.encode
    phantom.ctgb.update
    phantom.hgtc.inference
    phantom.ocl.observe
    phantom.fusion.decide
    phantom.pipeline          ← root span, parents all layer spans

Usage (inside phantom_plugin.py):
    from modules.ids_ips.tracing.phantom_tracer import PhantomTracer
    tracer = PhantomTracer.instance()

    with tracer.pipeline(src_ip, dst_ip) as root:
        with tracer.sbe():
            sbe_vec = self._sbe.encode(payload)
        with tracer.ctgb() as s:
            graph = self._ctgb.update(...)
            s.set("causal_density", graph.causal_density())
        with tracer.hgtc() as s:
            result = self._phantom.predict(sbe_vec)
            s.set("threat_class", result.threat_class)
        root.set("action", final_action.name)
"""
from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Optional

logger = logging.getLogger(__name__)


class _NoOpSpan:
    """Returned when tracing is disabled — zero overhead."""
    def set(self, key, value) -> "_NoOpSpan":
        return self
    def set_status_ok(self): pass
    def set_status_error(self, msg=""): pass
    def __enter__(self): return self
    def __exit__(self, *a): pass


class PhantomTracer:
    """
    Singleton adapter that bridges PHANTOM layers to OTelTracer.
    Falls back silently if OTelTracer is unavailable.
    """
    _instance: Optional["PhantomTracer"] = None

    def __init__(self) -> None:
        self._otel = None
        try:
            from system.telemetry.otel_tracer import OTelTracer
            self._otel = OTelTracer.instance()
            logger.info("PhantomTracer: OTel tracing active")
        except Exception as exc:
            logger.debug("PhantomTracer: OTel unavailable (%s) — no-op mode", exc)

    @classmethod
    def instance(cls) -> "PhantomTracer":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    # ── Span helpers ──────────────────────────────────────────────────────────

    @contextmanager
    def pipeline(self, src_ip: str = "", dst_ip: str = ""):
        """Root span for the full PHANTOM pipeline."""
        if self._otel:
            with self._otel.span(
                "phantom.pipeline",
                src_ip=src_ip,
                dst_ip=dst_ip,
            ) as span:
                yield span
        else:
            yield _NoOpSpan()

    @contextmanager
    def sbe(self):
        """Span for Layer 1: Spectral Byte Encoding."""
        if self._otel:
            with self._otel.span("phantom.sbe.encode") as span:
                yield span
        else:
            yield _NoOpSpan()

    @contextmanager
    def ctgb(self):
        """Span for Layer 2: Causal Temporal Graph update."""
        if self._otel:
            with self._otel.span("phantom.ctgb.update") as span:
                yield span
        else:
            yield _NoOpSpan()

    @contextmanager
    def hgtc(self):
        """Span for Layer 3: Hybrid GNN-Transformer inference."""
        if self._otel:
            with self._otel.span("phantom.hgtc.inference") as span:
                yield span
        else:
            yield _NoOpSpan()

    @contextmanager
    def ocl(self):
        """Span for Layer 4: Online Continual Learner observe step."""
        if self._otel:
            with self._otel.span("phantom.ocl.observe") as span:
                yield span
        else:
            yield _NoOpSpan()

    @contextmanager
    def fusion(self):
        """Span for Layer 5: Fusion decision."""
        if self._otel:
            with self._otel.span("phantom.fusion.decide") as span:
                yield span
        else:
            yield _NoOpSpan()
