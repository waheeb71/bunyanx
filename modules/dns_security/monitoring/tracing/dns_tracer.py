"""
DNS Security — OpenTelemetry Tracer
=====================================
Provides distributed tracing spans for each stage of the DNS inspection pipeline.

Trace hierarchy:
  dns.inspect                       ← root span (full plugin.inspect() call)
    ├─ dns.prefilter.ioc            ← Step 1: IOC / threat intel match
    ├─ dns.prefilter.tld            ← Step 2: suspicious TLD check  
    ├─ dns.prefilter.rate_limit     ← Step 3: rate limiter
    ├─ dns.prefilter.webfilter      ← Step 4: web filter category
    ├─ dns.prefilter.dga_legacy     ← Step 5: legacy Shannon entropy DGA
    ├─ dns.prefilter.tunneling      ← Step 6: legacy tunneling heuristics
    └─ dns.dart                     ← Step 7: DART triangulation (parent)
         ├─ dart.lexical            ← Layer 1 (S1)
         ├─ dart.temporal           ← Layer 2 (S2)
         ├─ dart.graph              ← Layer 3 (S3)
         └─ dart.fusion             ← Fusion engine

Integration: traces export to Tempo via OTLP gRPC (configured in system/config/base.yaml).
Silently degrades to a no-op context manager if opentelemetry is not installed.
"""

from __future__ import annotations

import contextlib
from typing import Any, Dict, Generator, Optional


# ─── Try to import OpenTelemetry ──────────────────────────────────────────────
try:
    from opentelemetry import trace
    from opentelemetry.trace import Span, StatusCode
    _OTEL_AVAILABLE = True
except ImportError:
    _OTEL_AVAILABLE = False


# ─── No-op shim ───────────────────────────────────────────────────────────────

class _NoOpSpan:
    """Duck-typed no-op span — zero overhead when OTEL is absent."""

    def set_attribute(self, *_, **__) -> None: pass
    def set_status(self, *_, **__) -> None:    pass
    def record_exception(self, *_, **__) -> None: pass
    def __enter__(self): return self
    def __exit__(self, *_): pass


# ─── Tracer Singleton ──────────────────────────────────────────────────────────

class DNSTracer:
    """
    Module-scoped OpenTelemetry tracer for dns_security.

    Usage:
        tracer = DNSTracer.get()

        with tracer.span("dns.dart") as root:
            root.set_attribute("dns.domain", domain)

            with tracer.span("dart.lexical") as s1_span:
                score, comps = lexical.analyze(domain)
                s1_span.set_attribute("dart.s1_score", score)
    """

    _instance: Optional["DNSTracer"] = None
    _SERVICE_NAME = "dns_security"

    def __init__(self) -> None:
        if _OTEL_AVAILABLE:
            self._tracer = trace.get_tracer(self._SERVICE_NAME)
        else:
            self._tracer = None

    @classmethod
    def get(cls) -> "DNSTracer":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @contextlib.contextmanager
    def span(
        self,
        name: str,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> Generator:
        """
        Context manager that creates an OTEL span (or a no-op if OTEL absent).

        Args:
            name:       span name, e.g. "dart.lexical"
            attributes: optional dict of span attributes to set on creation.

        Yields:
            The span object (real or no-op). Always safe to call .set_attribute() on it.
        """
        if not _OTEL_AVAILABLE or self._tracer is None:
            yield _NoOpSpan()
            return

        with self._tracer.start_as_current_span(name) as otel_span:
            if attributes:
                for k, v in attributes.items():
                    otel_span.set_attribute(k, v)
            try:
                yield otel_span
            except Exception as exc:
                otel_span.record_exception(exc)
                otel_span.set_status(StatusCode.ERROR, str(exc))
                raise

    @contextlib.contextmanager
    def dart_pipeline(
        self,
        domain: str,
        src_ip: str,
    ) -> Generator:
        """
        Convenience wrapper: creates the root DART trace span with standard attributes.

        with tracer.dart_pipeline(domain, src_ip) as root:
            ...
        """
        attrs = {
            "dns.domain": domain,
            "network.src.ip": src_ip,
            "service.name": self._SERVICE_NAME,
        }
        with self.span("dns.dart", attributes=attrs) as root_span:
            yield root_span
