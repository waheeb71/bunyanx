"""
DNS Security Module — Observability Stack
==========================================

Module-scoped observability (separate from the system-wide Loki/Prometheus).
Three pillars:

  logging/   → Structured JSON events per DNS decision (→ Loki stream: dns_security)
  metrics/   → Prometheus counters/histograms (→ /metrics scrape endpoint)
  tracing/   → OpenTelemetry spans per inspection stage (→ Tempo)

Usage from plugin.py:

    from modules.dns_security.monitoring import dns_logger, dns_metrics, dns_tracer

    with dns_tracer.span("dart.lexical"):
        s1, s1c = self._dart_lexical.analyze(domain)
    
    dns_metrics.DART_DETECTIONS.labels(verdict="malicious", layers="2").inc()
    dns_logger.log_dart_decision(domain, src_ip, dart_dec)
"""

from .logging.dns_logger  import DNSLogger
from .metrics.dns_metrics import DNSMetrics
from .tracing.dns_tracer  import DNSTracer

dns_logger  = DNSLogger.get()
dns_metrics = DNSMetrics.get()
dns_tracer  = DNSTracer.get()

__all__ = ["dns_logger", "dns_metrics", "dns_tracer", "DNSLogger", "DNSMetrics", "DNSTracer"]
