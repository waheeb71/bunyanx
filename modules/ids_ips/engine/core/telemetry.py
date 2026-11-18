"""
PHANTOM IDS/IPS — Unified Telemetry Facade
===========================================
Single integration point for all PHANTOM observability.
Combines:
  - Loki structured logging (phantom_logger.py)
  - Prometheus metrics (phantom_metrics.py)
  - Tempo/Jaeger traces (phantom_tracer.py)

Usage (in phantom_plugin.py):
    from modules.ids_ips.engine.core.telemetry import Telemetry
    t = Telemetry.instance()
    
    with t.trace.pipeline(src_ip, dst_ip):
        t.metrics.record_packet()
        t.log.threat(...)
"""
from __future__ import annotations
import logging

from modules.ids_ips.logging.phantom_logger import PhantomLogger
from modules.ids_ips.monitoring import phantom_metrics
from modules.ids_ips.tracing.phantom_tracer import PhantomTracer

logger = logging.getLogger(__name__)

class Telemetry:
    """Singleton facade for all PHANTOM observability (Logs, Metrics, Traces)."""
    
    _instance: Telemetry | None = None

    def __init__(self):
        self.log = PhantomLogger()
        self.metrics = phantom_metrics
        self.trace = PhantomTracer.instance()
        logger.info("PHANTOM Unified Telemetry facade initialized")

    @classmethod
    def instance(cls) -> Telemetry:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
