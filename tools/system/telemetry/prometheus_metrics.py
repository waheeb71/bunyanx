#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enterprise bunyanx - Prometheus Metrics Integration

Provides /metrics endpoint for Prometheus monitoring with:
- Request counts by verdict
- Event processing metrics
- Decision engine statistics
- Component health metrics
"""

# Security Patch: Prevent Hard Import Crash if metrics are disabled/uninstalled
try:
    from prometheus_client import (
        Counter,
        Histogram,
        Gauge,
        Info,
        generate_latest,
        CONTENT_TYPE_LATEST
    )
except ImportError:
    CONTENT_TYPE_LATEST = "text/plain"
    
    class _DummyMetric:
        def __init__(self, *args, **kwargs): pass
        def labels(self, **kwargs): return self
        def inc(self, *args, **kwargs): pass
        def observe(self, *args, **kwargs): pass
        def set(self, *args, **kwargs): pass
        def info(self, *args, **kwargs): pass
        
    Counter = Histogram = Gauge = Info = _DummyMetric
    def generate_latest(): return b"# Prometheus client not installed\n"
import logging
from fastapi.responses import Response
import time

logger = logging.getLogger(__name__)


# ==================== Metrics Definitions ====================

# Events metrics
bunyanx_events_total = Counter(
    'bunyanx_events_total',
    'Total number of events processed',
    ['source_path', 'verdict']
)

bunyanx_events_buffered = Gauge(
    'bunyanx_events_buffered',
    'Number of events currently in buffer'
)

bunyanx_events_flushed_total = Counter(
    'bunyanx_events_flushed_total',
    'Total number of events flushed to backends'
)

# Decision engine metrics
bunyanx_decisions_total = Counter(
    'bunyanx_decisions_total',
    'Total number of decisions made',
    ['action', 'source']
)

bunyanx_rate_limited_total = Counter(
    'bunyanx_rate_limited_total',
    'Total number of rate limit actions'
)

bunyanx_quarantined_total = Counter(
    'bunyanx_quarantined_total',
    'Total number of quarantine actions'
)

# TTL Manager metrics
bunyanx_ttl_entries_active = Gauge(
    'bunyanx_ttl_entries_active',
    'Number of active TTL entries',
    ['action_type']
)

bunyanx_ttl_expired_total = Counter(
    'bunyanx_ttl_expired_total',
    'Total number of expired TTL entries'
)

# XDP metrics
bunyanx_xdp_packets_total = Counter(
    'bunyanx_xdp_packets_total',
    'Total packets processed by XDP',
    ['verdict']
)

bunyanx_xdp_bytes_total = Counter(
    'bunyanx_xdp_bytes_total',
    'Total bytes processed by XDP'
)

# ML metrics
bunyanx_ml_predictions_total = Counter(
    'bunyanx_ml_predictions_total',
    'Total ML predictions made',
    ['label']
)

bunyanx_ml_confidence = Histogram(
    'bunyanx_ml_confidence',
    'ML prediction confidence scores',
    buckets=[0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.99, 1.0]
)

# Backend metrics
bunyanx_backend_writes_total = Counter(
    'bunyanx_backend_writes_total',
    'Total writes to backends',
    ['backend_type', 'status']
)

bunyanx_backend_latency = Histogram(
    'bunyanx_backend_latency_seconds',
    'Backend write latency',
    ['backend_type'],
    buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]
)

# Component health
bunyanx_component_healthy = Gauge(
    'bunyanx_component_healthy',
    'Component health status (1=healthy, 0=unhealthy)',
    ['component']
)

# System info
bunyanx_info = Info(
    'bunyanx',
    'Enterprise bunyanx system information'
)


# ==================== Helper Functions ====================

def update_metrics_from_event_sink(event_sink):
    """
    Update metrics from event sink statistics
    
    Args:
        event_sink: UnifiedEventSink instance
    """
    if not event_sink:
        return
    
    try:
        stats = event_sink.get_statistics()
        
        # Update buffer gauge
        bunyanx_events_buffered.set(stats.get('buffer_size', 0))
        
        # Update backend metrics
        for backend_stats in stats.get('backends', []):
            backend_type = backend_stats.get('type', 'unknown')
            
            # Successful writes
            if 'events_written' in backend_stats:
                bunyanx_backend_writes_total.labels(
                    backend_type=backend_type,
                    status='success'
                ).inc(backend_stats['events_written'])
            
            # Failed writes  
            if 'events_failed' in backend_stats:
                bunyanx_backend_writes_total.labels(
                    backend_type=backend_type,
                    status='failure'
                ).inc(backend_stats['events_failed'])
                
    except Exception as e:
        # Log but don't crash
        logger.debug(f"Error updating event sink metrics: {e}")


def update_metrics_from_decision_engine(decision_engine):
    """
    Update metrics from decision engine
    
    Args:
        decision_engine: BlockingDecisionEngine instance
    """
    if not decision_engine:
        return
    
    try:
        stats = decision_engine.get_enhanced_statistics()
        
        # Decision counts
        for action in ['blocked', 'allowed', 'monitored', 'rate_limited', 'quarantined']:
            count = stats.get(f'{action}_decisions', 0)
            if count > 0:
                # Note: Prometheus counters only increase, can't set directly
                # This is示意性的 - actual implementation would track deltas
                pass
        
        # TTL manager stats
        ttl_stats = stats.get('ttl_manager', {})
        active_by_type = ttl_stats.get('active_by_type', {})
        
        for action_type, count in active_by_type.items():
            bunyanx_ttl_entries_active.labels(action_type=action_type).set(count)
            
    except Exception as e:
        logger.debug(f"Error updating decision engine metrics: {e}")


def update_component_health(health_checker):
    """
    Update component health metrics
    
    Args:
        health_checker: HealthChecker instance
    """
    if not health_checker:
        return
    
    try:
        # This would be async in real implementation
        # health_status = await health_checker.check_all_components()
        
        # For now, set basic components
        components = ['event_sink', 'decision_engine', 'xdp_engine', 'api']
        for component in components:
            # Would check actual health here
            bunyanx_component_healthy.labels(component=component).set(1)
            
    except Exception as e:
        logger.debug(f"Error updating component health: {e}")


def set_system_info(version: str = "1.0.0"):
    """
    Set system information metric
    
    Args:
        version: System version
    """
    import os
    bunyanx_info.info({
        'version': version,
        'mode': os.getenv('bunyanx_ENV', os.getenv('NGFW_ENV', 'production')),
        'features': 'xdp,ml,threat_intel'
    })


# ==================== FastAPI Integration ====================

async def metrics_endpoint():
    """
    Prometheus /metrics endpoint
    
    Returns:
        Response with Prometheus metrics
    """
    # Collect latest metrics
    metrics_data = generate_latest()
    
    return Response(
        content=metrics_data,
        media_type=CONTENT_TYPE_LATEST
    )


# ==================== Metric Recording Functions ====================

def record_event(source_path: str, verdict: str):
    """Record an event"""
    bunyanx_events_total.labels(
        source_path=source_path,
        verdict=verdict
    ).inc()


def record_event_flush(count: int):
    """Record events flushed"""
    bunyanx_events_flushed_total.inc(count)


def record_decision(action: str, source: str = 'policy'):
    """Record a decision"""
    bunyanx_decisions_total.labels(
        action=action,
        source=source
    ).inc()


def record_rate_limit():
    """Record rate limit action"""
    bunyanx_rate_limited_total.inc()


def record_quarantine():
    """Record quarantine action"""
    bunyanx_quarantined_total.inc()


def record_xdp_packet(verdict: str, bytes: int = 0):
    """Record XDP packet"""
    bunyanx_xdp_packets_total.labels(verdict=verdict).inc()
    if bytes > 0:
        bunyanx_xdp_bytes_total.inc(bytes)


def record_ml_prediction(label: str, confidence: float):
    """Record ML prediction"""
    bunyanx_ml_predictions_total.labels(label=label).inc()
    bunyanx_ml_confidence.observe(confidence)


def record_backend_write(backend_type: str, latency: float, success: bool = True):
    """Record backend write"""
    status = 'success' if success else 'failure'
    bunyanx_backend_writes_total.labels(
        backend_type=backend_type,
        status=status
    ).inc()
    
    if success:
        bunyanx_backend_latency.labels(backend_type=backend_type).observe(latency)


# Initialize system info
set_system_info()
