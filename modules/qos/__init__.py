"""
Enterprise bunyanx — Quality of Service (QoS) Module

Token Bucket-based per-IP bandwidth shaping engine with both synchronous
and asynchronous consumption paths, designed for inline integration with
the NGFW inspection pipeline and proxy relay loop.

Key Features:
  - Per-IP TokenBucket with configurable rate and burst limits
  - Dual-mode operation: "monitor" (log only) or "enforce" (block excess)
  - Singleton QoSManager shared between Pipeline and Proxy
  - Background Garbage Collector for inactive bucket pruning
  - DB-backed hot-reload via REST API
  - InspectionPipeline plugin (QoSPlugin) at LOWEST priority

Integration Points:
  - InspectionPipeline → QoSPlugin (sync check_traffic)
  - Proxy relay loop → QoSManager.throttle (async delay-to-refill)
  - REST API → /api/v1/qos/* (config, stats, reset)
"""

__version__ = "2.0.0"
__module_name__ = "qos"
