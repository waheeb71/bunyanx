"""
Enterprise bunyanx — Proxy Engine Module

Multi-mode network proxy with deep packet inspection, TLS interception,
and enterprise-grade security features.

Supported Modes:
  - TransparentProxy (MITMProxy): Gateway mode with SNI extraction,
    SO_ORIGINAL_DST, VIP mapping, and full TLS interception.
  - ForwardProxy: Explicit proxy with HTTP CONNECT MITM and graceful
    TLS degradation for cert-pinned clients.
  - ReverseProxy: Web application protection with health-aware
    least-connections load balancing and SSL termination.

Key Features:
  - Inline DPI via InspectionPipeline (WAF, IDS, DLP, UBA)
  - eBPF-accelerated domain blocking
  - QoS traffic throttling per client IP
  - HTTPCloaker for server banner hardening
  - Structured event emission to telemetry pipeline
"""

__version__ = "2.0.0"
__module_name__ = "proxy"
