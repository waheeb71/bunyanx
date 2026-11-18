"""
Enterprise bunyanx — Firewall Async Telemetry (Logging Compatibility Shim)
Forwarding shim for modules.firewall.telemetry.async_logger to prevent
spawning duplicate QueueListener background threads.
"""

from modules.firewall.telemetry.async_logger import (
    JSONFormatter,
    AsyncFirewallLogger,
    firewall_telemetry,
)

__all__ = ["JSONFormatter", "AsyncFirewallLogger", "firewall_telemetry"]

