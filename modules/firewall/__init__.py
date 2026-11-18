"""
Enterprise bunyanx — Firewall Module
========================================
Exports the primary plugin entry point for the inspection pipeline.
"""
from modules.firewall.engine.firewall_plugin import FirewallPlugin

__all__ = ["FirewallPlugin"]
