"""
Enterprise bunyanx - Transparent Proxy Netfilter Manager (Alias)
Re-exports TransparentProxyManager from transparent_netfilter_manager for backward compatibility.
"""
from modules.proxy.engine.transparent_netfilter_manager import TransparentProxyManager

__all__ = ["TransparentProxyManager"]
