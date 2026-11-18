"""
bunyanx NGFW — Proxy Module (New-style BaseModule)
====================================================
Manages Transparent, Forward, and Reverse proxy engines.

Migrated from engine.py._init_proxies (Phase 3 decoupling).
"""
import logging
from typing import Any, Dict, Optional

from system.core.framework.base_module import BaseModule, ModuleManifest, ModuleType
from system.core.service_container import ServiceContainer

logger = logging.getLogger(__name__)


class ProxyModule(BaseModule):
    """Transparent, Forward, and Reverse Proxy module."""

    def __init__(self):
        super().__init__()
        self.transparent_networking = None
        self.transparent_proxy = None
        self.forward_proxy = None
        self.reverse_proxy = None
        self.dns_server = None
        self._proxy_mode = 'transparent'

    def get_manifest(self) -> ModuleManifest:
        from pathlib import Path
        manifest_path = Path(__file__).parent / 'manifest.yaml'
        if manifest_path.exists():
            return ModuleManifest.from_yaml(str(manifest_path))
        # Fallback if manifest.yaml not present
        return ModuleManifest.from_dict({
            'name': 'proxy',
            'type': 'service',
            'description': 'Transparent, Forward, and Reverse Proxy',
            'requires': ['config', 'ca_manager', 'xdp_engine', 'event_sink', 'pipeline', 'flow_tracker'],
            'provides': ['transparent_proxy', 'dns_server'],
        })

    async def initialize(self, container: ServiceContainer) -> None:
        config    = container.get('config')
        ca_mgr    = container.get_optional('ca_manager')
        xdp       = container.get_optional('xdp_engine')
        event_sink= container.get_optional('event_sink')
        pipeline  = container.get_optional('pipeline')
        flow      = container.get_optional('flow_tracker')

        proxy_cfg = config.get('proxy', {})
        self._proxy_mode = proxy_cfg.get('mode', 'transparent')

        if self._proxy_mode in ('none', 'disabled', 'off'):
            logger.info("🔕 Proxy disabled — running in packet-filter only mode (XDP/eBPF)")
            await super().initialize(container)
            return

        from modules.proxy.engine.proxy_modes import TransparentProxy, ForwardProxy, ReverseProxy
        from modules.proxy.engine.transparent_netfilter_manager import TransparentProxyManager

        if self._proxy_mode in ('transparent', 'all'):
            self.transparent_networking = TransparentProxyManager(config)
            self.transparent_proxy = TransparentProxy(
                config, ca_mgr, xdp, event_sink,
                inspection_pipeline=pipeline
            )

        if self._proxy_mode in ('forward', 'all'):
            self.forward_proxy = ForwardProxy(
                config, ca_mgr, flow, event_sink,
                inspection_pipeline=pipeline
            )

        if self._proxy_mode in ('reverse', 'all'):
            self.reverse_proxy = ReverseProxy(
                config, ca_mgr, flow, event_sink,
                inspection_pipeline=pipeline
            )

        if not any([self.transparent_proxy, self.forward_proxy, self.reverse_proxy]):
            logger.warning(
                "⚠️ Unknown proxy mode '%s' — no proxy started. "
                "Valid values: transparent, forward, reverse, all, none",
                self._proxy_mode
            )

        # DNS Steering Server
        from modules.dns_security.engine.servers.dns_server import DNSServer
        self.dns_server = DNSServer(config, pipeline)

        await super().initialize(container)

    async def start(self) -> None:
        if self.transparent_proxy:
            import asyncio
            asyncio.ensure_future(self.transparent_proxy.start())
        if self.forward_proxy:
            import asyncio
            asyncio.ensure_future(self.forward_proxy.start())
        if self.reverse_proxy:
            import asyncio
            asyncio.ensure_future(self.reverse_proxy.start())
        if self.dns_server:
            import asyncio
            asyncio.ensure_future(self.dns_server.start())
        await super().start()

    async def stop(self) -> None:
        if self.transparent_proxy:
            await self.transparent_proxy.stop()
        if self.forward_proxy:
            await self.forward_proxy.stop()
        if self.reverse_proxy:
            await self.reverse_proxy.stop()
        await super().stop()

    def get_provided_services(self) -> Dict[str, Any]:
        services = {}
        if self.transparent_proxy:
            services['transparent_proxy']     = self.transparent_proxy
            services['transparent_networking'] = self.transparent_networking
        if self.forward_proxy:
            services['forward_proxy'] = self.forward_proxy
        if self.reverse_proxy:
            services['reverse_proxy'] = self.reverse_proxy
        if self.dns_server:
            services['dns_server'] = self.dns_server
        return services

    def get_netfilter_rules(self) -> Dict[str, list]:
        """Delegate nftables rules to TransparentProxyManager if active."""
        if self.transparent_networking:
            return self.transparent_networking.get_netfilter_rules()
        return {}

    async def reload_config(self, new_config_dict: Dict[str, Any]) -> None:
        """
        Dynamically reload running proxy instance configuration without full system restart.
        """
        logger.info("🔄 Dynamically reloading ProxyModule configuration...")
        proxy_cfg = new_config_dict.get('proxy', {})
        self._proxy_mode = proxy_cfg.get('mode', 'transparent')

        # Update running reverse proxy backends & VIPs if active
        if self.reverse_proxy:
            self.reverse_proxy.proxy_config = proxy_cfg
            vips_table = {}
            for vip in proxy_cfg.get('vips', []):
                key = (vip.get('external_ip'), int(vip.get('external_port', 80)))
                vips_table[key] = vip
            self.reverse_proxy.vips_table = vips_table
            self.reverse_proxy.backends = proxy_cfg.get('backends', self.reverse_proxy.backends)

        # Update transparent proxy config & VIPs if active
        if self.transparent_proxy:
            self.transparent_proxy.proxy_config = proxy_cfg
            self.transparent_proxy.vips = proxy_cfg.get('vips', [])
            vips_table = {}
            for vip in self.transparent_proxy.vips:
                key = (vip.get('external_ip'), vip.get('external_port'))
                vips_table[key] = vip
            self.transparent_proxy.vips_table = vips_table

        # Update forward proxy config if active
        if self.forward_proxy:
            self.forward_proxy.proxy_config = proxy_cfg

        logger.info("✅ ProxyModule dynamic config reload completed.")

