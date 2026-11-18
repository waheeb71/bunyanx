"""
bunyanx NGFW — Web Filter Module (New-style BaseModule)
"""
import logging
from typing import Any, Dict, Optional

from system.core.framework.base_module import BaseModule, ModuleManifest
from system.core.service_container import ServiceContainer

logger = logging.getLogger(__name__)


class WebFilterModule(BaseModule):
    """URL/Domain Web Content Filter module."""

    def __init__(self):
        super().__init__()
        self._plugin = None
        self._web_engine = None

    def get_manifest(self) -> ModuleManifest:
        from pathlib import Path
        return ModuleManifest.from_yaml(
            str(Path(__file__).parent / 'manifest.yaml')
        )

    async def initialize(self, container: ServiceContainer) -> None:
        from modules.web_filter.engine.plugin import WebFilterPlugin
        from modules.web_filter.policy.engine import WebFilterEngine

        self._plugin = WebFilterPlugin()
        self._web_engine = WebFilterEngine()

        # Register as web-style engine in PolicyManager (needs url/domain)
        policy_mgr = container.get_optional('policy_manager')
        if policy_mgr:
            policy_mgr.register_engine(
                'web_filter', self._web_engine,
                priority=60, web_style=True,
            )
            logger.info("✅ WebFilter policy engine registered (p=60, web_style=True)")

        await super().initialize(container)

    def get_inspector_plugin(self):
        return self._plugin

    def get_provided_services(self) -> Dict[str, Any]:
        services = {}
        if self._web_engine:
            services['web_engine'] = self._web_engine
        return services
