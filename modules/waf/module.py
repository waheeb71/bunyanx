"""
bunyanx NGFW — WAF Module (New-style BaseModule)
"""
import logging
from typing import Optional

from system.core.framework.base_module import BaseModule, ModuleManifest
from system.core.service_container import ServiceContainer

logger = logging.getLogger(__name__)


class WAFModule(BaseModule):
    """AI-Powered Web Application Firewall module."""

    def get_manifest(self) -> ModuleManifest:
        from pathlib import Path
        return ModuleManifest.from_yaml(
            str(Path(__file__).parent / 'manifest.yaml')
        )

    async def initialize(self, container: ServiceContainer) -> None:
        from modules.waf.engine.waf_inspector import WAFInspectorPlugin
        self._plugin = WAFInspectorPlugin()
        await super().initialize(container)
        
        # Subscribe to global threat detection events
        try:
            from system.events.bus import EventBus
            from system.events.topics import Topics
            bus = await EventBus.instance()
            await bus.subscribe(Topics.THREAT_DETECTED, self._plugin.on_threat_detected)
            logger.info("WAFModule subscribed to %s", Topics.THREAT_DETECTED)
        except Exception as e:
            logger.warning("WAFModule event subscription failed: %s", e)

    def get_inspector_plugin(self):
        return self._plugin
