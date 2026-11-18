"""
bunyanx NGFW — UBA Module (New-style BaseModule)
"""
import logging
from typing import Any, Dict, Optional

from system.core.framework.base_module import BaseModule, ModuleManifest
from system.core.service_container import ServiceContainer

logger = logging.getLogger(__name__)


class UBAModule(BaseModule):
    """User Behavior Analytics module."""

    def __init__(self):
        super().__init__()
        self._plugin = None
        self._uba_engine = None

    def get_manifest(self) -> ModuleManifest:
        from pathlib import Path
        return ModuleManifest.from_yaml(
            str(Path(__file__).parent / 'manifest.yaml')
        )

    async def initialize(self, container: ServiceContainer) -> None:
        db = container.get_optional('db')
        from modules.uba.engine.core.uba_plugin import UBAPlugin
        self._plugin = UBAPlugin(db_manager=db)

        # Also expose the underlying analytics engine as a service
        from modules.uba.engine.user_behavior import UserBehaviorAnalytics
        self._uba_engine = UserBehaviorAnalytics(db)
        logger.info("✅ UserBehaviorAnalytics initialised inside UBAModule")

        await super().initialize(container)

    def get_inspector_plugin(self):
        return self._plugin

    def get_provided_services(self) -> Dict[str, Any]:
        services = {}
        if self._uba_engine:
            services['uba'] = self._uba_engine
        if self._plugin and hasattr(self._plugin, 'profiler'):
            services['uba_profiler'] = self._plugin.profiler
        return services

