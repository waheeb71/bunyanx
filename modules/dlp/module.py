"""
bunyanx NGFW — DLP Module (New-style BaseModule)
"""
import logging
from typing import Optional

from system.core.framework.base_module import BaseModule, ModuleManifest
from system.core.service_container import ServiceContainer

logger = logging.getLogger(__name__)


class DLPModule(BaseModule):
    """Data Loss Prevention module."""

    def get_manifest(self) -> ModuleManifest:
        from pathlib import Path
        return ModuleManifest.from_yaml(
            str(Path(__file__).parent / 'manifest.yaml')
        )

    async def initialize(self, container: ServiceContainer) -> None:
        from modules.dlp.engine.dlp_inspector import DLPInspectorPlugin
        self._plugin = DLPInspectorPlugin()
        await super().initialize(container)

    def get_inspector_plugin(self):
        return self._plugin
