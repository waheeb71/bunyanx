"""
bunyanx NGFW — HTTP Inspection Module (New-style BaseModule)
"""
import logging
from typing import Optional

from system.core.framework.base_module import BaseModule, ModuleManifest
from system.core.service_container import ServiceContainer

logger = logging.getLogger(__name__)


class HTTPInspectionModule(BaseModule):
    """Deep HTTP/HTTPS Protocol Inspection module."""

    def get_manifest(self) -> ModuleManifest:
        from pathlib import Path
        return ModuleManifest.from_yaml(
            str(Path(__file__).parent / 'manifest.yaml')
        )

    async def initialize(self, container: ServiceContainer) -> None:
        from modules.http_inspection.engine.http_inspector import HTTPInspector
        self._plugin = HTTPInspector()
        await super().initialize(container)

    def get_inspector_plugin(self):
        return self._plugin
