"""
bunyanx NGFW — SSL Inspection Module (New-style BaseModule)
"""
import logging
from typing import Any, Dict, Optional

from system.core.framework.base_module import BaseModule, ModuleManifest
from system.core.service_container import ServiceContainer

logger = logging.getLogger(__name__)


class SSLInspectionModule(BaseModule):
    """TLS/SSL Deep Inspection module."""

    def get_manifest(self) -> ModuleManifest:
        from pathlib import Path
        return ModuleManifest.from_yaml(
            str(Path(__file__).parent / 'manifest.yaml')
        )

    async def initialize(self, container: ServiceContainer) -> None:
        config = container.get('config')
        from modules.ssl_inspection.engine.ca_pool import CAPoolManager
        from modules.ssl_inspection.engine.inspector import SSLInspector
        
        self._ca_manager = CAPoolManager(config)
        self._ssl_inspector = SSLInspector(self._ca_manager, config)
        await super().initialize(container)

    def get_provided_services(self) -> Dict[str, Any]:
        return {
            'ca_manager': self._ca_manager,
            'ssl_inspector': self._ssl_inspector,
        }
