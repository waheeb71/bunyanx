"""
bunyanx NGFW — QoS Module (New-style BaseModule)
"""
import logging
from typing import Any, Dict, Optional

from system.core.framework.base_module import BaseModule, ModuleManifest
from system.core.service_container import ServiceContainer

logger = logging.getLogger(__name__)


class QoSModule(BaseModule):
    """Quality of Service and Bandwidth Management module."""

    def __init__(self):
        super().__init__()
        self._qos_manager = None
        self._plugin = None

    def get_manifest(self) -> ModuleManifest:
        from pathlib import Path
        return ModuleManifest.from_yaml(
            str(Path(__file__).parent / 'manifest.yaml')
        )

    async def initialize(self, container: ServiceContainer) -> None:
        db = container.get_optional('db')
        from modules.qos.qos_manager import QoSManager
        self._qos_manager = QoSManager.get_instance(db_manager=db)
        
        # Also load the pipeline plugin if available
        try:
            from modules.qos.engine.qos_plugin import QoSPlugin
            self._plugin = QoSPlugin()
        except Exception:
            pass
        
        await super().initialize(container)

    def get_inspector_plugin(self):
        return self._plugin

    def get_provided_services(self) -> Dict[str, Any]:
        if self._qos_manager:
            return {'qos_manager': self._qos_manager}
        return {}
