"""
bunyanx NGFW — Log Manager Module (New-style BaseModule)
"""
import logging
from typing import Optional

from system.core.framework.base_module import BaseModule, ModuleManifest
from system.core.service_container import ServiceContainer

logger = logging.getLogger(__name__)


class LogManagerModule(BaseModule):
    """Centralized Log Management module."""

    def __init__(self):
        super().__init__()
        self._plugin = None
        self._controller = None

    def get_manifest(self) -> ModuleManifest:
        from pathlib import Path
        return ModuleManifest.from_yaml(
            str(Path(__file__).parent / 'manifest.yaml')
        )

    async def initialize(self, container: ServiceContainer) -> None:
        try:
            from modules.log_manager.engine.plugin import LogManagerPlugin
            from modules.log_manager.engine.log_controller import LogControllerManager, setup_terminal_logging
            from modules.log_manager.config.loader import get_log_settings

            # Initialize memory logging
            setup_terminal_logging()

            # Initialize plugin and controller
            cfg = get_log_settings()
            self._plugin = LogManagerPlugin()
            self._plugin.initialize()
            self._controller = LogControllerManager.get_instance(cfg)

            # Register log_manager in ServiceContainer for cross-module injection
            if hasattr(container, 'register'):
                container.register("log_manager", self._controller)
                container.register("log_controller", self._controller)

            # Subscribe to central EventBus if present
            event_bus = getattr(container, 'event_bus', None)
            if event_bus and hasattr(event_bus, 'subscribe'):
                for event_type in ["security.alert", "traffic.flow", "system.audit"]:
                    event_bus.subscribe(event_type, self._handle_event_bus_msg)

            logger.info("LogManagerModule initialized and registered successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize LogManagerModule: {e}", exc_info=True)
            self._plugin = None
            self._controller = None

        await super().initialize(container)

    async def _handle_event_bus_msg(self, event_data: dict) -> None:
        """Callback to handle events emitted on central EventBus."""
        if self._controller and isinstance(event_data, dict):
            await self._controller.ingest_event(event_data)

    def get_inspector_plugin(self):
        return self._plugin

