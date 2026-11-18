"""
bunyanx NGFW — IDS/IPS Module (New-style BaseModule)
"""
import logging
from typing import Any, Dict, Optional

from system.core.framework.base_module import BaseModule, ModuleManifest
from system.core.service_container import ServiceContainer

logger = logging.getLogger(__name__)


class IDSIPSModule(BaseModule):
    """PHANTOM IDS/IPS detection and prevention module."""

    def __init__(self):
        super().__init__()
        self._plugin = None
        self._anomaly_detector = None
        self._ips_engine = None

    def get_manifest(self) -> ModuleManifest:
        from pathlib import Path
        return ModuleManifest.from_yaml(
            str(Path(__file__).parent / 'manifest.yaml')
        )

    async def initialize(self, container: ServiceContainer) -> None:
        config    = container.get_optional('config') or {}
        ml_config = config.get('ml', {})

        # Inspector plugin
        from modules.ids_ips.engine.phantom_plugin import PHANTOMPlugin
        self._plugin = PHANTOMPlugin()

        # AnomalyDetector — provides 'anomaly_detector' service to other modules
        if ml_config.get('enabled', True):
            from modules.ids_ips.engine.anomaly_detector import AnomalyDetector
            anomaly_conf = ml_config.get('anomaly_detection', {})
            self._anomaly_detector = AnomalyDetector(
                contamination=ml_config.get('anomaly_contamination', 0.1),
                model_path=anomaly_conf.get('model_path'),
            )
            logger.info("✅ AnomalyDetector initialised inside IDSIPSModule")

        # IPSEngine — registers as a policy engine in PolicyManager
        from modules.ids_ips.engine.core.engine import IPSEngine
        self._ips_engine = IPSEngine()

        policy_mgr = container.get_optional('policy_manager')
        if policy_mgr:
            policy_mgr.register_engine('ips', self._ips_engine, priority=20)
            logger.info("✅ IPSEngine registered in PolicyManager (p=20)")

        await super().initialize(container)

    def get_inspector_plugin(self):
        return self._plugin

    def get_provided_services(self) -> Dict[str, Any]:
        services = {}
        if self._anomaly_detector:
            services['anomaly_detector'] = self._anomaly_detector
        if self._ips_engine:
            services['ips_engine'] = self._ips_engine
        return services
