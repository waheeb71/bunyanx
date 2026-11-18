"""
bunyanx NGFW — Predictive AI Module (New-style BaseModule)
============================================================
Manages AEGIS v3 (AEGISEngine + TwoStageDefenseSystem) and
the legacy AIInspector pipeline plugin.

Migrated from engine.py._init_ml_components (Phase 3 decoupling).
"""
import logging
from typing import Any, Dict, Optional

from system.core.framework.base_module import BaseModule, ModuleManifest
from system.core.service_container import ServiceContainer

logger = logging.getLogger(__name__)


class PredictiveAIModule(BaseModule):
    """AEGIS v3 Predictive AI module."""

    def __init__(self):
        super().__init__()
        self._AEGIS_engine = None
        self._two_stage_system = None
        self._ai_inspector = None
        self._correlator = None

    def get_manifest(self) -> ModuleManifest:
        from pathlib import Path
        return ModuleManifest.from_yaml(
            str(Path(__file__).parent / 'manifest.yaml')
        )

    async def initialize(self, container: ServiceContainer) -> None:
        config = container.get_optional('config') or {}
        
        # Load local settings.yaml if predictive_ai config is missing
        if 'predictive_ai' not in config:
            from pathlib import Path
            import yaml
            settings_path = Path(__file__).parent / 'config' / 'settings.yaml'
            if settings_path.exists():
                try:
                    with open(settings_path, 'r', encoding='utf-8') as f:
                        yaml_cfg = yaml.safe_load(f) or {}
                        if 'predictive_ai' in yaml_cfg:
                            config['predictive_ai'] = yaml_cfg['predictive_ai']
                except Exception as ye:
                    logger.warning("Failed to load local settings.yaml: %s", ye)

        ml_config = config.get('ml', {})

        if not ml_config.get('enabled', True):
            logger.info("Predictive AI disabled via config — skipping AEGISEngine init.")
            await super().initialize(container)
            return

        # ── AEGIS v3: Stage 2 — Adaptive Defense Engine ──────────────
        from modules.predictive_ai.engine.AEGIS import AEGISEngine
        AEGIS_cfg = config.get('predictive_ai', {}).get('AEGIS', {})
        self._AEGIS_engine = AEGISEngine(
            ase_max_tracked_ips=AEGIS_cfg.get('performance', {}).get('max_tracked_ips', 4096),
            die_decoy_subnet=AEGIS_cfg.get('deception_engine', {}).get('decoy_subnet', '10.99.88.'),
            die_max_decoys=AEGIS_cfg.get('deception_engine', {}).get('max_active_decoys', 256),
            prevent_cpci_override_on_threats=AEGIS_cfg.get('prevent_cpci_override_on_threats', True),
        )
        logger.info("✅ AEGIS v3 Stage 2 — AEGISEngine initialised (ASE+AIS+CSO+DIE)")

        # ── PredictiveCorrelationEngine — Event Sink Bridge ───────────
        from modules.predictive_ai.engine.correlator import PredictiveCorrelationEngine, ForecastGate
        forecast_gate = ForecastGate()
        self._correlator = PredictiveCorrelationEngine(logger=logger)
        self._correlator.set_AEGIS(self._AEGIS_engine, forecast_gate)

        # ── EventBus Subscriptions ────────────────────────────────────
        event_bus = container.get_optional('event_bus')
        if event_bus:
            async def _on_security_threat_event(event_data):
                try:
                    await self._correlator.process_event(event_data)
                except Exception as err:
                    logger.debug("Predictive AI event handling error: %s", err)

            # Subscribe to all security event topics across the NGFW ecosystem
            threat_topics = [
                "threat.detected",
                "waf.block",
                "waf.alert",
                "ids.port_scan",
                "dns.threat",
                "dns.suspicious",
                "malware.detected",
                "email.threat",
                "web_filter.block",
                "dlp.incident",
                "anomaly.scored",
                "response.block",
                "response.quarantine",
                "response.alert",
            ]
            for topic in threat_topics:
                try:
                    event_bus.subscribe(topic, _on_security_threat_event)
                except Exception as ebs:
                    logger.debug("EventBus subscription to %s failed: %s", topic, ebs)
            logger.info("✅ Subscribed to %d security threat topics on EventBus", len(threat_topics))


        # ── AEGIS v3: Stage 1 — Threat Probability Engine (TPE) ──────
        tpe_cfg = config.get('predictive_ai', {}).get('tpe', {})
        try:
            from modules.predictive_ai.engine.tpe.pre_armed_adapter import TwoStageDefenseSystem
            from modules.predictive_ai.engine.tpe.risk_context import (
                OrganizationProfile, OrgSector, GeopoliticalZone, OrgSize,
                VulnerabilityContext, HistoricalBreachRecord,
            )
            raw_sector = tpe_cfg.get('org_sector', 'TECH').upper()
            if raw_sector == 'TECHNOLOGY':
                raw_sector = 'TECH'
            org_profile = OrganizationProfile(
                name=config.get('system', {}).get('org_name', 'bunyanx Deployment'),
                sector=OrgSector(raw_sector),
                geo_zone=GeopoliticalZone(tpe_cfg.get('org_geo_zone', 'STABLE').upper()),
                size=OrgSize(tpe_cfg.get('org_size', 'ENTERPRISE').upper()),
                vuln_context=VulnerabilityContext(
                    avg_epss=tpe_cfg.get('avg_epss', 0.10),
                    max_cvss=tpe_cfg.get('max_cvss', 6.0),
                ),
                breach_history=HistoricalBreachRecord(
                    breaches_last_12m=tpe_cfg.get('breaches_last_12m', 0),
                ),
            )
            self._two_stage_system = TwoStageDefenseSystem(org_profile)
            directive = self._two_stage_system.run_stage1()
            self._two_stage_system.apply_to_AEGIS(self._AEGIS_engine, directive)
            logger.info(
                "✅ AEGIS v3 Stage 1 — TPE assessed: score=%.3f level=%s pre_arm=%s",
                directive.threat_score, directive.risk_level, directive.pre_armed,
            )
        except Exception as tpe_err:
            logger.warning("TPE Stage 1 init failed (%s) — AEGIS running in standard mode.", tpe_err)

        # ── AIInspector — legacy pipeline plugin ───────────────────────
        try:
            from modules.predictive_ai.legacy_engine.ai_inspector import AIInspector
            self._ai_inspector = AIInspector()
            logger.info("✅ AIInspector created — will register in pipeline via get_inspector_plugin()")
        except ImportError as ie:
            logger.error("AIInspector not available — missing dependencies: %s", ie)
            raise RuntimeError(f"Strict Mode: Failed to load required AIInspector: {ie}")
        except Exception as ae:
            logger.error("AIInspector init failed: %s", ae)
            raise RuntimeError(f"Strict Mode: AIInspector init failed: {ae}")

        await super().initialize(container)

    def get_inspector_plugin(self):
        """Register AIInspector in the InspectionPipeline."""
        return self._ai_inspector

    def get_provided_services(self) -> Dict[str, Any]:
        services = {}
        if self._AEGIS_engine:
            services['AEGIS_engine'] = self._AEGIS_engine
        if self._two_stage_system:
            services['two_stage_system'] = self._two_stage_system
        if self._correlator:
            services['predictive_correlator'] = self._correlator
        return services
