"""
bunyanx NGFW — Application Controller (Phase 9: Rebuilt)
=============================================================
Slim orchestrator that:
  1. Loads configuration
  2. Initializes core infrastructure (DB, XDP, FlowTracker, EventSink)
  3. Registers core services in ServiceContainer
  4. Delegates ALL module loading to ModuleRegistry
  5. Wires system-level components (Acceleration, Correlation, HA, Proxies)
  6. Manages graceful shutdown via DAG-based tiers

All module-specific initialization (VPN, SIEM, AEGIS, QoS, etc.)
is handled by their BaseModule subclasses in modules/*/module.py.

No `from modules.*` imports at the top level — engine is fully decoupled.
"""

import asyncio
import logging
import signal
import sys
import yaml
import logging.handlers
from pathlib import Path
from typing import Optional

# ── System-level imports ONLY (zero module imports) ────────────────────────────
from system.core.router import TrafficRouter
from system.core.flow_tracker import FlowTracker
from system.core.framework.pipeline import InspectionPipeline
from system.core.service_container import ServiceContainer
from system.core.module_registry import ModuleRegistry
from system.core.path_manager import resolve_path
from system.database.database import DatabaseManager
from system.telemetry.events.unified_sink import create_unified_sink
from system.telemetry.health import HealthChecker

logger = logging.getLogger(__name__)

# ── Module-level singleton (used by API router lazy accessor) ─────────────────
_app_instance: Optional['bunyanxApplication'] = None
_app_singleton: Optional['bunyanxApplication'] = None


class bunyanxApplication:
    """
    Main bunyanx Application Controller.

    Phase 9: Refactored to use ServiceContainer + ModuleRegistry.
    Module-specific init is delegated to BaseModule subclasses.
    """

    def __init__(self, config_path: Path):
        global _app_instance, _app_singleton
        _app_instance = self
        _app_singleton = self

        self.config_path = config_path
        self.config: Optional[dict] = None

        # ── Database path resolution (3-tier priority) ─────────────────────────
        # 1. bunyanx_DATABASE_URL  env var → full URL (PostgreSQL, etc.)
        # 2. bunyanx_DB_PATH       env var → custom SQLite path
        # 3. base.yaml database.path       → configured path
        # 4. Fallback                       → data/bunyanx.db (project root)
        import os as _os
        _project_root = Path(__file__).resolve().parent.parent.parent  # enterprise_ngfw/
        _db_url = _os.environ.get('bunyanx_DATABASE_URL', '').strip()
        if not _db_url:
            _db_path_str = (
                _os.environ.get('bunyanx_DB_PATH', '').strip()
                or ''  # resolved after config load below
            )
            # _db_path_str may be empty until config is loaded; will be resolved in start()
            _db_path = Path(_db_path_str) if _db_path_str else (_project_root / 'data' / 'bunyanx.db')
            _db_url = f"sqlite:///{_db_path.resolve()}"

        self.db = DatabaseManager(_db_url)


        # Core infrastructure
        self.traffic_router: Optional[TrafficRouter] = None
        self.flow_tracker: Optional[FlowTracker] = None
        self.xdp_engine = None
        self.ca_manager = None
        self.ssl_inspector = None
        self.event_sink = None
        self.health_checker: Optional[HealthChecker] = None
        self.inspection_pipeline: Optional[InspectionPipeline] = None

        # Phase 9: DI + Module lifecycle
        self.container: Optional[ServiceContainer] = None
        self.module_registry: Optional[ModuleRegistry] = None

        # System-level wiring
        self.acceleration_bridge = None
        self.correlation_engine = None

        # HA clustering
        self.ha_manager = None
        self.state_sync = None
        self.is_ha_master: bool = True

        # Proxy engines
        self.transparent_proxy = None
        self.forward_proxy = None
        self.reverse_proxy = None
        self.transparent_networking = None
        self.dns_server = None

        # System services
        self.siem_connector = None
        self.ttl_manager = None

        # ML / AEGIS (backward-compat attributes — populated in _init_ml)
        self.anomaly_detector = None
        self.AEGIS_engine = None
        self.two_stage_system = None
        self.orchestrator = None
        self.recovery_manager = None
        self.vulnerability_predictor = None
        self.uba = None
        self.predictive_correlator = None
        self.forecast_gate = None

        # Module attributes (backward-compat — populated from container)
        self.vpn_manager = None
        self.vpn_enabled: bool = False
        self.vpn_portal = None
        self.qos_manager = None

        # Runtime
        self.running = False
        self.engine_running = False
        self._engine_tasks = []
        self.shutdown_event = asyncio.Event()
        self._start_time: Optional[float] = None

    # ══════════════════════════════════════════════════════════════════════════
    # Configuration
    # ══════════════════════════════════════════════════════════════════════════

    def load_config(self):
        logger.info(f"Loading configuration from {self.config_path}")
        try:
            from system.config.config_manager import ConfigManager
            config_mgr = ConfigManager(self.config_path.parent)
            ConfigManager._instance = config_mgr
            self.config = config_mgr.get_all()

            def on_config_reload(new_config):
                logger.info("⚙️ Core application configuration updated via hot-reload")
                self.config = new_config
                if self.container:
                    self.container.register('config', new_config)

            config_mgr.on_reload(on_config_reload)
            logger.info("✅ Configuration loaded successfully via ConfigManager")

            required_sections = ['proxy', 'tls']
            for section in required_sections:
                if section not in self.config:
                    logger.error(f"Missing required configuration section: {section}")
                    sys.exit(1)

            # ── Re-resolve DB path now that config is loaded ─────────────────
            # Priority: bunyanx_DATABASE_URL > bunyanx_DB_PATH > base.yaml > fallback
            import os as _os
            if not _os.environ.get('bunyanx_DATABASE_URL') and not _os.environ.get('bunyanx_DB_PATH'):
                _conf_db_path = self.config.get('database', {}).get('path', '')
                if _conf_db_path:
                    _project_root = Path(__file__).resolve().parent.parent.parent
                    _resolved = (
                        Path(_conf_db_path)
                        if Path(_conf_db_path).is_absolute()
                        else _project_root / _conf_db_path
                    )
                    _resolved.parent.mkdir(parents=True, exist_ok=True)
                    _new_url = f"sqlite:///{_resolved.resolve()}"
                    if _new_url != self.db.sync_url:
                        logger.info("🗄️  DB path from base.yaml: %s", _resolved.resolve())
                        self.db = DatabaseManager(_new_url)

            proxy_mode = self.config.get('proxy', {}).get('mode', 'transparent')
            logger.info(f"🔥 Proxy mode: {proxy_mode}")

            self.setup_file_logging()

        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            sys.exit(1)


    def setup_file_logging(self):
        """Setup rolling file logging based on centralized Log Manager configuration"""
        log_config = self.config.get('modules', {}).get('log_manager', {})
        log_file = resolve_path(log_config.get('main_log_file', 'data/logs/bunyanx.log'))
        log_file.parent.mkdir(parents=True, exist_ok=True)

        # Check if already has file handlers to prevent duplication on reload
        root_logger = logging.getLogger()
        for handler in root_logger.handlers:
            if isinstance(handler, logging.handlers.RotatingFileHandler):
                return

        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=log_config.get('max_file_size_bytes', 104857600),
            backupCount=log_config.get('backup_count', 10),
            encoding='utf-8'
        )
        file_handler.setFormatter(
            logging.Formatter(
                '%(asctime)s [%(levelname)8s] %(name)s: %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
        )
        root_logger.addHandler(file_handler)
        logger.info(f"✅ Rolling Log File configured: {log_file}")

    def reload_config(self):
        logger.info("Hot-reloading config.")
        self.load_config()

    def get_uptime(self) -> float:
        """Return system uptime in seconds since application start."""
        if self._start_time is None:
            return 0.0
        import time
        return time.monotonic() - self._start_time

    # ══════════════════════════════════════════════════════════════════════════
    # Component Initialization (Phase 9: Decomposed)
    # ══════════════════════════════════════════════════════════════════════════

    async def initialize_components(self):
        import time
        self._start_time = time.monotonic()
        global _app_instance
        _app_instance = self
        logger.info("Initializing components...")
        await self.db.initialize()
        logger.info("✅ Database initialized")

        # ── Hardware Appliance OOBE ──
        try:
            from system.networking.appliance.os_init.out_of_box_setup import setup_oobe_mgmt
            setup_oobe_mgmt()
        except Exception as _e:
            logger.warning(f"Skipping Appliance OOBE (Init failed): {_e}")

        # ── Network Auto-Configuration ──
        try:
            from system.networking.appliance.network_auto_configurator import NetworkAutoConfigurator
            net_configurator = NetworkAutoConfigurator(self.config)
            net_configurator.auto_configure()
            logger.info("✅ Network Auto-Configurator completed")
        except Exception as _net_err:
            logger.warning(f"Network Auto-Configuration skipped (non-fatal): {_net_err}")

        try:
            await self._init_core_infrastructure()
            await self._init_service_container()
            await self._init_module_registry()
            await self._init_acceleration_and_correlation()
            await self._init_ml_components()
            await self._init_vpn()
            await self._init_ha()
            await self._init_proxies()
            await self._init_siem()
            await self._init_ttl_manager()

            # ── Audio Alert System (must start AFTER EventBus is ready) ──
            # Starting here (not in start_firewall_components) ensures
            # EventSubscriber registers on the EventBus BEFORE any module
            # begins publishing events, preventing missed alerts.
            try:
                from system.audio.audio_manager import AudioManager
                audio_mgr = await AudioManager.instance()
                await audio_mgr.start()
                logger.info("✅ Audio Alert System started (EventSubscriber registered)")
            except Exception as _ae:
                logger.warning(f"[AudioManager] Could not start Audio Alert System: {_ae}")

            logger.info("✅ All components initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize components: {e}", exc_info=True)
            raise

    async def _init_core_infrastructure(self):
        """Create core engines that modules depend on."""
        logger.info("Initializing Core Engines...")
        # NOTE: ca_manager and ssl_inspector are now provided by SSLInspectionModule
        # via ServiceContainer. No direct imports from modules.ssl_inspection here.
        from acceleration.ebpf.xdp_engine import create_xdp_engine

        # Placeholder — will be populated by SSLInspectionModule.get_provided_services()
        self.ca_manager = None
        self.ssl_inspector = None
        self.traffic_router = TrafficRouter(self.config)

        log_mgr_conf = self.config.get('modules', {}).get('log_manager', {})
        sink_conf = log_mgr_conf.get('event_sink', {})
        self.event_sink = create_unified_sink(sink_conf)
        await self.event_sink.start()

        self.flow_tracker = FlowTracker(self.config)
        self.xdp_engine = create_xdp_engine(self.config, self.event_sink)
        self.flow_tracker.set_xdp_engine(self.xdp_engine)
        self.health_checker = HealthChecker(self)
        self.inspection_pipeline = InspectionPipeline()

    async def _init_service_container(self):
        """Register all core services in the DI container."""
        logger.info("Registering Core Services in ServiceContainer...")
        self.container = ServiceContainer.instance()
        self.container.register('db', self.db)
        self.container.register('config', self.config)
        self.container.register('xdp_engine', self.xdp_engine)
        self.container.register('pipeline', self.inspection_pipeline)
        self.container.register('flow_tracker', self.flow_tracker)
        self.container.register('event_sink', self.event_sink)
        self.container.register('traffic_router', self.traffic_router)

        # PolicyManager registered BEFORE modules so they can self-register engines
        from system.policy.manager import PolicyManager
        self.policy_manager = PolicyManager(self.config)
        self.container.register('policy_manager', self.policy_manager)

        # NOTE: ca_manager and ssl_inspector are registered by SSLInspectionModule
        # via get_provided_services() during _init_module_registry.
        logger.info("✅ ServiceContainer: %d core services", len(self.container.list_services()))


    async def _init_module_registry(self):
        """Discover, load, initialize, and start ALL modules via ModuleRegistry."""
        logger.info("Loading Modules via ModuleRegistry...")
        self.module_registry = ModuleRegistry(
            self.config, self.inspection_pipeline, self.container,
        )
        await self.module_registry.discover_and_load()
        await self.module_registry.initialize_all()
        await self.module_registry.start_all()

        # Sync backward-compat attributes from container after modules registered their services
        self.qos_manager   = self.container.get_optional('qos_manager')
        self.ca_manager    = self.container.get_optional('ca_manager')
        self.ssl_inspector = self.container.get_optional('ssl_inspector')

        # Wire the fully-populated PolicyManager into TrafficRouter's PolicyIntegrator
        if self.traffic_router and hasattr(self.traffic_router, 'policy_integrator'):
            self.traffic_router.policy_integrator.policy_manager = self.policy_manager
            logger.info(
                "✅ PolicyManager wired into TrafficRouter (%d engines registered)",
                len(self.policy_manager.list_engines()),
            )

        logger.info("✅ ModuleRegistry: %d modules active", len(self.module_registry.list_modules()))



    async def _init_acceleration_and_correlation(self):
        """Wire EventBus → XDP kernel blocks + multi-threat correlation."""
        logger.info("Starting Acceleration Bridge...")
        from system.core.acceleration_bridge import AccelerationBridge
        self.acceleration_bridge = AccelerationBridge(xdp_engine=self.xdp_engine)
        await self.acceleration_bridge.start()
        logger.info("✅ AccelerationBridge started — EventBus → XDP kernel wired")

        logger.info("Starting Correlation Engine...")
        from system.core.correlation_engine import CorrelationEngine
        self.correlation_engine = CorrelationEngine.instance()
        await self.correlation_engine.start()
        logger.info("✅ CorrelationEngine started — threat correlation active")

    async def _init_ml_components(self):
        """Sync ML/AI references from ServiceContainer and wire cross-cutting concerns.

        NOTE (Phase 3): Module-specific init moved to their respective BaseModule subclasses:
          - AnomalyDetector  → IDSIPSModule   (modules/ids_ips/module.py)
          - AEGISEngine     → PredictiveAIModule (modules/predictive_ai/module.py)
          - UserBehaviorAnalytics → UBAModule (modules/uba/module.py)
          - AIInspector      → PredictiveAIModule.get_inspector_plugin()

        This method only handles cross-cutting wiring that belongs to the engine:
          - MitigationOrchestrator (system/response)
          - PredictiveCorrelationEngine + ForecastGate (system/ml_core)
          - Wiring event_sink observer and flow_tracker analytics
        """
        ml_config = self.config.get('ml', {})
        if not ml_config.get('enabled', True):
            return

        logger.info("Wiring ML cross-cutting concerns...")

        # Sync module-provided references from ServiceContainer
        self.anomaly_detector = self.container.get_optional('anomaly_detector')
        self.AEGIS_engine    = self.container.get_optional('AEGIS_engine')
        self.uba              = self.container.get_optional('uba')

        # ── Mitigation Orchestrator (always available) ────────────────────────
        from system.response import MitigationOrchestrator, RecoveryManager
        self.orchestrator     = MitigationOrchestrator(logger=logger, ebpf_engine=self.xdp_engine)
        self.recovery_manager = RecoveryManager()

        # ── Predictive Correlation Engine (fault-tolerant import) ─────────────
        # correlator.py lives in modules/predictive_ai/engine/correlator.py.
        # If the file is missing (e.g. fresh deploy without full sync) we fall
        # back to lightweight no-op stubs so the rest of the engine can start.
        try:
            from modules.predictive_ai.engine.correlator import (
                PredictiveCorrelationEngine,
                ForecastGate,
            )
            self.predictive_correlator = PredictiveCorrelationEngine(
                orchestrator=self.orchestrator, logger=logger
            )
            self.forecast_gate = ForecastGate()
            logger.info("✅ PredictiveCorrelationEngine loaded from modules.predictive_ai")

        except ImportError as _corr_err:
            logger.warning(
                f"⚠️  modules.predictive_ai.engine.correlator not found "
                f"({_corr_err}). AEGIS v3 correlation layer will be inactive. "
                f"Ensure correlator.py is present in modules/predictive_ai/engine/."
            )

            # ── No-op stubs so the engine starts cleanly ──────────────────────
            class _NoopCorrelator:
                """Placeholder when correlator.py is unavailable."""
                async def process_event(self, event): pass
                def set_AEGIS(self, **kw): pass

            class _NoopForecastGate:
                """Placeholder when correlator.py is unavailable."""
                def record_decision(self, *a, **kw): pass
                def get_budget(self): return {}

            self.predictive_correlator = _NoopCorrelator()
            self.forecast_gate         = _NoopForecastGate()

        # ── VulnerabilityPredictor ────────────────────────────────────────────
        # Provided by predictive_ai module via ServiceContainer.
        # Fall back to a no-op stub if the module is not loaded.
        self.vulnerability_predictor = self.container.get_optional('vulnerability_predictor')
        if self.vulnerability_predictor is None:
            class _NoopVulnPredictor:
                def predict(self, *a, **kw): return None
                def get_metrics(self): return {}
            self.vulnerability_predictor = _NoopVulnPredictor()
            logger.debug("VulnerabilityPredictor not in ServiceContainer — using no-op stub")

        # ── Wire components together ──────────────────────────────────────────
        if self.event_sink:
            self.event_sink.register_observer(self.predictive_correlator.process_event)
            logger.info("✅ Correlation Engine wired to Unified Event Sink → AEGIS v3")

        # Inject AEGISEngine + ForecastGate into correlator
        # (avoids predictive_ai.py importing system.core.engine — circular dep)
        if hasattr(self.predictive_correlator, 'set_AEGIS'):
            self.predictive_correlator.set_AEGIS(
                AEGIS_engine=self.AEGIS_engine,
                forecast_gate=self.forecast_gate,
            )

        if self.flow_tracker:
            self.flow_tracker.set_analytics(self.uba, self.vulnerability_predictor)
        if self.traffic_router:
            self.traffic_router.set_orchestrator(self.orchestrator)

        logger.info("✅ ML cross-cutting wiring complete")




    async def _init_vpn(self):
        """Initialize WireGuard VPN if enabled.

        NOTE (Phase 3): VPN lifecycle is now managed by VPNModule (modules/vpn/module.py).
        The module initialises WireGuardManager and registers it in ServiceContainer.
        This method only syncs backward-compat attributes and runs DB persistence.
        """
        vpn_config = self.config.get('vpn', {}) or self.config.get('modules', {}).get('vpn', {})
        self.vpn_enabled = vpn_config.get('enabled', False)
        if not self.vpn_enabled:
            return

        # Pull from ServiceContainer — populated by VPNModule.get_provided_services()
        self.vpn_manager = self.container.get_optional('vpn_manager')
        self.vpn_portal  = self.container.get_optional('vpn_portal')

        if self.vpn_manager:
            vpn_ip   = vpn_config.get('ip_address', '10.99.0.1/24')
            vpn_port = vpn_config.get('listen_port', 51820)
            interface_name = vpn_config.get('interface', 'wg0')
            # DB persistence (engine responsibility — not VPNModule's)
            await self._save_vpn_config_to_db(interface_name, vpn_ip, vpn_port)
            await self._load_vpn_peers_from_db()
        else:
            logger.warning("[VPN] vpn_manager not found in ServiceContainer — VPNModule may not be loaded.")

        # VPN Portal — also provided by VPNModule; wire event callback if present
        if self.vpn_portal and hasattr(self.vpn_portal, 'set_event_callback'):
            self.vpn_portal.set_event_callback(self._vpn_portal_event_callback)



    async def _init_ha(self):
        """Initialize HA clustering if enabled."""
        ha_config = self.config.get('ha', {})
        if not ha_config.get('enabled', False):
            self.is_ha_master = True
            return

        logger.info("Initializing HA...")
        from system.ha import LeaderElection
        from system.ha.state_sync import StateSynchronizer

        peer_ip = ha_config.get('peer_ip', '127.0.0.1')
        self.ha_manager = LeaderElection.instance()
        self.state_sync = StateSynchronizer(peer_ip=peer_ip, logger=logger)
        self.state_sync.set_vpn_session_callback(self._on_vpn_session_sync)

        @self.ha_manager.on_become_leader
        async def _on_leader():
            self.is_ha_master = True
            if getattr(self, 'state_sync', None):
                await self.state_sync.start(True)
            logger.info("HA State changed! Currently Master: True")

        @self.ha_manager.on_lose_leadership
        async def _on_follower():
            self.is_ha_master = False
            if getattr(self, 'state_sync', None):
                await self.state_sync.start(False)
            logger.info("HA State changed! Currently Master: False")

        await self.ha_manager.start()
        self.is_ha_master = self.ha_manager.is_leader
        await self.state_sync.start(self.is_ha_master)

    async def _init_proxies(self):
        """Sync proxy engine references from ServiceContainer.

        NOTE (Phase 3): Proxy lifecycle is now managed by ProxyModule (modules/proxy/module.py).
        The module initialises TransparentProxy, ForwardProxy, ReverseProxy and DNSServer,
        then registers them in ServiceContainer via get_provided_services().
        This method only syncs backward-compat attributes on the engine instance.
        """
        self.transparent_networking = self.container.get_optional('transparent_networking')
        self.transparent_proxy      = self.container.get_optional('transparent_proxy')
        self.forward_proxy          = self.container.get_optional('forward_proxy')
        self.reverse_proxy          = self.container.get_optional('reverse_proxy')
        self.dns_server             = self.container.get_optional('dns_server')

        proxy_mode = self.config.get('proxy', {}).get('mode', 'transparent')
        if proxy_mode not in ('none', 'disabled', 'off'):
            if not any([self.transparent_proxy, self.forward_proxy, self.reverse_proxy]):
                logger.warning(
                    "⚠️ No proxy engines found in ServiceContainer for mode '%s'. "
                    "Ensure ProxyModule is loaded and enabled.", proxy_mode
                )


    async def _init_siem(self):
        """Initialize SIEM Connector and wire to EventSink."""
        try:
            from system.siem.siem_connector import create_siem_connector, SIEMEvent
            self.siem_connector = create_siem_connector(self.config)
            if not self.siem_connector:
                logger.info("ℹ️ SIEM Connector disabled or not configured (siem.enabled=false)")
                return

            await self.siem_connector.start()
            logger.info("✅ SIEM Connector started — security events will be forwarded")

            # Wire as observer to UnifiedEventSink
            if self.event_sink:
                async def siem_forwarder(event):
                    try:
                        from datetime import datetime
                        timestamp_str = getattr(event, "timestamp", None)
                        if hasattr(timestamp_str, "isoformat"):
                            timestamp_str = timestamp_str.isoformat()
                        elif not timestamp_str:
                            timestamp_str = datetime.utcnow().isoformat()

                        verdict_val = getattr(event, "verdict", None)
                        verdict_str = verdict_val.value if hasattr(verdict_val, "value") else str(verdict_val or "allow")

                        severity = "info"
                        if verdict_str in ["drop", "block", "quarantine"]:
                            severity = "critical"
                        elif verdict_str in ["rate_limit", "log_only"]:
                            severity = "warning"

                        siem_event = SIEMEvent(
                            timestamp=timestamp_str,
                            severity=severity,
                            event_type=getattr(event, "source_path", None).value if hasattr(getattr(event, "source_path", None), "value") else str(getattr(event, "source_path", "normal")),
                            source_ip=getattr(event, "src_ip", "0.0.0.0"),
                            destination_ip=getattr(event, "dst_ip", "0.0.0.0"),
                            source_port=getattr(event, "src_port", 0),
                            destination_port=getattr(event, "dst_port", 0),
                            protocol=getattr(event, "protocol", "TCP"),
                            action=verdict_str,
                            description=getattr(event, "reason", "Traffic Event"),
                            metadata={
                                "flow_id": getattr(event, "flow_id", ""),
                                "event_id": getattr(event, "event_id", ""),
                                "bytes": getattr(event, "bytes", 0),
                                "packets": getattr(event, "packets", 0)
                            }
                        )
                        await self.siem_connector.send(siem_event)
                    except Exception as forward_err:
                        logger.error(f"[SIEM] Failed to forward event to SIEM: {forward_err}")

                self.event_sink.register_observer(siem_forwarder)
                logger.info("✅ SIEM Connector wired as observer to UnifiedEventSink")

            # Register with DLP audit logger via ServiceContainer (avoid direct module import)
            try:
                dlp_audit = self.container.get_optional('dlp_audit_logger')
                if dlp_audit and hasattr(dlp_audit, 'register_siem_connector'):
                    dlp_audit.register_siem_connector(self.siem_connector)
                    logger.info("✅ SIEM Connector registered with DLPAuditLogger")
            except Exception as _dlp_siem_err:
                logger.warning(f"[SIEM] Failed to register SIEM connector with DLP: {_dlp_siem_err}")

        except Exception as _siem_err:
            logger.warning(f"[SIEM] Failed to start SIEM connector (non-fatal): {_siem_err}")

    async def _init_ttl_manager(self):
        """Initialize Decision TTL Manager for temporary block expirations."""
        try:
            from system.policy.decision_ttl import DecisionTTLManager
            self.ttl_manager = DecisionTTLManager(cleanup_interval=60)
            await self.ttl_manager.start()
            logger.info("✅ Decision TTL Manager started — temporary blocks will expire")
        except Exception as _ttl_err:
            logger.warning(f"[TTL] Failed to start TTL manager (non-fatal): {_ttl_err}")

    # ══════════════════════════════════════════════════════════════════════════
    # Data Plane: Start / Stop
    # ══════════════════════════════════════════════════════════════════════════

    async def start_firewall_components(self):
        if self.engine_running:
            return
        logger.info("Starting firewall data plane components...")
        self.engine_running = True
        self._engine_tasks = []

        if getattr(self, 'flow_tracker', None):
            await self.flow_tracker.start()
        if getattr(self, 'xdp_engine', None):
            await self.xdp_engine.start()

        # NOTE: transparent_proxy, forward_proxy, reverse_proxy, dns_server are
        # all managed by ProxyModule (modules/proxy/module.py) which is started
        # via module_registry.start_all() → ProxyModule.start().
        # Starting them again here would cause double-bind errors on every port.
        # We only need to enable IP forwarding if transparent proxy is active.
        if self.transparent_proxy:
            if getattr(self, 'network_orchestrator', None):
                self.network_orchestrator.netfilter.enable_ip_forwarding()

        if self.config.get('ml', {}).get('enabled', True):
            self._engine_tasks.append(asyncio.create_task(self._ml_maintenance_loop()))

        # Start Network Rule Orchestrator
        from system.networking.orchestrator import NetworkRuleOrchestrator
        self.network_orchestrator = NetworkRuleOrchestrator(self.config)
        
        # Build the list of rule providers
        rule_providers = self.module_registry.list_modules()
        if hasattr(self, 'transparent_networking') and self.transparent_networking:
            rule_providers.append(self.transparent_networking)
            
        self.network_orchestrator.orchestrate_rules(rule_providers)

        logger.info("✅ Firewall engine native loop started.")

        # ── Audio Alert System ──
        try:
            from system.audio.audio_manager import AudioManager
            from system.events.bus import EventBus
            from system.events.topics import Topics
            audio_mgr = await AudioManager.instance()
            await audio_mgr.start()
            bus = await EventBus.instance()
            await bus.publish(Topics.SYSTEM_STARTED, {
                "message": "bunyanx NGFW started",
                "node_id": "local",
            })
        except Exception as _ae:
            logger.warning(f"[AudioManager] Could not start Audio Alert System: {_ae}")

    async def stop_firewall_components(self):
        if not self.engine_running:
            return
        logger.warning("Stopping firewall data plane components natively...")
        self.engine_running = False

        for task in self._engine_tasks:
            task.cancel()
        self._engine_tasks.clear()

        if getattr(self, 'transparent_proxy', None):
            await self.transparent_proxy.stop()
        if getattr(self, 'network_orchestrator', None):
            self.network_orchestrator.netfilter.clear_rules()
            self.network_orchestrator.netfilter.add_mgmt_protection_rules()
            self.network_orchestrator.netfilter.apply_atomic()
            logger.info("✅ Network rules reverted (Safemode baseline activated).")
        if getattr(self, 'forward_proxy', None):
            await self.forward_proxy.stop()
        if getattr(self, 'reverse_proxy', None):
            await self.reverse_proxy.stop()
        if getattr(self, 'dns_server', None):
            await self.dns_server.stop()
        if getattr(self, 'flow_tracker', None):
            await self.flow_tracker.stop()
        if getattr(self, 'xdp_engine', None):
            await self.xdp_engine.stop()
        logger.info("🛑 Firewall engine natively stopped.")

    # ══════════════════════════════════════════════════════════════════════════
    # Graceful Shutdown (DAG-based)
    # ══════════════════════════════════════════════════════════════════════════

    async def stop(self):
        if not self.running:
            return
        logger.info("🛑 Stopping Enterprise bunyanx via DAG-based shutdown")

        # Emit shutdown audio event
        try:
            from system.events.bus import EventBus
            from system.events.topics import Topics
            bus = await EventBus.instance()
            await bus.publish(Topics.SYSTEM_SHUTDOWN, {"message": "Graceful shutdown initiated"})
        except Exception:
            pass

        shutdown_tiers = [
            # Tier 1: Stop incoming traffic
            [
                ("VPN Portal", self._stop_vpn_portal),
                ("Firewall/XDP", self.stop_firewall_components),
            ],
            # Tier 2: Stop acceleration + modules
            [
                ("Acceleration Bridge", self._stop_acceleration_bridge),
                ("VPN Manager", self._stop_vpn_manager),
                ("Module Registry", self._stop_module_registry),
            ],
            # Tier 3: Stop HA sync
            [
                ("State Sync", self._stop_state_sync),
                ("HA Manager", self._stop_ha_manager),
            ],
            # Tier 4: Stop core infra
            [
                ("Event Bus", self._stop_event_bus),
                ("Database", self.db.close),
            ],
        ]

        for tier_idx, tier_tasks in enumerate(shutdown_tiers):
            logger.info(f"Shutdown Tier {tier_idx + 1}...")
            tasks = []
            for name, func in tier_tasks:
                if func:
                    async def run_task(n, f):
                        try:
                            if asyncio.iscoroutinefunction(f):
                                await f()
                            else:
                                f()
                            logger.debug(f"Shutdown: {n} OK")
                        except Exception as e:
                            logger.error(f"Shutdown Error in {n}: {e}")
                    tasks.append(run_task(name, func))
            if tasks:
                await asyncio.gather(*tasks)

        self.running = False
        self.shutdown_event.set()
        logger.info("🛑 Shutdown complete")

    # ── Shutdown helpers ───────────────────────────────────────────────────

    async def _stop_vpn_portal(self):
        if getattr(self, 'vpn_portal', None):
            active = self.vpn_portal.active_count()
            if active:
                logger.info(f"VPN Portal: terminating {active} active session(s)")
            for s in list(self.vpn_portal.list_sessions()):
                self.vpn_portal.terminate_session(s["session_id"])

    async def _stop_acceleration_bridge(self):
        if getattr(self, 'acceleration_bridge', None):
            await self.acceleration_bridge.stop()

    async def _stop_vpn_manager(self):
        if getattr(self, 'vpn_manager', None) and getattr(self, 'vpn_enabled', False):
            self.vpn_manager.teardown()

    async def _stop_module_registry(self):
        if getattr(self, 'module_registry', None):
            await self.module_registry.stop_all()

    async def _stop_state_sync(self):
        if getattr(self, 'state_sync', None):
            await self.state_sync.stop()

    async def _stop_ha_manager(self):
        if getattr(self, 'ha_manager', None):
            await self.ha_manager.stop()

    async def _stop_event_bus(self):
        from system.core.framework.pipeline import _get_bus
        bus = _get_bus()
        if bus and hasattr(bus, 'close'):
            if asyncio.iscoroutinefunction(bus.close):
                await bus.close()
            else:
                bus.close()

    # ══════════════════════════════════════════════════════════════════════════
    # VPN Callbacks (HA state sync)
    # ══════════════════════════════════════════════════════════════════════════

    def _vpn_portal_event_callback(self, event_type: str, details: dict):
        if not getattr(self, 'is_ha_master', False) or not self.state_sync:
            return

        if event_type == "vpn.session.created":
            action = "create"
        elif event_type == "vpn.session.terminated":
            action = "terminate"
        else:
            return

        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.state_sync.broadcast_vpn_session(action, details))
        except RuntimeError:
            pass

    def _on_vpn_session_sync(self, action: str, data: dict):
        if not self.vpn_portal:
            return
        session_id = data.get("session_id")
        if not session_id:
            return
        if action == "create":
            self.vpn_portal.create_session(
                username=data.get("username"),
                peer_public_key=data.get("peer_public_key"),
                allowed_ips=data.get("allowed_ips", []),
                endpoint=data.get("endpoint"),
                session_id=session_id
            )
        elif action == "terminate":
            self.vpn_portal.terminate_session(session_id)

    # ══════════════════════════════════════════════════════════════════════════
    # Runtime
    # ══════════════════════════════════════════════════════════════════════════

    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown."""
        loop = asyncio.get_event_loop()

        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum} — scheduling graceful shutdown")
            loop.call_soon_threadsafe(lambda: loop.create_task(self.stop()))

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        logger.info("✅ Signal handlers installed (SIGINT, SIGTERM)")

    async def run_forever(self):
        """Run until shutdown signal received"""
        self._setup_signal_handlers()
        await self.shutdown_event.wait()

    async def _ml_maintenance_loop(self):
        logger.info("ML maintenance loop started")
        while self.running:
            try:
                await asyncio.sleep(60)
                if self.AEGIS_engine:
                    try:
                        health = self.AEGIS_engine.health_check()
                        tracked = health.get('ase', {}).get('tracked_ips', 0)
                        acc = health.get('ais', {}).get('accuracy', 0.0)
                        decoys = health.get('die', {}).get('active_decoys', 0)
                        logger.info(
                            "[AEGIS v3] health: tracked_ips=%d  ais_accuracy=%.1f%%  active_decoys=%d",
                            tracked, acc * 100, decoys,
                        )
                    except Exception as _e:
                        logger.debug("AEGIS health check error: %s", _e)

                    if self.recovery_manager:
                        recovered = self.recovery_manager.check_recoveries()
                        if recovered:
                            logger.info(f"🔄 Automated recoveries executed for: {recovered}")
            except Exception as e:
                logger.error(f"Error in ML maintenance: {e}")

    # ══════════════════════════════════════════════════════════════════════════
    # VPN Database Helpers
    # ══════════════════════════════════════════════════════════════════════════

    async def _save_vpn_config_to_db(self, interface: str, ip: str, port: int):
        """Save current VPN interface configuration to DB.

        SECURITY: Only the public key is saved. The private key is NEVER
        persisted — it lives only in WireGuardManager.private_key (in-memory)
        and briefly in /tmp during interface setup.
        """
        from system.database.database import VPNConfig
        from sqlalchemy.future import select
        async with self.db.session() as session:
            result = await session.execute(select(VPNConfig).filter_by(interface=interface))
            config = result.scalars().first()
            if not config:
                config = VPNConfig(interface=interface)
                session.add(config)

            config.server_ip = ip
            config.listen_port = port
            config.enabled = True
            if self.vpn_manager:
                config.public_key = self.vpn_manager.public_key or ""

            await session.commit()
            logger.debug(f"VPN configuration for {interface} saved to DB (public key only)")

    async def _load_vpn_peers_from_db(self):
        """Restore WireGuard peers from database.

        VPN-specific types live in modules/vpn — we do NOT import them here.
        If VPNModule exposes restore_peers_from_db() we call that; otherwise
        we ask the vpn_manager to build peers from raw DB rows so the types
        stay inside the module boundary.
        """
        if not self.vpn_manager:
            return

        # Preferred path: VPNModule handles its own DB restoration
        if hasattr(self.vpn_manager, 'restore_peers_from_db'):
            await self.vpn_manager.restore_peers_from_db(self.db)
            return

        # Fallback: build peers via vpn_manager factory methods (no direct import)
        try:
            from system.database.database import VPNPeer
            from sqlalchemy.future import select

            async with self.db.session() as session:
                result = await session.execute(select(VPNPeer).filter_by(enabled=True))
                db_peers = result.scalars().all()
                loaded = 0
                for dbp in db_peers:
                    # vpn_manager.add_peer_from_db() keeps PeerConfig/decrypt_psk
                    # inside modules/vpn — no import needed here.
                    if hasattr(self.vpn_manager, 'add_peer_from_db'):
                        self.vpn_manager.add_peer_from_db(dbp)
                        loaded += 1
                logger.info("✅ Restored %d VPN peers from database", loaded)
        except Exception as _vpn_err:
            logger.warning("[VPN] Could not restore peers from DB: %s", _vpn_err)


# ── Backward-compatibility class alias ───────────────────────────────────────
BunyanXApplication = bunyanxApplication


