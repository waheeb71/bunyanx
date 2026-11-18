"""
bunyanx NGFW — Base Module (Unified Module Lifecycle)
========================================================
Abstract base class that ALL modules must inherit from.

This replaces the fragmented approach where some modules are
InspectorPlugins (pipeline), some are services (VPN, QoS),
and some are both (firewall, WAF).

Every module now follows the same lifecycle:
    discover → load manifest → initialize(container) → start → stop

Modules declare their capabilities via ModuleManifest:
    - type: inspector | service | hybrid
    - requires: list of services needed from ServiceContainer
    - provides: list of services this module offers
    - event_subscriptions: topics to subscribe to
    - event_publications: topics this module publishes

Usage:
    class FirewallModule(BaseModule):
        def get_manifest(self) -> ModuleManifest:
            return ModuleManifest.from_yaml('modules/firewall/manifest.yaml')

        async def initialize(self, container: ServiceContainer) -> None:
            db = container.get('db')
            self.plugin = FirewallPlugin(db_manager=db, ...)

        def get_inspector_plugin(self):
            return self.plugin
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Awaitable, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)

# Type alias for event handlers
Handler = Callable[[dict], Awaitable[None]]


class ModuleType(str, Enum):
    """Module integration type."""
    INSPECTOR = "inspector"   # Participates in InspectionPipeline
    SERVICE   = "service"     # Background service (VPN, QoS, SIEM, ...)
    HYBRID    = "hybrid"      # Both pipeline + service


class ModuleStatus(str, Enum):
    """Module lifecycle status."""
    DISCOVERED  = "discovered"
    LOADED      = "loaded"
    INITIALIZED = "initialized"
    RUNNING     = "running"
    STOPPED     = "stopped"
    ERROR       = "error"


@dataclass
class HealthStatus:
    """Module health report."""
    healthy: bool = True
    status: str = "ok"
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ModuleManifest:
    """
    Declarative module descriptor.
    
    Loaded from manifest.yaml in each module directory.
    """
    name: str
    version: str = "1.0.0"
    description: str = ""
    type: ModuleType = ModuleType.INSPECTOR
    priority: int = 50  # Pipeline priority (lower = earlier)
    
    # Dependency Injection
    requires: List[str] = field(default_factory=list)
    provides: List[str] = field(default_factory=list)
    
    # Event Bus integration
    event_subscriptions: List[str] = field(default_factory=list)
    event_publications: List[str] = field(default_factory=list)
    
    # Module directory path (auto-set during discovery)
    module_dir: Optional[str] = None

    @classmethod
    def from_yaml(cls, yaml_path: str) -> 'ModuleManifest':
        """Load manifest from a YAML file."""
        path = Path(yaml_path)
        if not path.exists():
            raise FileNotFoundError(f"Manifest not found: {yaml_path}")
        
        with open(path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f) or {}
        
        # Convert type string to enum
        mod_type = data.get('type', 'inspector')
        if isinstance(mod_type, str):
            try:
                mod_type = ModuleType(mod_type)
            except ValueError:
                logger.warning(f"Unknown module type '{mod_type}', defaulting to 'inspector'")
                mod_type = ModuleType.INSPECTOR
        
        return cls(
            name=data.get('name', path.parent.name),
            version=data.get('version', '1.0.0'),
            description=data.get('description', ''),
            type=mod_type,
            priority=data.get('priority', 50),
            requires=data.get('requires', []),
            provides=data.get('provides', []),
            event_subscriptions=data.get('event_subscriptions', []),
            event_publications=data.get('event_publications', []),
            module_dir=str(path.parent),
        )

    @classmethod
    def from_dict(cls, data: dict) -> 'ModuleManifest':
        """Create manifest from a dictionary (for programmatic creation)."""
        mod_type = data.get('type', 'inspector')
        if isinstance(mod_type, str):
            try:
                mod_type = ModuleType(mod_type)
            except ValueError:
                mod_type = ModuleType.INSPECTOR
        
        return cls(
            name=data.get('name', 'unknown'),
            version=data.get('version', '1.0.0'),
            description=data.get('description', ''),
            type=mod_type,
            priority=data.get('priority', 50),
            requires=data.get('requires', []),
            provides=data.get('provides', []),
            event_subscriptions=data.get('event_subscriptions', []),
            event_publications=data.get('event_publications', []),
            module_dir=data.get('module_dir'),
        )


class BaseModule(ABC):
    """
    Abstract base class for ALL bunyanx modules.
    
    Provides a unified lifecycle that replaces the fragmented
    approach of manual wiring in engine.py.
    
    Lifecycle:
        1. __init__() — minimal setup
        2. initialize(container) — receive dependencies, configure
        3. start() — begin processing / register event handlers
        4. stop() — graceful shutdown
        5. health_check() — report health status
    
    Integration points (optional overrides):
        - get_inspector_plugin() → register in InspectionPipeline
        - get_event_subscriptions() → subscribe to EventBus topics
        - get_provided_services() → register services in ServiceContainer
    """

    def __init__(self):
        self._status = ModuleStatus.DISCOVERED
        self._manifest: Optional[ModuleManifest] = None
        self.logger = logging.getLogger(f"module.{self.__class__.__name__}")

    # ── Abstract Methods ───────────────────────────────────────────

    @abstractmethod
    def get_manifest(self) -> ModuleManifest:
        """
        Return the module's manifest.
        
        Must be implemented by every module.
        Can load from manifest.yaml or construct programmatically.
        """
        ...

    # ── Lifecycle Methods (override as needed) ─────────────────────

    async def initialize(self, container: 'ServiceContainer') -> None:
        """
        Initialize the module with dependencies from the ServiceContainer.
        
        Called once during system startup. Use this to:
        - Fetch required services (db, config, etc.)
        - Create internal components (plugins, managers, etc.)
        - Load configuration
        
        Args:
            container: The system-wide ServiceContainer
        """
        self._status = ModuleStatus.INITIALIZED

    async def start(self) -> None:
        """
        Start the module's runtime operations.
        
        Called after all modules are initialized.
        Use this for:
        - Starting background tasks
        - Opening network listeners
        - Registering periodic tasks
        """
        self._status = ModuleStatus.RUNNING

    async def stop(self) -> None:
        """
        Gracefully stop the module.
        
        Called during system shutdown.
        Use this to:
        - Cancel background tasks
        - Close connections
        - Flush buffers
        """
        self._status = ModuleStatus.STOPPED

    async def health_check(self) -> HealthStatus:
        """
        Report module health.
        
        Called periodically by the health checker.
        Override to provide detailed health metrics.
        """
        return HealthStatus(
            healthy=self._status == ModuleStatus.RUNNING,
            status=self._status.value,
        )

    # ── Integration Points (optional overrides) ────────────────────

    def get_inspector_plugin(self) -> Optional[Any]:
        """
        Return an InspectorPlugin instance for pipeline integration.
        
        Override this if your module participates in the
        InspectionPipeline (type: inspector or hybrid).
        
        Returns:
            An InspectorPlugin instance, or None if not applicable
        """
        return None

    def get_event_subscriptions(self) -> Dict[str, Handler]:
        """
        Return a dict of {topic: async_handler} for EventBus subscriptions.
        
        Override this if your module needs to receive events.
        The ModuleRegistry will wire these automatically.
        
        Returns:
            Dict mapping topic strings to async handler functions
        """
        return {}

    def get_provided_services(self) -> Dict[str, Any]:
        """
        Return a dict of {service_name: service_instance} to register
        in the ServiceContainer.
        
        Override this if your module provides services that other
        modules depend on.
        
        Returns:
            Dict mapping service names to instances
        """
        return {}

    # ── Properties ─────────────────────────────────────────────────

    @property
    def status(self) -> ModuleStatus:
        return self._status

    @property
    def manifest(self) -> ModuleManifest:
        if self._manifest is None:
            self._manifest = self.get_manifest()
        return self._manifest

    @property
    def name(self) -> str:
        return self.manifest.name

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.name}, status={self._status.value})"
