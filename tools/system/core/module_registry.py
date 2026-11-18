"""
bunyanx NGFW — Module Registry (Unified Module Loader)
=========================================================
Discovers, loads, initializes, and manages ALL modules through
the unified BaseModule lifecycle.

Replaces the old ModuleManager which only handled InspectorPlugins.
Now supports:
  - Inspector modules (pipeline participation)
  - Service modules (background services like VPN, QoS, SIEM)
  - Hybrid modules (both pipeline + service)

Discovery process:
  1. Scan modules/ directory for manifest.yaml files
  2. Check if module is enabled in base.yaml config
  3. Load module.py and instantiate the BaseModule subclass
  4. Validate DI requirements against ServiceContainer
  5. Initialize in dependency order
  6. Wire InspectorPlugins into pipeline
  7. Wire EventBus subscriptions
  8. Register provided services

Usage:
    registry = ModuleRegistry(config, pipeline, container)
    await registry.discover_and_load()
    await registry.initialize_all()
    await registry.start_all()
    # ... at shutdown:
    await registry.stop_all()
"""

import asyncio
import importlib
import inspect
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional, Any

from system.core.framework.base_module import (
    BaseModule, ModuleManifest, ModuleType, ModuleStatus, HealthStatus,
)
from system.core.framework.pipeline import InspectionPipeline
from system.core.framework.plugin_base import InspectorPlugin
from system.core.service_container import ServiceContainer

logger = logging.getLogger(__name__)


class ModuleRegistry:
    """
    Unified module lifecycle manager.
    
    Discovers modules from the filesystem, loads them via manifest.yaml,
    and manages their full lifecycle (init → start → stop).
    """

    def __init__(
        self,
        config: Dict[str, Any],
        pipeline: InspectionPipeline,
        container: ServiceContainer,
    ):
        self.config = config
        self.pipeline = pipeline
        self.container = container
        self.modules_config = config.get('modules', {})
        
        # Registered modules (ordered by discovery)
        self._modules: Dict[str, BaseModule] = {}
        
        # Track which modules are loaded
        self._load_order: List[str] = []

    # ── Discovery & Loading ────────────────────────────────────────

    async def discover_and_load(self) -> int:
        """
        Discover all modules and load enabled ones.
        
        Returns:
            Number of modules loaded
        """
        modules_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), '..', '..', 'modules')
        )
        
        if not os.path.exists(modules_dir):
            logger.error(f"Modules directory not found: {modules_dir}")
            return 0

        loaded_count = 0
        logger.info("═══ Module Registry: Starting Discovery ═══")

        for module_name in sorted(os.listdir(modules_dir)):
            module_path = os.path.join(modules_dir, module_name)
            if not os.path.isdir(module_path):
                continue
            if module_name.startswith('__') or module_name.startswith('.'):
                continue

            # Check if enabled in config
            mod_conf = self.modules_config.get(module_name, {})
            if not mod_conf.get('enabled', False):
                logger.debug(f"Module '{module_name}' disabled in config. Skipping.")
                continue

            try:
                module = await self._load_module(module_name, module_path, mod_conf)
                if module is not None:
                    self._modules[module_name] = module
                    self._load_order.append(module_name)
                    loaded_count += 1
            except Exception as e:
                logger.error(
                    f"Failed to load module '{module_name}': {e}",
                    exc_info=True
                )
                raise RuntimeError(
                    f"Strict Mode: Failed to load enabled module '{module_name}': {e}"
                )

        # Topological sort based on manifest dependencies
        provider_map = {}
        for name, mod in self._modules.items():
            provides = getattr(mod.manifest, 'provides', []) if hasattr(mod, 'manifest') and mod.manifest else []
            for svc in provides:
                provider_map[svc] = name

        dep_graph = {}
        for name, mod in self._modules.items():
            requires = getattr(mod.manifest, 'requires', []) if hasattr(mod, 'manifest') and mod.manifest else []
            deps = set()
            for req in requires:
                if req in provider_map:
                    deps.add(provider_map[req])
            dep_graph[name] = deps

        visited = {}
        sorted_order = []

        def dfs(node):
            if visited.get(node, 0) == 1:
                logger.warning(f"Circular dependency detected involving module '{node}'")
                return
            if visited.get(node, 0) == 2:
                return
            visited[node] = 1
            for dep in dep_graph.get(node, []):
                dfs(dep)
            visited[node] = 2
            sorted_order.append(node)

        for name in list(self._modules.keys()):
            dfs(name)

        self._load_order = sorted_order
        logger.info(f"Topological Load Order: {', '.join(self._load_order)}")

        logger.info(
            f"═══ Module Registry: Loaded {loaded_count} modules ═══"
        )
        return loaded_count

    async def _load_module(
        self,
        module_name: str,
        module_path: str,
        mod_conf: dict,
    ) -> Optional[BaseModule]:
        """
        Load a single module.
        
        Attempts to load via:
          1. New-style: module.py with BaseModule subclass + manifest.yaml
          2. Legacy-style: engine/ directory with InspectorPlugin (backward compat)
        """
        manifest_path = os.path.join(module_path, 'manifest.yaml')
        module_py_path = os.path.join(module_path, 'module.py')

        # ── New-style module (manifest.yaml + module.py) ───────────
        if os.path.exists(manifest_path) and os.path.exists(module_py_path):
            return await self._load_new_style(module_name, manifest_path, mod_conf)

        # ── Legacy-style module (InspectorPlugin in engine/) ───────
        return await self._load_legacy_style(module_name, module_path, mod_conf)

    async def _load_new_style(
        self,
        module_name: str,
        manifest_path: str,
        mod_conf: dict,
    ) -> Optional[BaseModule]:
        """Load a new-style BaseModule with manifest.yaml."""
        manifest = ModuleManifest.from_yaml(manifest_path)
        
        # Import module.py
        import_path = f"modules.{module_name}.module"
        mod = importlib.import_module(import_path)
        
        # Find the BaseModule subclass
        module_class = None
        for attr_name in dir(mod):
            attr = getattr(mod, attr_name)
            if (inspect.isclass(attr) 
                and issubclass(attr, BaseModule) 
                and attr is not BaseModule
                and attr.__module__ == import_path):
                module_class = attr
                break
        
        if module_class is None:
            logger.warning(
                f"Module '{module_name}' has manifest.yaml but no BaseModule "
                f"subclass in module.py. Falling back to legacy loader."
            )
            module_dir = os.path.dirname(manifest_path)
            return await self._load_legacy_style(module_name, module_dir, mod_conf)

        # Instantiate
        instance = module_class()
        instance._manifest = manifest
        
        logger.info(
            f"✅ Loaded new-style module: {module_name} "
            f"(type={manifest.type.value}, priority={manifest.priority})"
        )
        return instance

    async def _load_legacy_style(
        self,
        module_name: str,
        module_path: str,
        mod_conf: dict,
    ) -> Optional[BaseModule]:
        """
        Load a legacy InspectorPlugin module by wrapping it in a
        LegacyModuleAdapter.
        
        This ensures 100% backward compatibility with existing modules
        that haven't been migrated to the BaseModule pattern yet.
        """
        modules_dir = os.path.dirname(module_path)
        engine_pkg_path = os.path.join(module_path, 'engine')
        
        if not os.path.exists(engine_pkg_path):
            logger.info(
                f"Skipping module '{module_name}': no engine/ directory "
                f"and no module.py found."
            )
            return None

        # Walk engine/ to find InspectorPlugin subclass
        plugin_class = None
        for root, _, files in os.walk(engine_pkg_path):
            for file in files:
                if file.endswith('.py') and not file.startswith('__'):
                    rel_path = os.path.relpath(
                        os.path.join(root, file), modules_dir
                    )
                    import_path = "modules." + rel_path.replace(os.sep, '.')[:-3]
                    
                    try:
                        mod = importlib.import_module(import_path)
                        for attr_name in dir(mod):
                            attr = getattr(mod, attr_name)
                            if (inspect.isclass(attr) 
                                and issubclass(attr, InspectorPlugin) 
                                and attr is not InspectorPlugin
                                and attr.__module__ == import_path):
                                plugin_class = attr
                                break
                        if plugin_class:
                            break
                    except Exception as inner_e:
                        logger.debug(
                            f"Skipping {import_path} during legacy discovery: {inner_e}"
                        )
            if plugin_class:
                break

        if plugin_class is None:
            logger.info(
                f"Skipping module '{module_name}': no InspectorPlugin found "
                f"(expected for control-plane or backend-only modules)."
            )
            return None

        # Wrap in LegacyModuleAdapter
        adapter = LegacyModuleAdapter(
            module_name=module_name,
            plugin_class=plugin_class,
            mod_conf=mod_conf,
        )
        
        logger.info(
            f"✅ Loaded legacy module: {module_name} → {plugin_class.__name__} "
            f"(wrapped in LegacyModuleAdapter)"
        )
        return adapter

    # ── Lifecycle Management ───────────────────────────────────────

    async def initialize_all(self) -> None:
        """Initialize all loaded modules with DI from ServiceContainer."""
        logger.info("═══ Module Registry: Initializing Modules ═══")
        
        for name in self._load_order:
            module = self._modules[name]
            try:
                # Validate required services exist
                manifest = module.manifest
                for req in manifest.requires:
                    if not self.container.has(req):
                        logger.warning(
                            f"Module '{name}' requires service '{req}' "
                            f"which is not yet registered."
                        )
                
                # Initialize
                await module.initialize(self.container)
                
                # Register provided services
                for svc_name, svc_instance in module.get_provided_services().items():
                    self.container.register(svc_name, svc_instance)
                
                # Register InspectorPlugin in pipeline
                plugin = module.get_inspector_plugin()
                if plugin is not None:
                    # Inject module configuration
                    mod_conf = self.modules_config.get(name, {})
                    if not hasattr(plugin, 'config') or plugin.config is None:
                        plugin.config = mod_conf
                    
                    # Call plugin.initialize() if available
                    if hasattr(plugin, 'initialize'):
                        if asyncio.iscoroutinefunction(plugin.initialize):
                            await plugin.initialize()
                        else:
                            plugin.initialize()
                    
                    self.pipeline.register_plugin(plugin)
                    logger.info(
                        f"  ✅ Pipeline plugin registered: {plugin.name}"
                    )
                
                logger.info(f"  ✅ Module initialized: {name}")
                
            except Exception as e:
                module._status = ModuleStatus.ERROR
                logger.error(
                    f"  ❌ Failed to initialize module '{name}': {e}",
                    exc_info=True
                )
                raise RuntimeError(
                    f"Strict Mode: Module '{name}' initialization failed: {e}"
                )

    async def start_all(self) -> None:
        """Start all initialized modules."""
        logger.info("═══ Module Registry: Starting Modules ═══")
        
        for name in self._load_order:
            module = self._modules[name]
            if module.status != ModuleStatus.INITIALIZED:
                continue
                
            try:
                await module.start()
                
                # Wire EventBus subscriptions
                subscriptions = module.get_event_subscriptions()
                if subscriptions:
                    from system.events.bus import EventBus
                    bus = await EventBus.instance()
                    for topic, handler in subscriptions.items():
                        await bus.subscribe(topic, handler)
                        logger.debug(
                            f"  📡 Subscribed {name} to {topic}"
                        )
                
                logger.info(f"  ✅ Module started: {name}")
                
            except Exception as e:
                module._status = ModuleStatus.ERROR
                logger.error(f"  ❌ Failed to start module '{name}': {e}")

    async def stop_all(self) -> None:
        """Stop all running modules in reverse order."""
        logger.info("═══ Module Registry: Stopping Modules ═══")
        
        for name in reversed(self._load_order):
            module = self._modules[name]
            if module.status not in (ModuleStatus.RUNNING, ModuleStatus.INITIALIZED):
                continue
                
            try:
                await module.stop()
                logger.info(f"  🛑 Module stopped: {name}")
            except Exception as e:
                logger.error(f"  ❌ Error stopping module '{name}': {e}")

    async def health_check_all(self) -> Dict[str, HealthStatus]:
        """Run health checks on all modules."""
        results = {}
        for name, module in self._modules.items():
            try:
                results[name] = await module.health_check()
            except Exception as e:
                results[name] = HealthStatus(
                    healthy=False,
                    status='error',
                    details={'error': str(e)}
                )
        return results

    # ── Query Methods ──────────────────────────────────────────────

    def get_module(self, name: str) -> Optional[BaseModule]:
        """Get a loaded module by name."""
        return self._modules.get(name)

    def list_modules(self) -> List[str]:
        """List all loaded module names."""
        return list(self._load_order)

    def get_all_modules(self) -> Dict[str, BaseModule]:
        """Get all loaded modules."""
        return dict(self._modules)

    def get_statistics(self) -> Dict[str, Any]:
        """Get registry statistics."""
        return {
            'total_loaded': len(self._modules),
            'by_status': {
                status.value: sum(
                    1 for m in self._modules.values()
                    if m.status == status
                )
                for status in ModuleStatus
            },
            'modules': {
                name: {
                    'type': m.manifest.type.value,
                    'status': m.status.value,
                    'priority': m.manifest.priority,
                }
                for name, m in self._modules.items()
            }
        }


class LegacyModuleAdapter(BaseModule):
    """
    Adapter that wraps a legacy InspectorPlugin class in the
    BaseModule interface for backward compatibility.
    
    This allows existing modules that haven't been migrated
    to continue working without any code changes.
    """

    def __init__(
        self,
        module_name: str,
        plugin_class: type,
        mod_conf: dict,
    ):
        super().__init__()
        self._module_name = module_name
        self._plugin_class = plugin_class
        self._mod_conf = mod_conf
        self._plugin_instance: Optional[InspectorPlugin] = None
        self._manifest = ModuleManifest(
            name=module_name,
            type=ModuleType.INSPECTOR,
            description=f"Legacy adapter for {plugin_class.__name__}",
        )

    def get_manifest(self) -> ModuleManifest:
        return self._manifest

    async def initialize(self, container: ServiceContainer) -> None:
        """Create the plugin instance with appropriate DI."""
        db_manager = container.get_optional('db')
        xdp_engine = container.get_optional('xdp_engine')

        # Special-case modules that need DI (preserved for backward compat)
        if self._module_name == "firewall":
            self._plugin_instance = self._plugin_class(
                db_manager=db_manager,
                config=self._mod_conf,
            )
            if xdp_engine is not None:
                self._plugin_instance._xdp_engine = xdp_engine
            logger.info(
                f"FirewallPlugin instantiated with "
                f"db_manager={'OK' if db_manager else 'MISSING'}, "
                f"xdp_engine={'OK' if xdp_engine else 'mock/disabled'}"
            )
        elif self._module_name == "uba":
            self._plugin_instance = self._plugin_class(
                db_manager=db_manager,
            )
            logger.info(
                f"UBAPlugin instantiated with "
                f"db_manager={'OK' if db_manager else 'MISSING'}"
            )
        else:
            self._plugin_instance = self._plugin_class()

        # Inject module config
        self._plugin_instance.config = self._mod_conf
        
        self._status = ModuleStatus.INITIALIZED

    def get_inspector_plugin(self) -> Optional[InspectorPlugin]:
        return self._plugin_instance

    def __repr__(self) -> str:
        return (
            f"LegacyModuleAdapter(name={self._module_name}, "
            f"plugin={self._plugin_class.__name__})"
        )
