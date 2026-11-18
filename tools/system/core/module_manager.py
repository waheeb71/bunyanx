import logging
import importlib
from typing import Dict, Any
from system.core.framework.pipeline import InspectionPipeline

logger = logging.getLogger(__name__)

class ModuleManager:
    """ Reads config and dynamically loads enabled bunyanx modules into the pipeline """
    

    
    def __init__(self, config: Dict[str, Any], pipeline: InspectionPipeline,
                 db_manager=None, xdp_engine=None):
        self.config = config
        self.pipeline = pipeline
        self.modules_config = self.config.get('modules', {})
        self.db_manager = db_manager
        self.xdp_engine = xdp_engine
        
    async def load_plugins(self):
        """ Dynamically loads and registers plugins for enabled modules """
        import os
        import importlib
        import inspect
        from system.core.framework.plugin_base import InspectorPlugin

        loaded_count = 0
        logger.info("Starting Dynamic Module Loader...")
        
        # Discover all modules dynamically
        modules_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../modules'))
        
        if not os.path.exists(modules_dir):
            logger.error(f"Modules directory not found: {modules_dir}")
            return

        for module_name in os.listdir(modules_dir):
            mod_conf = self.modules_config.get(module_name, {})
            # If enabled in config (default False if missing)
            if mod_conf.get('enabled', False):
                try:
                    logger.debug(f"Attempting to dynamically discover plugin for {module_name}...")
                    
                    plugin_class = None
                    engine_pkg_path = os.path.join(modules_dir, module_name, 'engine')
                    
                    if os.path.exists(engine_pkg_path):
                        # Walk the engine package to find the InspectorPlugin
                        for root, _, files in os.walk(engine_pkg_path):
                            for file in files:
                                if file.endswith('.py') and not file.startswith('__'):
                                    rel_path = os.path.relpath(os.path.join(root, file), modules_dir)
                                    module_path = "modules." + rel_path.replace(os.sep, '.')[:-3]
                                    
                                    try:
                                        mod = importlib.import_module(module_path)
                                        for attr_name in dir(mod):
                                            attr = getattr(mod, attr_name)
                                            if inspect.isclass(attr) and issubclass(attr, InspectorPlugin) and attr is not InspectorPlugin:
                                                if attr.__module__ == module_path:
                                                    plugin_class = attr
                                                    break
                                        if plugin_class:
                                            break
                                    except Exception as inner_e:
                                        logger.debug(f"Skipping {module_path} during discovery: {inner_e}")
                            if plugin_class:
                                break
                    
                    if not plugin_class:
                        logger.info(f"Skipping module '{module_name}': no pipeline InspectorPlugin class found (expected for control-plane or backend-only modules).")
                        continue

                    # FirewallPlugin requires db_manager injected at creation so it
                    # can load rules from the DB on first packet evaluation.
                    if module_name == "firewall":
                        plugin_instance = plugin_class(
                            db_manager=self.db_manager,
                            config=mod_conf,
                        )
                        # Wire XDP engine so IPBlocklistManager can push blocks
                        # to the kernel map immediately.
                        if self.xdp_engine is not None:
                            plugin_instance._xdp_engine = self.xdp_engine
                        logger.info(
                            f"FirewallPlugin instantiated with "
                            f"db_manager={'OK' if self.db_manager else 'MISSING — rules will NOT load'}, "
                            f"xdp_engine={'OK' if self.xdp_engine else 'mock/disabled'}"
                        )
                    elif module_name == "uba":
                        plugin_instance = plugin_class(
                            db_manager=self.db_manager,
                        )
                        logger.info(
                            f"UBAPlugin instantiated with "
                            f"db_manager={'OK' if self.db_manager else 'MISSING'}"
                        )
                    else:
                        plugin_instance = plugin_class()

                    # Inject module configuration from base.yaml
                    plugin_instance.config = mod_conf
                    
                    # Phase 8: Call plugin initialization if provided
                    if hasattr(plugin_instance, "initialize"):
                        import asyncio
                        if asyncio.iscoroutinefunction(plugin_instance.initialize):
                            await plugin_instance.initialize()
                        else:
                            plugin_instance.initialize()
                        
                    self.pipeline.register_plugin(plugin_instance)
                    loaded_count += 1
                    logger.info(f"✅ Successfully loaded and activated plugin: {plugin_class.__name__}")
                except Exception as e:
                    logger.error(f"Failed to load plugin for module '{module_name}': {e}", exc_info=True)
                    raise RuntimeError(f"Strict Mode: Failed to load enabled module '{module_name}': {e}")
            else:
                logger.debug(f"Module '{module_name}' is disabled in configuration. Skipping.")
                
        logger.info(f"Dynamic Module Loader finished. Activated {loaded_count} plugins.")
