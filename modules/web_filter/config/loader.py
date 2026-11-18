import os
import yaml
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class WebFilterConfigLoader:
    """
    Singleton Configuration Loader for the Web Filter Module.
    Reads settings.yaml and exposes it as structured properties.
    """
    _instance = None
    _config: Dict[str, Any] = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(WebFilterConfigLoader, cls).__new__(cls)
            cls._instance._load_config()
        return cls._instance

    def _load_config(self):
        config_path = os.path.join(os.path.dirname(__file__), "settings.yaml")
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                raw_cfg = yaml.safe_load(f) or {}
                self._config = raw_cfg.get("web_filter", {})
            logger.info(f"[WebFilterConfigLoader] Successfully loaded configuration from {config_path}")
        except Exception as e:
            logger.error(f"[WebFilterConfigLoader] Failed to load {config_path}: {e}")
            self._config = {}

    @property
    def raw_config(self) -> Dict[str, Any]:
        return self._config

    @property
    def default_action(self) -> str:
        return self._config.get("default_action", "ALLOW")

    @property
    def safe_search(self) -> Dict[str, Any]:
        return self._config.get("safe_search", {})

    @property
    def cache(self) -> Dict[str, Any]:
        return self._config.get("cache", {})

    @property
    def dns_sinkhole(self) -> Dict[str, Any]:
        return self._config.get("dns_sinkhole", {})

    @property
    def builtin_categories(self) -> List[Dict[str, Any]]:
        return self._config.get("builtin_categories", [])

    @property
    def logging(self) -> Dict[str, Any]:
        return self._config.get("logging", {})

    @property
    def holofilter(self) -> Dict[str, Any]:
        return self._config.get("ai_holofilter", {})

# Expose a ready-to-use instance
config = WebFilterConfigLoader()
