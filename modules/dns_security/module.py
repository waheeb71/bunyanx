"""
bunyanx NGFW — DNS Security Module (New-style BaseModule)
"""
import logging
from pathlib import Path

from system.core.framework.base_module import BaseModule, ModuleManifest
from system.core.service_container import ServiceContainer

logger = logging.getLogger(__name__)


class DNSSecurityModule(BaseModule):
    """DNS Security module with sinkholing, DGA detection, and DART-DNS."""

    def get_manifest(self) -> ModuleManifest:
        return ModuleManifest.from_yaml(
            str(Path(__file__).parent / 'manifest.yaml')
        )

    async def initialize(self, container: ServiceContainer) -> None:
        import yaml
        from modules.dns_security.engine.plugin import DNSSecurityPlugin

        # ── Load module-local settings.yaml ────────────────────────────────────
        _settings_path = Path(__file__).parent / 'config' / 'settings.yaml'
        module_conf: dict = {}
        if _settings_path.exists():
            try:
                with open(_settings_path, encoding='utf-8') as _f:
                    _raw = yaml.safe_load(_f) or {}
                # settings.yaml has top-level "dns_security:" key
                module_conf = _raw.get('dns_security', _raw)
                logger.info(
                    "DNSSecurityModule: loaded settings.yaml (%d keys)",
                    len(module_conf)
                )
            except Exception as exc:
                logger.warning(
                    "DNSSecurityModule: could not load settings.yaml: %s", exc
                )

        # ── Merge: system config takes priority over settings.yaml ──────────────
        sys_config  = container.get_optional('config') or {}
        sys_mod_conf = sys_config.get('modules', {}).get('dns_security', {})
        mod_conf = {**module_conf, **sys_mod_conf}

        # mode: enforce → block_on_match=True, monitor → block_on_match=False
        mode = mod_conf.get('mode', 'enforce').lower()
        block_on_match = (mode == 'enforce')

        self._plugin = DNSSecurityPlugin(
            config=mod_conf,
            block_on_match=block_on_match,
        )

        await super().initialize(container)
        logger.info(
            "DNSSecurityModule initialized — mode=%s sinkhole_ip=%s "
            "intercept_port=%s dart=%s dga=%s",
            mode,
            mod_conf.get('sinkhole_ip', '10.10.0.1'),
            mod_conf.get('intercept_port', 5353),
            mod_conf.get('enable_dart_detection', True),
            mod_conf.get('enable_dga_detection', True),
        )

    def get_inspector_plugin(self):
        return self._plugin
