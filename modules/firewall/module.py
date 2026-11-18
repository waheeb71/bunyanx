"""
bunyanx NGFW — Firewall Module (New-style BaseModule)
"""
import logging
from typing import Any, Dict, Optional

from system.core.framework.base_module import BaseModule, ModuleManifest
from system.core.service_container import ServiceContainer

logger = logging.getLogger(__name__)


class FirewallModule(BaseModule):
    """Stateful Next-Gen Firewall module."""

    def __init__(self):
        super().__init__()
        self._plugin = None
        self._acl_engine = None
        self._app_engine = None

    def get_manifest(self) -> ModuleManifest:
        from pathlib import Path
        return ModuleManifest.from_yaml(
            str(Path(__file__).parent / 'manifest.yaml')
        )

    async def initialize(self, container: ServiceContainer) -> None:
        from pathlib import Path
        import yaml
        import json
        from modules.firewall.engine.firewall_plugin import FirewallPlugin

        db     = container.get_optional('db')
        xdp    = container.get_optional('xdp_engine')
        config = container.get_optional('config') or {}

        # ── Load firewall settings.yaml (module-local config) ──────────────────
        _settings_path = Path(__file__).parent / 'config' / 'settings.yaml'
        module_conf: dict = {}
        if _settings_path.exists():
            try:
                with open(_settings_path, encoding='utf-8') as _f:
                    _raw = yaml.safe_load(_f) or {}
                module_conf = _raw.get('firewall', _raw)
                logger.info("FirewallModule: loaded settings.yaml (%d keys)", len(module_conf))
            except Exception as _ye:
                logger.warning("FirewallModule: could not load settings.yaml: %s", _ye)

        # ── Merge: system config overrides settings.yaml ────────────────────────
        sys_mod_conf = config.get('modules', {}).get('firewall', {})
        mod_conf = {**module_conf, **sys_mod_conf}

        # ── Auto-detect zones from network_auto_configurator state ──────────────
        # The network_auto_configurator discovers which NIC is WAN/LAN at runtime
        # (based on MAC address matching or USB auto-detection).
        # We read its state file to build accurate zone mappings instead of
        # relying on hardcoded interface names like eth0/eth1.
        detected_zones = self._detect_zones_from_state()
        if detected_zones:
            # Auto-detected zones override the static settings.yaml zones
            mod_conf['zones'] = detected_zones
            logger.info(
                "FirewallModule: auto-detected zones from network state: %s",
                detected_zones
            )
        elif not mod_conf.get('zones'):
            logger.warning(
                "FirewallModule: no zone config found — all traffic will use zone 'any'. "
                "Run network_auto_configurator or set zones in settings.yaml."
            )

        self._plugin = FirewallPlugin(db_manager=db, config=mod_conf)
        if xdp is not None:
            self._plugin._xdp_engine = xdp

        # Init policy engines — will be registered in ServiceContainer
        from modules.firewall.policy.access_control.acl_engine import ACLEngine
        from modules.firewall.policy.app_control.engine import AppControlEngine
        self._acl_engine = ACLEngine()
        self._app_engine = AppControlEngine()

        # Register policy engines into PolicyManager via ServiceContainer
        policy_mgr = container.get_optional('policy_manager')
        if policy_mgr:
            policy_mgr.register_engine('acl', self._acl_engine, priority=10)
            policy_mgr.register_engine('app_control', self._app_engine, priority=30)
            logger.info("✅ Firewall policy engines registered: acl (p=10), app_control (p=30)")

        await super().initialize(container)
        logger.info(
            "FirewallModule initialized — db=%s xdp=%s default_policy=%s "
            "mgmt_ports=%s dev_ports=%s zones=%s",
            'OK' if db else 'MISSING',
            'OK' if xdp else 'mock',
            mod_conf.get('default_policy', 'DROP'),
            mod_conf.get('management_ports', []),
            mod_conf.get('dev_ports', []) if mod_conf.get('dev_ports_enabled', False) else 'disabled',
            mod_conf.get('zones', {}),
        )

    @staticmethod
    def _detect_zones_from_state() -> dict:
        """
        Read the network_auto_configurator state file to build zone mappings.

        State file: /etc/bunyanx/network_applied_state.json
        Written by: system/networking/appliance/network_auto_configurator.py

        Returns a dict like: {'enx001122': 'wan', 'ens3': 'lan', 'lo': 'loopback'}
        Returns {} if state file doesn't exist (first boot or Windows dev environment).
        """
        import json
        from pathlib import Path

        state_file = Path("/etc/bunyanx/network_applied_state.json")
        if not state_file.exists():
            return {}

        try:
            state = json.loads(state_file.read_text())
            zones = {}

            wan_device = state.get("wan_device", "")
            lan_device = state.get("lan_device", "")
            mgmt_device = state.get("mgmt_device", "")

            if wan_device:
                zones[wan_device] = "wan"
            if lan_device and lan_device != wan_device:
                zones[lan_device] = "lan"
            if mgmt_device and mgmt_device not in zones:
                zones[mgmt_device] = "management"

            # Always include loopback
            zones["lo"] = "loopback"

            # VPN interface from base.yaml (wg0 is always wg0)
            zones["wg0"] = "vpn"

            return zones

        except Exception as exc:
            logger.debug("FirewallModule: could not parse network state: %s", exc)
            return {}




    def get_inspector_plugin(self):
        return self._plugin

    def get_provided_services(self) -> Dict[str, Any]:
        services = {}
        if self._acl_engine:
            services['acl_engine'] = self._acl_engine
        if self._app_engine:
            services['app_engine'] = self._app_engine
        return services

    def get_netfilter_rules(self) -> Dict[str, list]:
        if self._plugin and hasattr(self._plugin, 'get_netfilter_rules'):
            return self._plugin.get_netfilter_rules()
        return {}
