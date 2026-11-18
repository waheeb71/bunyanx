"""
bunyanx NGFW — VPN Module (New-style BaseModule)
"""
import logging
from typing import Any, Dict, Optional

from system.core.framework.base_module import BaseModule, ModuleManifest
from system.core.service_container import ServiceContainer

logger = logging.getLogger(__name__)


class VPNModule(BaseModule):
    """WireGuard VPN Server module."""

    def __init__(self):
        super().__init__()
        self._vpn_manager = None
        self._vpn_portal = None
        self._vpn_enabled = False

    def get_manifest(self) -> ModuleManifest:
        from pathlib import Path
        return ModuleManifest.from_yaml(
            str(Path(__file__).parent / 'manifest.yaml')
        )

    async def initialize(self, container: ServiceContainer) -> None:
        config = container.get('config') if container and container.has('config') else {}
        vpn_config = {}
        if hasattr(config, 'get'):
            vpn_config = config.get('vpn', {}) or config.get('modules', {}).get('vpn', {})
        
        self._vpn_enabled = vpn_config.get('enabled', False)
        
        if self._vpn_enabled:
            from modules.vpn.engine.wireguard import WireGuardManager
            from modules.vpn.policy.vpn.portal import VPNPortal
            interface_name = vpn_config.get('interface', 'wg0')
            self._vpn_manager = WireGuardManager(interface=interface_name, logger=logger)
            self._vpn_portal = VPNPortal()
        
        await super().initialize(container)

    async def start(self) -> None:
        if not self._vpn_enabled or not self._vpn_manager:
            await super().start()
            return
        
        config = self._container.get('config') if (hasattr(self, '_container') and self._container and self._container.has('config')) else {}
        vpn_config = config.get('vpn', {}) if hasattr(config, 'get') else {}
        vpn_ip = vpn_config.get('ip_address', '10.99.0.1/24')
        vpn_port = vpn_config.get('listen_port', 51820)
        interface_name = vpn_config.get('interface', 'wg0')
        
        if self._vpn_manager.setup_interface(ip_address=vpn_ip, port=vpn_port):
            logger.info(f"✅ WireGuard VPN initialized on {interface_name} ({vpn_ip})")
        else:
            logger.error(f"❌ WireGuard VPN setup failed for {interface_name}")
            try:
                from system.events.bus import EventBus
                from system.events.topics import Topics
                bus = await EventBus.instance()
                await bus.publish(Topics.VPN_FAILURE, {
                    "interface": interface_name,
                    "ip_address": vpn_ip,
                    "port": vpn_port,
                    "reason": "WireGuard interface setup failed"
                })
            except Exception as _ve:
                logger.warning(f"[VPN] Failed to publish vpn.failure: {_ve}")
        
        await super().start()

    async def stop(self) -> None:
        if self._vpn_manager and self._vpn_enabled:
            self._vpn_manager.teardown()
        await super().stop()

    def get_provided_services(self) -> Dict[str, Any]:
        services = {}
        if self._vpn_manager:
            services['vpn_manager'] = self._vpn_manager
        if self._vpn_portal:
            services['vpn_portal'] = self._vpn_portal
        return services

    # ------------------------------------------------------------------
    # DB peer restoration — called by engine._load_vpn_peers_from_db()
    # Keeps modules.vpn.engine.* imports inside this module boundary.
    # ------------------------------------------------------------------

    async def restore_peers_from_db(self, db_manager) -> None:
        """Restore WireGuard peers from DB rows (called by engine.py)."""
        if not self._vpn_manager:
            return
        try:
            from system.database.database import VPNPeer
            from sqlalchemy.future import select

            async with db_manager.session() as session:
                result = await session.execute(select(VPNPeer).filter_by(enabled=True))
                db_peers = result.scalars().all()
                loaded = 0
                for dbp in db_peers:
                    self.add_peer_from_db(dbp)
                    loaded += 1
                logger.info("✅ VPNModule: restored %d peers from database", loaded)
        except Exception as exc:
            logger.warning("[VPN] restore_peers_from_db failed: %s", exc)

    def add_peer_from_db(self, dbp) -> None:
        """Construct a PeerConfig from a VPNPeer DB row and add to manager."""
        if not self._vpn_manager:
            return
        try:
            import json
            from modules.vpn.engine.wireguard import PeerConfig
            from modules.vpn.engine.crypto import decrypt_psk

            allowed_ips = dbp.allowed_ips or []
            if isinstance(allowed_ips, str):
                try:
                    allowed_ips = json.loads(allowed_ips)
                except Exception:
                    allowed_ips = [allowed_ips]
            if not isinstance(allowed_ips, list):
                allowed_ips = [str(allowed_ips)]

            peer = PeerConfig(
                public_key=dbp.public_key,
                allowed_ips=allowed_ips,
                endpoint=dbp.endpoint or None,
                preshared_key=decrypt_psk(dbp.preshared_key) or None,
                persistent_keepalive=dbp.persistent_keepalive,
            )
            self._vpn_manager.add_peer(peer)
        except Exception as exc:
            logger.warning("[VPN] add_peer_from_db failed for peer %s: %s",
                           getattr(dbp, 'public_key', '?'), exc)
