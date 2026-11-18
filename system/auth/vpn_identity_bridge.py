"""
VPN Identity Bridge — BunyanX NGFW
====================================
Subscribes to VPN module EventBus events and updates the IdentityCache
so that remote-access VPN users appear in UBA like any internal user.

Events consumed
---------------
Topics.VPN_CONNECTED     → cache.set(assigned_ip, username)
Topics.VPN_DISCONNECTED  → cache.invalidate(assigned_ip)

These events are already published by the VPN module when a tunnel comes up/down.
"""

from __future__ import annotations

import logging
from typing import Optional

from .identity_cache import IdentityCache, get_identity_cache

logger = logging.getLogger(__name__)


class VPNIdentityBridge:
    """
    Listens for VPN lifecycle events and keeps IdentityCache in sync.

    Usage
    -----
        bridge = VPNIdentityBridge(cfg)
        bridge.start()   # registers EventBus handlers
    """

    _singleton: Optional["VPNIdentityBridge"] = None

    def __init__(self, cfg: dict, cache: Optional[IdentityCache] = None):
        vpn_cfg = cfg.get("vpn_bridge", {})
        self.enabled = vpn_cfg.get("enabled", True)
        self.ttl     = int(vpn_cfg.get("ttl_seconds", 86400))  # 24h default for VPN sessions
        self._cache  = cache or get_identity_cache()

    def start(self) -> None:
        if not self.enabled:
            logger.info("[VPNBridge] Disabled in config")
            return
        try:
            from system.events.bus import EventBus
            from system.events.topics import Topics

            EventBus.subscribe_from_thread(Topics.VPN_CONNECTED,    self._on_vpn_connect)
            EventBus.subscribe_from_thread(Topics.VPN_DISCONNECTED, self._on_vpn_disconnect)
            logger.info("[VPNBridge] ✅ Subscribed to VPN events")
        except Exception as exc:
            logger.warning("[VPNBridge] Could not subscribe to EventBus: %s", exc)

    def _on_vpn_connect(self, payload: dict) -> None:
        """
        Called when a VPN tunnel is established.

        Expected payload keys:
            assigned_ip   the IP assigned to the client inside the VPN
            username      the authenticated username
            real_ip       the client's real public IP (optional)
            groups        list of AD groups (optional)
            role          NGFW role (optional)
        """
        ip       = payload.get("assigned_ip", "")
        username = payload.get("username", "")
        if not ip or not username:
            return

        self._cache.set(
            ip,
            username,
            display_name = payload.get("display_name", username),
            email        = payload.get("email", ""),
            groups       = payload.get("groups", []),
            role         = payload.get("role", "user"),
            department   = payload.get("department", ""),
            source       = "vpn",
            ttl          = self.ttl,
        )
        logger.info("[VPNBridge] VPN connect: %s → %s", ip, username)

    def _on_vpn_disconnect(self, payload: dict) -> None:
        """
        Called when a VPN tunnel is torn down.

        Expected payload keys:
            assigned_ip   the previously assigned VPN IP
            username      the user (for logging only)
        """
        ip       = payload.get("assigned_ip", "")
        username = payload.get("username", "")
        if ip:
            self._cache.invalidate(ip)
            logger.info("[VPNBridge] VPN disconnect: %s (was %s)", ip, username)

    @classmethod
    def configure_and_start(
        cls,
        cfg: dict,
        cache: Optional[IdentityCache] = None,
    ) -> "VPNIdentityBridge":
        cls._singleton = cls(cfg, cache=cache)
        cls._singleton.start()
        return cls._singleton

    @classmethod
    def get(cls) -> Optional["VPNIdentityBridge"]:
        return cls._singleton
