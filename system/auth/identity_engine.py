"""
Identity Correlation Engine — BunyanX NGFW
===========================================
Central orchestrator that:
  1. Loads identity_correlation.yaml
  2. Starts all configured identity sources (LDAP, RADIUS, VPN, …)
  3. Exposes resolve(src_ip) → IdentityContext for the InspectionPipeline
  4. Provides status/stats for the API dashboard

Usage
-----
    # At startup (called once by app_state or main.py)
    from system.auth.identity_engine import IdentityCorrelationEngine
    ice = IdentityCorrelationEngine.start_from_config("system/config/identity_correlation.yaml")

    # Per-packet (called by ContextBuilder)
    from system.auth.identity_engine import resolve_identity
    ctx.identity = resolve_identity(src_ip)
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from system.core.inspection_context import IdentityContext
from .identity_cache import IdentityCache, UserEntry

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _load_yaml(path: str) -> dict:
    try:
        import yaml
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except ImportError:
        logger.error("[ICE] PyYAML not installed — pip install pyyaml")
        return {}
    except FileNotFoundError:
        logger.warning("[ICE] Config not found: %s — using defaults", path)
        return {}
    except Exception as exc:
        logger.error("[ICE] Failed to load %s: %s", path, exc)
        return {}


# ─────────────────────────────────────────────────────────────────────────────
# Engine
# ─────────────────────────────────────────────────────────────────────────────

class IdentityCorrelationEngine:
    """
    Orchestrates all identity sources and provides a unified resolve() API.

    Singleton — use IdentityCorrelationEngine.get() after start_from_config().
    """

    _singleton: Optional["IdentityCorrelationEngine"] = None

    def __init__(self, cfg: dict):
        self._cfg   = cfg
        self._cache = IdentityCache.configure(cfg)

        # Source instances (None if not started)
        self._ldap_sync       = None
        self._radius          = None
        self._vpn_bridge      = None
        self._captive_manager = None
        self._captive_bridge  = None

        # Source priority map (higher = wins on conflict)
        prio_cfg = cfg.get("source_priority", {})
        self._priority = {
            "manual":    prio_cfg.get("manual",    100),
            "radius":    prio_cfg.get("radius",     80),
            "vpn":       prio_cfg.get("vpn",        70),
            "ldap_sync": prio_cfg.get("ldap_sync",  50),
            "captive":   prio_cfg.get("captive",    40),
        }

    # ── Startup ───────────────────────────────────────────────────────────────

    def _start_ldap(self) -> None:
        try:
            from .ldap_user_sync import LDAPUserSync
            self._ldap_sync = LDAPUserSync.configure_and_start(
                self._cfg, cache=self._cache
            )
        except Exception as exc:
            logger.error("[ICE] LDAP sync failed to start: %s", exc)

    def _start_radius(self) -> None:
        try:
            from .radius_accounting import RADIUSAccountingListener
            self._radius = RADIUSAccountingListener.configure_and_start(
                self._cfg, cache=self._cache
            )
        except Exception as exc:
            logger.error("[ICE] RADIUS listener failed to start: %s", exc)

    def _start_vpn(self) -> None:
        try:
            from .vpn_identity_bridge import VPNIdentityBridge
            self._vpn_bridge = VPNIdentityBridge.configure_and_start(
                self._cfg, cache=self._cache
            )
        except Exception as exc:
            logger.error("[ICE] VPN bridge failed to start: %s", exc)

    def _start_captive_portal(self) -> None:
        try:
            from .captive_portal_bridge import CaptivePortalBridge, CaptivePortalManager
            # Start the session manager (auth logic + guest passes)
            self._captive_manager = CaptivePortalManager.configure_and_start(
                self._cfg, cache=self._cache
            )
            # Start the EventBus consumer (cache updater)
            self._captive_bridge = CaptivePortalBridge.configure_and_start(
                self._cfg, cache=self._cache
            )
        except Exception as exc:
            logger.error("[ICE] Captive portal failed to start: %s", exc)

    def start(self) -> "IdentityCorrelationEngine":
        """Start all enabled identity sources."""
        logger.info("[ICE] ✅ Identity Correlation Engine starting...")

        ldap_enabled    = self._cfg.get("ldap_sync",         {}).get("enabled", False)
        radius_enabled  = self._cfg.get("radius_accounting", {}).get("enabled", False)
        vpn_enabled     = self._cfg.get("vpn_bridge",        {}).get("enabled", True)
        captive_enabled = self._cfg.get("captive_portal",    {}).get("enabled", False)

        if ldap_enabled:
            self._start_ldap()
        if radius_enabled:
            self._start_radius()
        if vpn_enabled:
            self._start_vpn()
        if captive_enabled:
            self._start_captive_portal()

        active = [
            s for s, e in [
                ("ldap_sync",      ldap_enabled),
                ("radius",         radius_enabled),
                ("vpn",            vpn_enabled),
                ("captive_portal", captive_enabled),
            ] if e
        ]
        logger.info("[ICE] Active sources: %s", active or ["none — anonymous mode"])
        return self

    def stop(self) -> None:
        """Gracefully stop all sources."""
        if self._ldap_sync:
            self._ldap_sync.stop()
        if self._radius:
            self._radius.stop()
        self._cache.stop()
        logger.info("[ICE] Stopped")

    # ── Core API ──────────────────────────────────────────────────────────────

    def resolve(self, src_ip: str) -> IdentityContext:
        """
        Resolve an IP address to a user IdentityContext.

        Lookup order:
          1. IdentityCache (all sources write here)
          2. anonymous fallback

        Returns IdentityContext — never raises.
        """
        if not src_ip:
            return IdentityContext()

        entry: Optional[UserEntry] = self._cache.get(src_ip)
        if entry and entry.is_authenticated:
            return IdentityContext(
                user_id    = entry.username,
                role       = entry.role,
                tenant_id  = entry.department,
            )
        return IdentityContext()

    def bind_manual(
        self,
        ip:       str,
        username: str,
        *,
        role:       str = "user",
        department: str = "",
        ttl:        int = 3600,
    ) -> UserEntry:
        """
        Manually bind an IP → user (REST API / admin override).
        Source = "manual" (highest priority).
        """
        entry = self._cache.set(
            ip, username,
            role       = role,
            department = department,
            source     = "manual",
            ttl        = ttl,
        )
        logger.info("[ICE] Manual bind: %s → %s (ttl=%ds)", ip, username, ttl)
        return entry

    def unbind(self, ip: str) -> bool:
        """Remove a manual or any binding for an IP."""
        return self._cache.invalidate(ip)

    def force_ldap_sync(self) -> int:
        """Trigger immediate LDAP sync (blocking). Returns bindings written."""
        if self._ldap_sync:
            return self._ldap_sync.force_sync()
        return 0

    # ── Observability ─────────────────────────────────────────────────────────

    def status(self) -> dict:
        return {
            "cache":          self._cache.stats(),
            "ldap_sync":      self._ldap_sync.status()      if self._ldap_sync      else {"enabled": False},
            "radius":         self._radius.status()         if self._radius         else {"enabled": False},
            "vpn_bridge":     {"enabled": bool(self._vpn_bridge)},
            "captive_portal": self._captive_manager.status() if self._captive_manager else {"enabled": False},
        }

    def all_bindings(self) -> list:
        """Return all active IP→user bindings (for API/dashboard)."""
        return self._cache.all_entries()

    # ── Singleton ─────────────────────────────────────────────────────────────

    @classmethod
    def start_from_config(cls, config_path: str) -> "IdentityCorrelationEngine":
        """Load config and start the engine. Returns the singleton."""
        cfg = _load_yaml(config_path)
        instance = cls(cfg)
        instance.start()
        cls._singleton = instance
        return instance

    @classmethod
    def get(cls) -> Optional["IdentityCorrelationEngine"]:
        return cls._singleton


# ─────────────────────────────────────────────────────────────────────────────
# Module-level fast accessor (used by ContextBuilder per-packet)
# ─────────────────────────────────────────────────────────────────────────────

def resolve_identity(src_ip: str) -> IdentityContext:
    """
    Fast per-packet identity resolution.

    Falls back to anonymous if the engine is not yet started.
    """
    engine = IdentityCorrelationEngine.get()
    if engine:
        return engine.resolve(src_ip)
    return IdentityContext()
