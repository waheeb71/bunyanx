"""
Captive Portal Bridge — BunyanX NGFW
======================================
Provides guest/BYOD identity resolution for networks without Active Directory.

Two components in one file:
  1. CaptivePortalBridge  — subscribes to CAPTIVE_PORTAL_LOGIN/LOGOUT events
                            and updates IdentityCache (same pattern as VPN bridge)
  2. CaptivePortalManager — manages active portal sessions, enforces TTL,
                            and exposes the REST-callable login/logout API

How it works:
  ┌─────────────────────────────────────────────┐
  │           Guest opens any HTTP page          │
  │   Browser redirected to: /captive/login      │
  │   (redirect handled by firewall/proxy rule)  │
  └──────────────────────┬──────────────────────┘
                         │
  ┌──────────────────────▼──────────────────────┐
  │        CaptivePortalManager.authenticate()   │
  │   - Validates credentials (or guest pass)   │
  │   - Binds MAC + IP → username               │
  │   - Publishes CAPTIVE_PORTAL_LOGIN event     │
  └──────────────────────┬──────────────────────┘
                         │
  ┌──────────────────────▼──────────────────────┐
  │        CaptivePortalBridge._on_login()       │
  │   - identity_cache.set(ip, username)         │
  │   - source = "captive"                       │
  └─────────────────────────────────────────────┘

Supported auth modes (configured in identity_correlation.yaml):
  - "none"       : open portal — just collect device info (MAC, hostname)
  - "guest_pass" : pre-generated 8-char codes (receptionist gives to visitor)
  - "ldap"       : authenticate against LDAP/AD (employees on guest WiFi)
  - "social"     : redirect to OAuth (Google/Azure) — future
  - "sms"        : one-time SMS code — future

Configuration (identity_correlation.yaml → captive_portal):
    enabled:       true
    auth_mode:     "guest_pass"   # none | guest_pass | ldap
    ttl_seconds:   28800          # 8 hours (default)
    max_sessions:  10000
    landing_url:   "https://ngfw.company.com/captive/login"
    redirect_url:  "https://company.com"   # after successful login
    guest_pass:
      length:      8
      valid_hours: 24
      single_use:  false
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import string
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .identity_cache import IdentityCache, get_identity_cache

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PortalSession:
    """
    An active Captive Portal session.

    Fields
    ------
    session_id  UUID-like token stored in browser cookie
    src_ip      Client IP at login time
    mac_address MAC address (populated if available via ARP table)
    username    Authenticated user or guest identifier
    auth_mode   How the user authenticated
    created_at  Unix timestamp
    expires_at  Unix timestamp (0 = never)
    last_active Last HTTP request timestamp
    """
    session_id:  str
    src_ip:      str
    mac_address: str         = ""
    username:    str         = ""
    auth_mode:   str         = "none"
    created_at:  float       = field(default_factory=time.time)
    expires_at:  float       = 0.0
    last_active: float       = field(default_factory=time.time)

    @property
    def is_expired(self) -> bool:
        return self.expires_at > 0 and time.time() > self.expires_at

    def touch(self) -> None:
        self.last_active = time.time()

    def to_dict(self) -> dict:
        return {
            "session_id":  self.session_id,
            "src_ip":      self.src_ip,
            "mac_address": self.mac_address,
            "username":    self.username,
            "auth_mode":   self.auth_mode,
            "created_at":  self.created_at,
            "expires_at":  self.expires_at,
            "last_active": self.last_active,
        }


@dataclass
class GuestPass:
    """A single-use or multi-use guest access code."""
    code:        str
    created_by:  str           = "admin"
    created_at:  float         = field(default_factory=time.time)
    expires_at:  float         = 0.0
    single_use:  bool          = False
    used_by:     List[str]     = field(default_factory=list)  # list of IPs that used it
    max_uses:    int           = 0   # 0 = unlimited

    @property
    def is_expired(self) -> bool:
        return self.expires_at > 0 and time.time() > self.expires_at

    @property
    def is_exhausted(self) -> bool:
        if self.single_use and len(self.used_by) >= 1:
            return True
        if self.max_uses > 0 and len(self.used_by) >= self.max_uses:
            return True
        return False

    @property
    def is_valid(self) -> bool:
        return not self.is_expired and not self.is_exhausted


# ─────────────────────────────────────────────────────────────────────────────
# Manager
# ─────────────────────────────────────────────────────────────────────────────

class CaptivePortalManager:
    """
    Manages guest sessions and enforces authentication policy.

    Usage
    -----
        manager = CaptivePortalManager(cfg)
        # In REST API:
        result = manager.authenticate(src_ip, code="ABCD1234", mac="aa:bb:cc:dd:ee:ff")
        if result["success"]:
            ...redirect to company website...
    """

    _singleton: Optional["CaptivePortalManager"] = None
    _singleton_lock = threading.Lock()

    def __init__(self, cfg: dict, cache: Optional[IdentityCache] = None):
        cp_cfg = cfg.get("captive_portal", {})

        self.enabled       = cp_cfg.get("enabled", False)
        self.auth_mode     = cp_cfg.get("auth_mode", "guest_pass")
        self.ttl           = int(cp_cfg.get("ttl_seconds", 28800))    # 8 hours
        self.max_sessions  = int(cp_cfg.get("max_sessions", 10_000))
        self.redirect_url  = cp_cfg.get("redirect_url", "https://www.google.com")
        self.landing_url   = cp_cfg.get("landing_url", "/captive/login")

        gp_cfg             = cp_cfg.get("guest_pass", {})
        self._gp_length    = int(gp_cfg.get("length", 8))
        self._gp_hours     = int(gp_cfg.get("valid_hours", 24))
        self._gp_single    = bool(gp_cfg.get("single_use", False))

        # LDAP config (for ldap auth_mode)
        self._ldap_cfg     = cfg.get("ldap_sync", {})

        self._cache        = cache or get_identity_cache()
        self._lock         = threading.RLock()

        # Active sessions: session_id → PortalSession
        self._sessions: Dict[str, PortalSession] = {}
        # IP → session_id (fast lookup per packet)
        self._ip_index: Dict[str, str] = {}
        # Guest passes: code → GuestPass
        self._guest_passes: Dict[str, GuestPass] = {}

        # Background cleanup
        self._stop_event = threading.Event()
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            name="captive-portal-cleanup",
            daemon=True,
        )
        self._cleanup_thread.start()

    # ── Authentication ────────────────────────────────────────────────────────

    def authenticate(
        self,
        src_ip:      str,
        mac_address: str = "",
        *,
        username:    str = "",
        password:    str = "",
        guest_code:  str = "",
    ) -> dict:
        """
        Authenticate a client and create a portal session.

        Returns dict:
            {
                "success":      bool,
                "session_id":   str,   # browser cookie value
                "username":     str,
                "redirect_url": str,
                "error":        str,   # if not success
            }
        """
        if not self.enabled:
            return {"success": False, "error": "Captive portal disabled"}

        # ── Auth dispatch ─────────────────────────────────────────────────────
        auth_username = ""
        auth_error    = ""

        if self.auth_mode == "none":
            # Open portal — just register device, no credentials needed
            auth_username = f"guest@{src_ip}"

        elif self.auth_mode == "guest_pass":
            result = self._validate_guest_pass(guest_code.strip().upper(), src_ip)
            if result["valid"]:
                auth_username = result["username"]
            else:
                auth_error = result["error"]

        elif self.auth_mode == "ldap":
            result = self._validate_ldap(username, password)
            if result["valid"]:
                auth_username = result["username"]
            else:
                auth_error = result["error"]

        else:
            auth_error = f"Unknown auth_mode: {self.auth_mode}"

        if auth_error:
            logger.warning(
                "[CaptivePortal] Auth failed for %s (mode=%s): %s",
                src_ip, self.auth_mode, auth_error,
            )
            return {"success": False, "error": auth_error}

        # ── Create session ────────────────────────────────────────────────────
        session = self._create_session(
            src_ip=src_ip,
            mac_address=mac_address,
            username=auth_username,
        )

        # ── Update IdentityCache ──────────────────────────────────────────────
        self._cache.set(
            src_ip,
            auth_username,
            display_name = auth_username,
            source       = "captive",
            role         = "user",
            ttl          = self.ttl,
        )

        # ── Publish event ─────────────────────────────────────────────────────
        self._publish("captive_portal.login", {
            "src_ip":      src_ip,
            "username":    auth_username,
            "mac_address": mac_address,
            "auth_mode":   self.auth_mode,
            "session_id":  session.session_id,
        })

        logger.info(
            "[CaptivePortal] ✅ Login: %s → %s (mode=%s mac=%s)",
            src_ip, auth_username, self.auth_mode, mac_address or "unknown",
        )
        return {
            "success":      True,
            "session_id":   session.session_id,
            "username":     auth_username,
            "redirect_url": self.redirect_url,
        }

    def logout(self, src_ip: str = "", session_id: str = "") -> bool:
        """
        Explicitly log out a session.
        Either src_ip or session_id must be provided.
        """
        with self._lock:
            if session_id and session_id in self._sessions:
                session = self._sessions.pop(session_id)
                self._ip_index.pop(session.src_ip, None)
                self._cache.invalidate(session.src_ip)
                self._publish("captive_portal.logout", {
                    "src_ip":   session.src_ip,
                    "username": session.username,
                    "reason":   "explicit_logout",
                })
                logger.info("[CaptivePortal] Logout: %s (%s)", session.src_ip, session.username)
                return True

            if src_ip:
                sid = self._ip_index.pop(src_ip, None)
                if sid and sid in self._sessions:
                    session = self._sessions.pop(sid)
                    self._cache.invalidate(src_ip)
                    self._publish("captive_portal.logout", {
                        "src_ip":   src_ip,
                        "username": session.username,
                        "reason":   "explicit_logout",
                    })
                    logger.info("[CaptivePortal] Logout: %s (%s)", src_ip, session.username)
                    return True

        return False

    def is_authenticated(self, src_ip: str) -> bool:
        """Check if an IP currently has a valid portal session."""
        with self._lock:
            sid = self._ip_index.get(src_ip)
            if not sid:
                return False
            session = self._sessions.get(sid)
            if not session or session.is_expired:
                return False
            session.touch()
            return True

    # ── Guest Pass management ─────────────────────────────────────────────────

    def generate_guest_pass(
        self,
        created_by:  str  = "admin",
        valid_hours: int  = None,
        single_use:  bool = None,
        max_uses:    int  = 0,
    ) -> GuestPass:
        """
        Generate a new guest pass code.

        Args
        ----
        created_by   Who issued the pass (for audit trail)
        valid_hours  Override default validity
        single_use   Override default single-use setting
        max_uses     Maximum number of devices that can use this code

        Returns the GuestPass object (contains .code).
        """
        alphabet = string.ascii_uppercase + string.digits
        code = "".join(secrets.choice(alphabet) for _ in range(self._gp_length))

        hours    = valid_hours if valid_hours is not None else self._gp_hours
        su       = single_use  if single_use  is not None else self._gp_single
        expires  = time.time() + hours * 3600 if hours > 0 else 0.0

        gp = GuestPass(
            code        = code,
            created_by  = created_by,
            expires_at  = expires,
            single_use  = su,
            max_uses    = max_uses,
        )

        with self._lock:
            self._guest_passes[code] = gp

        logger.info(
            "[CaptivePortal] Guest pass generated: %s (by=%s valid=%dh single_use=%s)",
            code, created_by, hours, su,
        )
        return gp

    def revoke_guest_pass(self, code: str) -> bool:
        with self._lock:
            if code in self._guest_passes:
                del self._guest_passes[code]
                return True
            return False

    def list_guest_passes(self) -> List[dict]:
        with self._lock:
            return [
                {
                    "code":       gp.code,
                    "created_by": gp.created_by,
                    "expires_at": gp.expires_at,
                    "single_use": gp.single_use,
                    "max_uses":   gp.max_uses,
                    "used_count": len(gp.used_by),
                    "valid":      gp.is_valid,
                }
                for gp in self._guest_passes.values()
            ]

    # ── Observability ─────────────────────────────────────────────────────────

    def active_sessions(self) -> List[dict]:
        with self._lock:
            return [
                s.to_dict()
                for s in self._sessions.values()
                if not s.is_expired
            ]

    def status(self) -> dict:
        with self._lock:
            return {
                "enabled":        self.enabled,
                "auth_mode":      self.auth_mode,
                "ttl_seconds":    self.ttl,
                "active_sessions": len([s for s in self._sessions.values() if not s.is_expired]),
                "guest_passes":   len(self._guest_passes),
            }

    def stop(self) -> None:
        self._stop_event.set()

    # ── Private helpers ───────────────────────────────────────────────────────

    def _create_session(self, src_ip: str, mac_address: str, username: str) -> PortalSession:
        """Create and register a new portal session."""
        session_id = secrets.token_urlsafe(32)
        session = PortalSession(
            session_id  = session_id,
            src_ip      = src_ip,
            mac_address = mac_address,
            username    = username,
            auth_mode   = self.auth_mode,
            expires_at  = time.time() + self.ttl if self.ttl > 0 else 0.0,
        )
        with self._lock:
            # Evict oldest if at capacity
            if len(self._sessions) >= self.max_sessions:
                self._evict_oldest()
            self._sessions[session_id] = session
            self._ip_index[src_ip]     = session_id
        return session

    def _validate_guest_pass(self, code: str, src_ip: str) -> dict:
        """Validate a guest pass code."""
        with self._lock:
            gp = self._guest_passes.get(code)
        if not gp:
            return {"valid": False, "error": "Invalid guest pass"}
        if not gp.is_valid:
            return {"valid": False, "error": "Guest pass expired or exhausted"}
        with self._lock:
            gp.used_by.append(src_ip)
        return {"valid": True, "username": f"guest/{code}"}

    def _validate_ldap(self, username: str, password: str) -> dict:
        """Validate credentials against LDAP/AD (for employee access on guest WiFi)."""
        if not username or not password:
            return {"valid": False, "error": "Username and password required"}
        try:
            from system.auth.ldap_auth import LDAPAuthenticator
            auth = LDAPAuthenticator(self._ldap_cfg)
            result = auth.authenticate(username, password)
            if result:
                return {"valid": True, "username": username}
            return {"valid": False, "error": "Invalid credentials"}
        except Exception as exc:
            logger.error("[CaptivePortal] LDAP auth error: %s", exc)
            return {"valid": False, "error": "Authentication service unavailable"}

    def _evict_oldest(self) -> None:
        """Evict the session with the oldest last_active timestamp (under lock)."""
        if not self._sessions:
            return
        oldest_sid = min(self._sessions, key=lambda s: self._sessions[s].last_active)
        session    = self._sessions.pop(oldest_sid)
        self._ip_index.pop(session.src_ip, None)

    def _cleanup_loop(self) -> None:
        """Background thread: remove expired sessions every 60 seconds."""
        while not self._stop_event.wait(timeout=60):
            self._remove_expired()

    def _remove_expired(self) -> int:
        removed = 0
        now = time.time()
        with self._lock:
            expired_sids = [
                sid for sid, s in self._sessions.items()
                if s.expires_at > 0 and now > s.expires_at
            ]
            for sid in expired_sids:
                session = self._sessions.pop(sid)
                self._ip_index.pop(session.src_ip, None)
                self._cache.invalidate(session.src_ip)
                self._publish("captive_portal.logout", {
                    "src_ip":   session.src_ip,
                    "username": session.username,
                    "reason":   "ttl_expired",
                })
                removed += 1

            # Also purge expired guest passes
            expired_codes = [c for c, gp in self._guest_passes.items() if gp.is_expired]
            for code in expired_codes:
                del self._guest_passes[code]

        if removed:
            logger.info("[CaptivePortal] Cleanup: removed %d expired sessions", removed)
        return removed

    @staticmethod
    def _publish(topic_str: str, payload: dict) -> None:
        try:
            from system.events.bus import EventBus
            EventBus.publish_from_thread(topic_str, payload)
        except Exception:
            pass

    # ── Singleton ─────────────────────────────────────────────────────────────

    @classmethod
    def configure_and_start(
        cls,
        cfg:   dict,
        cache: Optional[IdentityCache] = None,
    ) -> "CaptivePortalManager":
        with cls._singleton_lock:
            if cls._singleton is not None:
                cls._singleton.stop()
            cls._singleton = cls(cfg, cache=cache)
        return cls._singleton

    @classmethod
    def get(cls) -> Optional["CaptivePortalManager"]:
        return cls._singleton


# ─────────────────────────────────────────────────────────────────────────────
# Bridge (EventBus consumer — same pattern as VPNIdentityBridge)
# ─────────────────────────────────────────────────────────────────────────────

class CaptivePortalBridge:
    """
    Subscribes to CAPTIVE_PORTAL_LOGIN/LOGOUT events published by
    CaptivePortalManager and updates the IdentityCache.

    This is the EventBus consumer side. CaptivePortalManager is the publisher.
    Both run in the same process but are decoupled via the bus for testability.
    """

    _singleton: Optional["CaptivePortalBridge"] = None

    def __init__(self, cfg: dict, cache: Optional[IdentityCache] = None):
        cp_cfg = cfg.get("captive_portal", {})
        self.enabled = cp_cfg.get("enabled", False)
        self.ttl     = int(cp_cfg.get("ttl_seconds", 28800))
        self._cache  = cache or get_identity_cache()

    def start(self) -> None:
        if not self.enabled:
            logger.info("[CaptivePortalBridge] Disabled in config")
            return
        try:
            from system.events.bus import EventBus
            from system.events.topics import Topics
           
            EventBus.subscribe_from_thread(Topics.CAPTIVE_PORTAL_LOGIN,  self._on_login)
            EventBus.subscribe_from_thread(Topics.CAPTIVE_PORTAL_LOGOUT, self._on_logout)
            logger.info("[CaptivePortalBridge] ✅ Subscribed to captive portal events")
        except Exception as exc:
            logger.warning("[CaptivePortalBridge] Could not subscribe: %s", exc)

    def _on_login(self, payload: dict) -> None:
        """
        Called when a guest/BYOD device authenticates.

        Payload keys:
            src_ip      client IP
            username    authenticated name (e.g. "guest/ABCD1234")
            mac_address MAC address (optional)
            auth_mode   how they authenticated
            session_id  portal session token
        """
        ip       = payload.get("src_ip", "")
        username = payload.get("username", "")
        if not ip or not username:
            return

        self._cache.set(
            ip,
            username,
            display_name = payload.get("display_name", username),
            source       = "captive",
            role         = "user",
            ttl          = self.ttl,
        )
        logger.info("[CaptivePortalBridge] LOGIN  %s → %s", ip, username)

    def _on_logout(self, payload: dict) -> None:
        """
        Called when a portal session expires or is explicitly terminated.

        Payload keys:
            src_ip    client IP
            username  (for logging only)
            reason    "explicit_logout" | "ttl_expired"
        """
        ip       = payload.get("src_ip", "")
        username = payload.get("username", "")
        reason   = payload.get("reason", "unknown")
        if ip:
            self._cache.invalidate(ip)
            logger.info(
                "[CaptivePortalBridge] LOGOUT %s (was %s, reason=%s)",
                ip, username, reason,
            )

    @classmethod
    def configure_and_start(
        cls,
        cfg:   dict,
        cache: Optional[IdentityCache] = None,
    ) -> "CaptivePortalBridge":
        cls._singleton = cls(cfg, cache=cache)
        cls._singleton.start()
        return cls._singleton

    @classmethod
    def get(cls) -> Optional["CaptivePortalBridge"]:
        return cls._singleton
