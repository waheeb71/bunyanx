"""
Enterprise BunyanX — Identity Services
=======================================
Phase 11: Full Identity Correlation Engine (ICE)

Exports:
  - LDAPAuthenticator        : Dashboard user login via LDAP/AD
  - LDAPUser                 : Authenticated user data model
  - IdentityCache            : Thread-safe IP → user mapping store
  - UserEntry                : Identity entry data class
  - LDAPUserSync             : Background LDAP/AD user sync daemon
  - RADIUSAccountingListener : Real-time RADIUS Accounting UDP server
  - VPNIdentityBridge        : VPN event → identity cache bridge
  - CaptivePortalBridge      : Captive portal event → identity cache bridge
  - CaptivePortalManager     : Guest session manager (auth + guest passes)
  - IdentityCorrelationEngine: Central orchestrator
  - resolve_identity         : Fast per-packet IP → IdentityContext lookup
"""

from .ldap_auth import LDAPAuthenticator, LDAPUser
from .identity_cache import IdentityCache, UserEntry, get_identity_cache
from .ldap_user_sync import LDAPUserSync
from .radius_accounting import RADIUSAccountingListener
from .vpn_identity_bridge import VPNIdentityBridge
from .captive_portal_bridge import CaptivePortalBridge, CaptivePortalManager
from .identity_engine import IdentityCorrelationEngine, resolve_identity

__all__ = [
    "LDAPAuthenticator",
    "LDAPUser",
    "IdentityCache",
    "UserEntry",
    "get_identity_cache",
    "LDAPUserSync",
    "RADIUSAccountingListener",
    "VPNIdentityBridge",
    "CaptivePortalBridge",
    "CaptivePortalManager",
    "IdentityCorrelationEngine",
    "resolve_identity",
]
