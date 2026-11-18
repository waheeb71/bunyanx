"""
Identity Services Abstraction (Cisco ISE Style)
Provides an abstract contract for connecting Firewall rules to User Identity,
Active Directory (AD), and Endpoint Posture logic seamlessly.

Phase 11: resolve() now delegates to IdentityCorrelationEngine (ICE) which
unifies LDAP, RADIUS, VPN, and Captive Portal sources via identity_cache.
"""

import logging
from typing import List, Optional
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

class EndPointPosture(BaseModel):
    device_id: str = "unknown"
    os: str = "unknown"
    is_compliant: bool = True     # E.g., AV updated, OS unpatched

class IdentityContext(BaseModel):
    """
    Standardized payload for Identity evaluation.
    Used by the firewall policy engine (AppRule matching).

    NOTE: This is the FIREWALL policy IdentityContext (Pydantic).
    The INSPECTION pipeline uses system.core.inspection_context.IdentityContext (dataclass).
    Both are populated from the same IdentityCorrelationEngine cache.
    """
    user: str = "anonymous"
    groups: List[str] = Field(default_factory=list)
    device: EndPointPosture = Field(default_factory=EndPointPosture)
    authenticated: bool = False


class IdentityManager:
    """
    Singleton resolver — bridges the firewall policy engine to the
    IdentityCorrelationEngine (ICE) cache.

    resolve(src_ip) is called once per connection by the firewall engine.
    """
    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(IdentityManager, cls).__new__(cls)
            cls._instance._init()
        return cls._instance
        
    def _init(self):
        self.enabled = True
        self.logger = logger
        self.logger.info("IdentityManager initialised (backed by IdentityCorrelationEngine)")

    def resolve(self, src_ip: str, metadata: dict = None) -> "IdentityContext":
        """
        Resolve IP → user identity for the firewall policy engine.

        Priority:
          1. IdentityCorrelationEngine cache (LDAP/RADIUS/VPN)
          2. Caller-provided metadata dict (legacy / test)
          3. anonymous fallback
        """
        # 1. ICE cache (production path)
        try:
            from system.auth.identity_engine import IdentityCorrelationEngine
            engine = IdentityCorrelationEngine.get()
            if engine:
                from system.auth.identity_cache import get_identity_cache
                entry = get_identity_cache().get(src_ip)
                if entry and entry.is_authenticated:
                    return IdentityContext(
                        user          = entry.username,
                        groups        = entry.groups,
                        authenticated = True,
                    )
        except Exception as exc:
            self.logger.debug("ICE lookup failed for %s: %s", src_ip, exc)

        # 2. Legacy metadata dict (backward compat / unit tests)
        if metadata and "identity" in metadata:
            try:
                return IdentityContext(**metadata["identity"])
            except Exception:
                pass

        # 3. anonymous
        return IdentityContext(user="anonymous", groups=[], authenticated=False)

# Global Instance
identity_manager = IdentityManager()
