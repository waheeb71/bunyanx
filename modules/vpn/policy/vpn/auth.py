"""
Enterprise bunyanx - VPN User Authentication
================================================
Authenticates VPN users against the system's central User database.
Supports local accounts (bcrypt) with RBAC checks via the Rule table.
Designed to be extensible for LDAP/RADIUS in future phases.
"""

import logging
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)


# ── Domain Object ─────────────────────────────────────────────────────────────

@dataclass
class VPNUser:
    """Authenticated VPN user identity."""
    username: str
    role: str
    groups: List[str] = field(default_factory=list)
    email: Optional[str] = None

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "role": self.role,
            "groups": self.groups,
            "email": self.email,
        }


# ── Authentication Manager ────────────────────────────────────────────────────

class UserAuth:
    """
    Authenticates VPN users against the bunyanx central User table.

    Authentication flow:
      1. Lookup user by username (must be active).
      2. Verify password against bcrypt hash.
      3. Check VPN access: admins/operators always pass;
         other roles must have an explicit Rule with resource='vpn'.

    Args:
        db_session_factory: Optional callable returning a SQLAlchemy Session.
                            Falls back to the global SessionLocal helper if None.
    """

    def __init__(self, db_session_factory=None):
        self._db_session_factory = db_session_factory

    # ── Public API ────────────────────────────────────────────────────────────

    def authenticate(self, username: str, password: str) -> Optional[VPNUser]:
        """
        Verify credentials and VPN access rights.

        Returns:
            VPNUser on success, None on failure.
        """
        if not username or not password:
            logger.warning("VPN Auth: Empty username or password rejected.")
            return None

        session = self._get_session()
        if session is None:
            logger.error("VPN Auth: No DB session available — authentication aborted.")
            return None

        try:
            return self._do_authenticate(session, username, password)
        except Exception as exc:
            logger.error("VPN Auth: Unexpected error for '%s': %s", username, exc, exc_info=True)
            return None
        finally:
            session.close()

    def has_vpn_permission(self, username: str) -> bool:
        """
        Check VPN access rights without password verification.
        Useful for post-authentication policy checks.
        """
        session = self._get_session()
        if session is None:
            return False
        try:
            from system.database.database import User, Rule
            user = session.query(User).filter_by(username=username, is_active=True).first()
            if not user:
                return False
            return self._check_vpn_access(session, user)
        except Exception as exc:
            logger.error("VPN Auth: Permission check error for '%s': %s", username, exc)
            return False
        finally:
            session.close()

    # ── Internal Helpers ──────────────────────────────────────────────────────

    def _do_authenticate(self, session, username: str, password: str) -> Optional[VPNUser]:
        """Core authentication logic — runs inside an open session."""
        from system.database.database import User

        # Step 1: Lookup active user
        user = session.query(User).filter_by(username=username, is_active=True).first()
        if not user:
            logger.warning("VPN Auth: Unknown or inactive user '%s'.", username)
            return None

        # Step 2: Verify password
        if not self._verify_password(password, user.password_hash):
            logger.warning("VPN Auth: Invalid password for user '%s'.", username)
            return None

        # Step 3: RBAC — check VPN access
        if not self._check_vpn_access(session, user):
            logger.warning("VPN Auth: User '%s' (role=%s) lacks VPN permission.", username, user.role)
            return None

        logger.info("VPN Auth: ✅ User '%s' (role=%s) authenticated successfully.", username, user.role)
        return VPNUser(
            username=user.username,
            role=user.role,
            groups=[user.role],
            email=user.email,
        )

    def _check_vpn_access(self, session, user) -> bool:
        """
        Returns True when the user is allowed to use VPN.

        Rules:
          - role == 'admin'    → always allowed
          - role == 'operator' → always allowed
          - other roles        → must have a Rule(resource='vpn', enabled=True)
        """
        if user.role in ("admin", "operator"):
            return True

        from system.database.database import Rule
        rule = session.query(Rule).filter_by(
            user_id=user.id,
            resource="vpn",
            enabled=True,
        ).first()
        return rule is not None

    @staticmethod
    def _verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify a plain-text password against a stored bcrypt hash."""
        try:
            import bcrypt
            return bcrypt.checkpw(
                plain_password.encode("utf-8"),
                hashed_password.encode("utf-8"),
            )
        except Exception as exc:
            logger.error("VPN Auth: bcrypt verification error: %s", exc)
            return False

    def _get_session(self):
        """Acquire a SQLAlchemy Session from factory or global helper."""
        if self._db_session_factory:
            try:
                return self._db_session_factory()
            except Exception as exc:
                logger.error("VPN Auth: Session factory error: %s", exc)
                return None
        try:
            from system.database.database import SessionLocal
            return SessionLocal()
        except Exception as exc:
            logger.error("VPN Auth: Could not acquire DB session: %s", exc)
            return None
