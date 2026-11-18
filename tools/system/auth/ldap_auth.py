#!/usr/bin/env python3
"""
Enterprise bunyanx - LDAP/Active Directory Authentication

Features:
- LDAP bind/search for user authentication (LDAPS only — plain LDAP rejected)
- Group-based role mapping (admin/operator/viewer)
- Thread-safe connection pool (max configurable pool size)
- bind_password loaded from env var (BUNYANX_LDAP_BIND_PASSWORD)
- Fallback to local auth if LDAP unavailable
- LDAP Injection protection via escape_filter_chars()
"""

import os
import logging
import threading
from typing import Optional, List
from dataclasses import dataclass, field
from queue import Queue, Empty

logger = logging.getLogger(__name__)


@dataclass
class LDAPUser:
    """Authenticated LDAP user"""
    username: str
    display_name: str
    email: str
    groups: List[str]
    role: str        # admin | operator | viewer
    dn: str


class LDAPAuthenticator:
    """
    LDAP/Active Directory Authentication.

    Authenticates users against an LDAP directory and maps
    AD groups to bunyanx roles.

    Configuration is read from base.yaml → integration.ldap.
    The bind_password MUST be set via the BUNYANX_LDAP_BIND_PASSWORD
    environment variable — never hardcoded in config files.
    """

    # Default group-to-role mapping (overridden by config)
    DEFAULT_ROLE_MAP = {
        "bunyanx-admins":    "admin",
        "bunyanx-operators": "operator",
        "Domain Admins":     "admin",
        "bunyanx-viewers":   "viewer",
    }

    def __init__(self, config: dict):
        self.config = config
        ldap_cfg = config.get('integration', {}).get('ldap', {})

        self.enabled          = ldap_cfg.get('enabled', False)
        self.server           = ldap_cfg.get('server', 'ldaps://localhost:636')
        self.base_dn          = ldap_cfg.get('base_dn', 'dc=example,dc=com')
        self.bind_dn          = ldap_cfg.get('bind_dn', '')
        self.search_filter    = ldap_cfg.get('search_filter', '(sAMAccountName={username})')
        self.group_attribute  = ldap_cfg.get('group_attribute', 'memberOf')
        self.role_mapping     = ldap_cfg.get('role_mapping', self.DEFAULT_ROLE_MAP)
        self.timeout          = int(ldap_cfg.get('timeout', 10))
        self._pool_size       = int(ldap_cfg.get('connection_pool_size', 5))

        # ── bind_password: ALWAYS from env var, never from config file ────────
        raw_pw = ldap_cfg.get('bind_password', '')
        if raw_pw.startswith('${') and raw_pw.endswith('}'):
            # Resolve env var placeholder (e.g. ${BUNYANX_LDAP_BIND_PASSWORD})
            env_key = raw_pw[2:-1]
            self.bind_password = os.environ.get(env_key, '')
        else:
            # Direct value (not recommended — warn loudly)
            self.bind_password = raw_pw
            if raw_pw:
                logger.warning(
                    "⚠️  LDAP bind_password is set as a literal in config. "
                    "Use env var BUNYANX_LDAP_BIND_PASSWORD instead."
                )

        # ── Thread-safe connection pool ───────────────────────────────────────
        self._pool: Queue = Queue(maxsize=self._pool_size)
        self._pool_lock = threading.Lock()
        self._pool_initialized = False

        if self.enabled:
            logger.info("LDAPAuthenticator initialized: %s (pool=%d)", self.server, self._pool_size)
        else:
            logger.info("LDAPAuthenticator: LDAP disabled (local auth only)")

    # ── Security enforcement ───────────────────────────────────────────────────

    def _enforce_ldaps(self) -> bool:
        """Reject plain LDAP — only LDAPS is permitted."""
        if not self.server.lower().startswith('ldaps://'):
            logger.critical(
                "🚨 [SECURITY] LDAP server must use ldaps:// protocol. "
                "Plain ldap:// transmits credentials in cleartext. "
                "Current value: %s", self.server
            )
            return False
        return True

    # ── Connection pool ────────────────────────────────────────────────────────

    def _create_connection(self):
        """Create a single authenticated (bind) LDAP connection."""
        import ldap3
        srv = ldap3.Server(
            self.server,
            get_info=ldap3.ALL,
            use_ssl=True,
            connect_timeout=self.timeout,
        )
        conn = ldap3.Connection(
            srv,
            user=self.bind_dn,
            password=self.bind_password,
            auto_bind=True,
            receive_timeout=self.timeout,
        )
        return conn

    def _init_pool(self) -> bool:
        """Populate the connection pool (called lazily on first use)."""
        with self._pool_lock:
            if self._pool_initialized:
                return True
            try:
                for _ in range(self._pool_size):
                    conn = self._create_connection()
                    self._pool.put_nowait(conn)
                self._pool_initialized = True
                logger.info("✅ LDAP connection pool ready (%d connections)", self._pool_size)
                return True
            except ImportError:
                logger.warning("ldap3 package not installed. Run: pip install ldap3")
                return False
            except Exception as exc:
                logger.error("❌ LDAP pool init failed: %s", exc)
                return False

    def _acquire(self):
        """Borrow a connection from the pool (blocks up to timeout)."""
        try:
            return self._pool.get(timeout=self.timeout)
        except Empty:
            logger.warning("LDAP pool exhausted — creating temporary connection")
            return self._create_connection()

    def _release(self, conn) -> None:
        """Return a connection to the pool; recreate if it's broken."""
        try:
            if not conn.bound:
                conn.bind()
            self._pool.put_nowait(conn)
        except Exception:
            # Connection is broken — replace with a fresh one
            try:
                fresh = self._create_connection()
                self._pool.put_nowait(fresh)
            except Exception as exc:
                logger.debug("Failed to replace broken LDAP connection: %s", exc)

    # ── Public API ─────────────────────────────────────────────────────────────

    def connect(self) -> bool:
        """Initialise pool. Returns True if LDAP is ready."""
        if not self.enabled:
            return False
        if not self._enforce_ldaps():
            return False
        return self._init_pool()

    def authenticate(self, username: str, password: str) -> Optional[LDAPUser]:
        """
        Authenticate user against LDAP.

        Args:
            username: sAMAccountName (or configured search filter field)
            password: User's password

        Returns:
            LDAPUser on success, None on failure (caller falls back to local auth)
        """
        if not self.enabled:
            logger.debug("LDAP disabled — skipping")
            return None

        if not self._enforce_ldaps():
            return None

        if not self._pool_initialized:
            if not self._init_pool():
                return None

        conn = self._acquire()
        try:
            import ldap3
            from ldap3.utils.conv import escape_filter_chars

            # ── Search for user DN (LDAP Injection protected) ─────────────────
            safe_user = escape_filter_chars(username)
            search_f  = self.search_filter.replace('{username}', safe_user)

            conn.search(
                search_base=self.base_dn,
                search_filter=search_f,
                search_scope=ldap3.SUBTREE,
                attributes=['cn', 'mail', 'displayName', self.group_attribute],
            )

            if not conn.entries:
                logger.warning("LDAP user not found: %s", username)
                return None

            entry   = conn.entries[0]
            user_dn = entry.entry_dn

            # ── Bind as the user to verify password ────────────────────────────
            # Each user bind uses a dedicated short-lived connection (not pooled)
            # so credentials are not mixed with the service bind connection.
            user_conn = ldap3.Connection(
                conn.server,
                user=user_dn,
                password=password,
                receive_timeout=self.timeout,
            )
            try:
                if not user_conn.bind():
                    logger.warning("LDAP auth failed for: %s", username)
                    return None
            finally:
                user_conn.unbind()   # always release, even on exception

            # ── Extract groups ─────────────────────────────────────────────────
            groups: List[str] = []
            if hasattr(entry, self.group_attribute):
                raw = getattr(entry, self.group_attribute).values
                groups = [self._extract_cn(g) for g in raw]

            role = self._resolve_role(groups)

            logger.info("✅ LDAP auth OK: %s → role=%s groups=%s", username, role, groups)
            return LDAPUser(
                username=username,
                display_name=str(getattr(entry, 'displayName', username)),
                email=str(getattr(entry, 'mail', '')),
                groups=groups,
                role=role,
                dn=user_dn,
            )

        except Exception as exc:
            logger.error("LDAP authentication error for %s: %s", username, exc)
            return None
        finally:
            self._release(conn)

    def is_available(self) -> bool:
        """
        Probe LDAP availability with a lightweight WhoAmI operation.
        Returns True only if the pool is up and a connection responds.
        """
        if not self.enabled or not self._pool_initialized:
            return False
        conn = None
        try:
            conn = self._acquire()
            conn.extend.standard.who_am_i()
            return True
        except Exception as exc:
            logger.debug("LDAP availability probe failed: %s", exc)
            return False
        finally:
            if conn is not None:
                self._release(conn)

    def disconnect(self) -> None:
        """Drain and close all pooled connections gracefully."""
        drained = 0
        while not self._pool.empty():
            try:
                conn = self._pool.get_nowait()
                conn.unbind()
                drained += 1
            except Exception:
                pass
        self._pool_initialized = False
        logger.info("LDAP pool closed (%d connections released)", drained)

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _resolve_role(self, groups: List[str]) -> str:
        """Map AD groups to bunyanx role. Returns 'viewer' if no match."""
        for group, role in self.role_mapping.items():
            if group in groups:
                return role
        return "viewer"

    def _extract_cn(self, dn: str) -> str:
        """Extract the CN value from a full Distinguished Name string."""
        for part in dn.split(','):
            if part.strip().upper().startswith('CN='):
                return part.strip()[3:]
        return dn
