"""
LDAP / Active Directory User Sync — BunyanX NGFW
==================================================
Background daemon thread that periodically queries an LDAP/AD directory to
build the IP → username mapping used by IdentityManager.

Supports:
  - Windows Active Directory (sAMAccountName, msRADIUSFramedIPAddress, etc.)
  - OpenLDAP   (uid, ipHostNumber, radiusFramedIPAddress)
  - Auto-detect server type or explicit override via config
  - Read-only service account (never needs write privileges)
  - TLS/LDAPS only (plain LDAP refused)
  - Graceful reconnect on failure (exponential back-off)
  - Configurable sync interval (default 5 min)
  - Publishes EventBus notification after each sync

Configuration block (identity_correlation.yaml → ldap_sync):
    enabled:              true
    server:               "ldaps://dc01.company.com:636"
    fallback_servers:     ["ldaps://dc02.company.com:636"]
    base_dn:              "dc=company,dc=com"
    bind_dn:              "cn=ngfw-reader,ou=service-accounts,dc=company,dc=com"
    bind_password:        "${NGFW_LDAP_BIND_PASSWORD}"
    server_type:          "auto"          # auto | ad | openldap
    interval_seconds:     300
    page_size:            500
    timeout_seconds:      15
    tls_verify:           true
    ip_attributes:                        # which attributes hold the IP
      - "msRADIUSFramedIPAddress"         # AD
      - "radiusFramedIPAddress"           # OpenLDAP
      - "ipHostNumber"                    # generic posixAccount
    username_attribute:   "auto"          # auto → sAMAccountName (AD) / uid (LDAP)
    group_attribute:      "memberOf"
    department_attribute: "department"
    filter:               ""              # extra search filter (optional)
    ttl_seconds:          900             # cache TTL per entry (default 15 min)
    role_mapping:                         # AD group → NGFW role
      "bunyanx-admins":   "admin"
      "Domain Admins":    "admin"
      "bunyanx-operators":"operator"
      "bunyanx-viewers":  "viewer"
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional

from .identity_cache import IdentityCache, UserEntry, get_identity_cache

logger = logging.getLogger(__name__)

# ─── Back-off constants ───────────────────────────────────────────────────────
_BACKOFF_BASE  = 5    # seconds — first retry delay
_BACKOFF_MAX   = 300  # seconds — cap at 5 minutes
_BACKOFF_MULT  = 2    # exponential multiplier


class LDAPUserSync:
    """
    Periodic LDAP/AD → IdentityCache synchroniser.

    Usage
    -----
        cfg = load_yaml("identity_correlation.yaml")
        sync = LDAPUserSync(cfg)
        sync.start()
        ...
        sync.stop()   # graceful shutdown

    Or via the module-level singleton:
        LDAPUserSync.configure_and_start(cfg)
    """

    _singleton: Optional["LDAPUserSync"] = None
    _singleton_lock = threading.Lock()

    # ── Init ──────────────────────────────────────────────────────────────────

    def __init__(self, cfg: dict, cache: Optional[IdentityCache] = None):
        ldap_cfg = cfg.get("ldap_sync", {})

        self.enabled            = ldap_cfg.get("enabled", False)
        self.servers: List[str] = self._build_server_list(ldap_cfg)
        self.base_dn            = ldap_cfg.get("base_dn", "")
        self.bind_dn            = ldap_cfg.get("bind_dn", "")
        self.bind_password      = self._resolve_password(ldap_cfg)
        self.server_type        = ldap_cfg.get("server_type", "auto").lower()
        self.interval           = int(ldap_cfg.get("interval_seconds", 300))
        self.page_size          = int(ldap_cfg.get("page_size", 500))
        self.timeout            = int(ldap_cfg.get("timeout_seconds", 15))
        self.tls_verify         = bool(ldap_cfg.get("tls_verify", True))
        self.ip_attributes      = ldap_cfg.get("ip_attributes", [
            "msRADIUSFramedIPAddress",  # AD
            "radiusFramedIPAddress",    # OpenLDAP + FreeRADIUS
            "ipHostNumber",             # posixAccount / generic
        ])
        self._username_attr_cfg = ldap_cfg.get("username_attribute", "auto")
        self.group_attr         = ldap_cfg.get("group_attribute", "memberOf")
        self.dept_attr          = ldap_cfg.get("department_attribute", "department")
        self.extra_filter       = ldap_cfg.get("filter", "")
        self.entry_ttl          = int(ldap_cfg.get("ttl_seconds", 900))
        self.role_mapping: Dict[str, str] = ldap_cfg.get("role_mapping", {
            "bunyanx-admins":    "admin",
            "Domain Admins":     "admin",
            "bunyanx-operators": "operator",
            "bunyanx-viewers":   "viewer",
        })

        self._cache         = cache or get_identity_cache()
        self._stop_event    = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_sync_at  = 0.0
        self._last_error    = ""
        self._sync_count    = 0
        self._backoff       = _BACKOFF_BASE
        self._detected_type = None  # filled on first connect

    # ── Server type detection ─────────────────────────────────────────────────

    @property
    def username_attribute(self) -> str:
        """Return the right username attribute for the detected server type."""
        if self._username_attr_cfg != "auto":
            return self._username_attr_cfg
        if self._detected_type == "ad":
            return "sAMAccountName"
        if self._detected_type == "openldap":
            return "uid"
        return "sAMAccountName"   # safe default until we detect

    def _detect_server_type(self, conn) -> str:
        """Probe the DSE to decide if we're talking to AD or OpenLDAP."""
        if self.server_type != "auto":
            return self.server_type
        try:
            import ldap3
            conn.search(
                search_base="",
                search_filter="(objectClass=*)",
                search_scope=ldap3.BASE,
                attributes=["defaultNamingContext", "vendorName"],
            )
            if conn.entries:
                entry = conn.entries[0]
                if hasattr(entry, "defaultNamingContext"):
                    logger.info("[LDAPSync] Detected: Windows Active Directory")
                    return "ad"
                if hasattr(entry, "vendorName") and "openldap" in str(entry.vendorName).lower():
                    logger.info("[LDAPSync] Detected: OpenLDAP")
                    return "openldap"
        except Exception as exc:
            logger.debug("[LDAPSync] Type detection failed: %s", exc)
        logger.info("[LDAPSync] Defaulting to AD-style attributes")
        return "ad"

    # ── Connection helpers ────────────────────────────────────────────────────

    def _connect(self) -> Any:
        """Try servers in order and return a bound ldap3 connection."""
        import ldap3

        tls_cfg = ldap3.Tls(validate=2 if self.tls_verify else 0)

        last_exc = None
        for server_uri in self.servers:
            try:
                server = ldap3.Server(
                    server_uri,
                    get_info=ldap3.ALL,
                    use_ssl=server_uri.lower().startswith("ldaps"),
                    tls=tls_cfg,
                    connect_timeout=self.timeout,
                )
                conn = ldap3.Connection(
                    server,
                    user=self.bind_dn,
                    password=self.bind_password,
                    auto_bind=True,
                    receive_timeout=self.timeout,
                    authentication=ldap3.SIMPLE,
                )
                logger.info("[LDAPSync] Connected to %s", server_uri)
                return conn
            except Exception as exc:
                last_exc = exc
                logger.warning("[LDAPSync] Failed to connect to %s: %s", server_uri, exc)

        raise ConnectionError(
            f"All LDAP servers unavailable. Last error: {last_exc}"
        )

    # ── Search / Parse ────────────────────────────────────────────────────────

    def _build_search_filter(self) -> str:
        """
        Build the LDAP search filter to find all users with IP attributes.
        """
        ip_attr_filter = "".join(f"({a}=*)" for a in self.ip_attributes)
        user_filter = (
            "(objectClass=user)"        # AD
            if self._detected_type == "ad"
            else "(objectClass=inetOrgPerson)"  # OpenLDAP
        )
        base = f"(&{user_filter}(|{ip_attr_filter}))"
        if self.extra_filter:
            base = f"(&{base}{self.extra_filter})"
        return base

    def _extract_groups(self, entry) -> List[str]:
        """Extract CN names from memberOf DNs."""
        raw = []
        if hasattr(entry, self.group_attr):
            raw = getattr(entry, self.group_attr).values or []
        return [self._cn_from_dn(g) for g in raw]

    @staticmethod
    def _cn_from_dn(dn: str) -> str:
        for part in dn.split(","):
            if part.strip().upper().startswith("CN="):
                return part.strip()[3:]
        return dn

    def _resolve_role(self, groups: List[str]) -> str:
        for group, role in self.role_mapping.items():
            if group in groups:
                return role
        return "user"

    # ── Core sync logic ───────────────────────────────────────────────────────

    def _do_sync(self) -> int:
        """
        Run one full LDAP sync.
        Returns number of IP→user bindings written to cache.
        """
        import ldap3

        conn = self._connect()
        self._detected_type = self._detect_server_type(conn)

        attrs = list({
            self.username_attribute,
            self.group_attr,
            self.dept_attr,
            "displayName", "mail",
            *self.ip_attributes,
        })
        search_filter = self._build_search_filter()

        entries_written = 0

        # Paged search — handles large directories (100k+ users)
        cookie = None
        while True:
            controls = []
            if self.page_size > 0:
                # Simple Paged Results control
                controls = [ldap3.PAGED_RESULT_CONTROL_OID]
                conn.extend.standard.paged_search(
                    search_base=self.base_dn,
                    search_filter=search_filter,
                    search_scope=ldap3.SUBTREE,
                    attributes=attrs,
                    paged_size=self.page_size,
                    generator=True,    # memory-efficient iterator
                )
            else:
                conn.search(
                    search_base=self.base_dn,
                    search_filter=search_filter,
                    search_scope=ldap3.SUBTREE,
                    attributes=attrs,
                )

            batch: Dict[str, UserEntry] = {}

            entries_iter = conn.entries if self.page_size == 0 else conn.response

            for entry in entries_iter:
                # Skip referrals and searchResRef entries
                if not hasattr(entry, "entry_dn") and not isinstance(entry, dict):
                    continue
                # In paged mode, entries come as dicts
                if isinstance(entry, dict):
                    if entry.get("type") != "searchResEntry":
                        continue
                    attrs_raw = entry.get("attributes", {})
                    username  = str(attrs_raw.get(self.username_attribute, "")).strip()
                    ips_raw   = [str(attrs_raw.get(a, "")) for a in self.ip_attributes
                                 if attrs_raw.get(a)]
                    name      = str(attrs_raw.get("displayName", username))
                    email     = str(attrs_raw.get("mail", ""))
                    dept      = str(attrs_raw.get(self.dept_attr, ""))
                    groups    = []
                    if isinstance(attrs_raw.get(self.group_attr), list):
                        groups = [self._cn_from_dn(g)
                                  for g in attrs_raw.get(self.group_attr, [])]
                else:
                    username = str(getattr(entry, self.username_attribute, "")).strip()
                    ips_raw  = [
                        str(getattr(entry, a, ""))
                        for a in self.ip_attributes
                        if hasattr(entry, a) and str(getattr(entry, a, ""))
                    ]
                    name     = str(getattr(entry, "displayName", username))
                    email    = str(getattr(entry, "mail", ""))
                    dept     = str(getattr(entry, self.dept_attr, ""))
                    groups   = self._extract_groups(entry)

                if not username:
                    continue

                role = self._resolve_role(groups)

                for raw_ip in ips_raw:
                    ip = raw_ip.strip()
                    if not ip or ip == "None":
                        continue
                    # Handle RADIUS packed IP format (octet string → dotted)
                    if "." not in ip and len(ip) == 4:
                        ip = ".".join(str(b) for b in ip.encode("latin1"))

                    batch[ip] = UserEntry(
                        username     = username,
                        display_name = name,
                        email        = email,
                        groups       = groups,
                        role         = role,
                        department   = dept,
                        source       = "ldap_sync",
                        src_ip       = ip,
                        expires_at   = time.time() + self.entry_ttl if self.entry_ttl > 0 else 0,
                    )
                    entries_written += 1

            if batch:
                self._cache.bulk_set(batch)

            # For non-paged or when paged returns all at once, break
            break

        conn.unbind()
        return entries_written

    # ── Thread lifecycle ──────────────────────────────────────────────────────

    def _run_loop(self) -> None:
        """Main sync loop — runs as a daemon thread."""
        logger.info(
            "[LDAPSync] Daemon started (interval=%ds servers=%s)",
            self.interval, self.servers,
        )
        while not self._stop_event.is_set():
            try:
                t0     = time.monotonic()
                count  = self._do_sync()
                elapsed = time.monotonic() - t0
                self._last_sync_at = time.time()
                self._last_error   = ""
                self._sync_count  += 1
                self._backoff      = _BACKOFF_BASE   # reset on success
                logger.info(
                    "[LDAPSync] ✅ Sync #%d completed: %d bindings in %.1fs",
                    self._sync_count, count, elapsed,
                )
                # Publish event for monitoring
                try:
                    from system.events.bus import EventBus
                    EventBus.publish_from_thread("identity.ldap_sync_completed", {
                        "sync_count": self._sync_count,
                        "bindings":   count,
                        "elapsed_s":  round(elapsed, 2),
                    })
                except Exception:
                    pass

            except ImportError:
                logger.error("[LDAPSync] ldap3 not installed. Run: pip install ldap3")
                self._stop_event.wait(timeout=self.interval)
                continue
            except Exception as exc:
                self._last_error = str(exc)
                logger.error("[LDAPSync] ❌ Sync failed: %s (retry in %ds)", exc, self._backoff)
                self._stop_event.wait(timeout=self._backoff)
                self._backoff = min(self._backoff * _BACKOFF_MULT, _BACKOFF_MAX)
                continue

            self._stop_event.wait(timeout=self.interval)

        logger.info("[LDAPSync] Daemon stopped")

    def start(self) -> None:
        """Start the background sync thread (idempotent)."""
        if not self.enabled:
            logger.info("[LDAPSync] Disabled in config — not starting")
            return
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="ldap-user-sync",
            daemon=True,
        )
        self._thread.start()
        logger.info("[LDAPSync] Thread started")

    def stop(self) -> None:
        """Signal the thread to stop and wait for it to exit."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("[LDAPSync] Stopped")

    def force_sync(self) -> int:
        """Trigger an immediate (blocking) sync. Returns entries written."""
        if not self.enabled:
            return 0
        try:
            count = self._do_sync()
            self._last_sync_at = time.time()
            logger.info("[LDAPSync] Force sync: %d bindings written", count)
            return count
        except Exception as exc:
            logger.error("[LDAPSync] Force sync failed: %s", exc)
            return 0

    def status(self) -> dict:
        return {
            "enabled":       self.enabled,
            "servers":       self.servers,
            "server_type":   self._detected_type or self.server_type,
            "interval_s":    self.interval,
            "sync_count":    self._sync_count,
            "last_sync_at":  self._last_sync_at,
            "last_error":    self._last_error,
            "thread_alive":  bool(self._thread and self._thread.is_alive()),
        }

    # ── Singleton helpers ─────────────────────────────────────────────────────

    @classmethod
    def configure_and_start(
        cls,
        cfg: dict,
        cache: Optional[IdentityCache] = None,
    ) -> "LDAPUserSync":
        with cls._singleton_lock:
            if cls._singleton is not None:
                cls._singleton.stop()
            cls._singleton = cls(cfg, cache=cache)
            cls._singleton.start()
        return cls._singleton

    @classmethod
    def get(cls) -> Optional["LDAPUserSync"]:
        return cls._singleton

    # ── Internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _build_server_list(cfg: dict) -> List[str]:
        primary   = cfg.get("server", "")
        fallbacks = cfg.get("fallback_servers", [])
        servers   = [s for s in ([primary] + fallbacks) if s]
        if not servers:
            logger.warning("[LDAPSync] No servers configured")
        return servers

    @staticmethod
    def _resolve_password(cfg: dict) -> str:
        raw = cfg.get("bind_password", "")
        if raw.startswith("${") and raw.endswith("}"):
            env_key = raw[2:-1]
            value   = os.environ.get(env_key, "")
            if not value:
                logger.warning(
                    "[LDAPSync] Env var %s not set — LDAP bind may fail", env_key
                )
            return value
        if raw:
            logger.warning(
                "[LDAPSync] ⚠️  bind_password set as literal in config. "
                "Use ${ENV_VAR} syntax instead."
            )
        return raw
