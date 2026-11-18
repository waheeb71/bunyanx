"""
RADIUS Accounting Listener — BunyanX NGFW
==========================================
Listens for RADIUS Accounting-Start / Accounting-Stop packets (UDP 1813) and
immediately updates the IdentityCache with the IP → username binding.

This gives *real-time* identity resolution:
  - Accounting-Start  → cache.set(ip, username)     (user just logged in)
  - Accounting-Stop   → cache.invalidate(ip)         (user just logged out)
  - Accounting-Interim→ cache.set(ip, username, ttl) (refresh — session alive)

Supports:
  - Multiple NAS clients (each with its own shared secret)
  - Default shared secret for unlisted NAS
  - Attribute parsing: Framed-IP-Address, User-Name, NAS-Identifier,
    Acct-Status-Type, Session-Timeout, Class (for department/group)
  - Authenticator validation (MD5 HMAC) — rejects spoofed packets
  - Async event publishing to EventBus

Configuration block (identity_correlation.yaml → radius_accounting):
    enabled:         true
    listen_ip:       "0.0.0.0"
    port:            1813
    default_secret:  "${NGFW_RADIUS_SECRET}"
    nas_clients:
      - ip: "10.0.0.100"             # NPS / FreeRADIUS server
        secret: "${NAS_100_SECRET}"
      - ip: "10.0.0.101"
        secret: "${NAS_101_SECRET}"
    ttl_seconds:     1800            # cache TTL per session (default 30 min)
    interim_ttl_s:   3600            # TTL for interim-update entries
    max_packet_size: 4096
    role_class_map:                  # RADIUS Class attr → NGFW role (optional)
      "Finance": "user"
      "IT-Admins": "operator"
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import socket
import struct
import threading
from typing import Dict, Optional, Tuple

from .identity_cache import IdentityCache, get_identity_cache

logger = logging.getLogger(__name__)

# ─── RADIUS attribute codes we care about ────────────────────────────────────
_ATTR_USER_NAME             = 1
_ATTR_FRAMED_IP             = 8
_ATTR_FRAMED_IP_NETMASK     = 9
_ATTR_CLASS                 = 25
_ATTR_SESSION_TIMEOUT       = 27
_ATTR_CALLING_STATION_ID    = 31   # MAC address of device
_ATTR_NAS_IDENTIFIER        = 32
_ATTR_ACCT_STATUS_TYPE      = 40
_ATTR_ACCT_INPUT_OCTETS     = 42
_ATTR_ACCT_OUTPUT_OCTETS    = 43
_ATTR_ACCT_SESSION_ID       = 44

# Acct-Status-Type values
_STATUS_START     = 1
_STATUS_STOP      = 2
_STATUS_INTERIM   = 3
_STATUS_ON        = 7    # NAS came online
_STATUS_OFF       = 8    # NAS went offline


class RADIUSAccountingListener:
    """
    UDP server listening for RADIUS Accounting packets on port 1813.

    Usage
    -----
        cfg = load_yaml("identity_correlation.yaml")
        listener = RADIUSAccountingListener(cfg)
        listener.start()     # non-blocking — starts daemon thread
        ...
        listener.stop()

    Or via singleton:
        RADIUSAccountingListener.configure_and_start(cfg)
    """

    _singleton: Optional["RADIUSAccountingListener"] = None
    _singleton_lock = threading.Lock()

    def __init__(self, cfg: dict, cache: Optional[IdentityCache] = None):
        rad_cfg = cfg.get("radius_accounting", {})

        self.enabled        = rad_cfg.get("enabled", False)
        self.listen_ip      = rad_cfg.get("listen_ip", "0.0.0.0")
        self.port           = int(rad_cfg.get("port", 1813))
        self.default_secret = self._resolve_env(rad_cfg.get("default_secret", ""))
        self.ttl            = int(rad_cfg.get("ttl_seconds",    1800))
        self.interim_ttl    = int(rad_cfg.get("interim_ttl_s",  3600))
        self.max_pkt        = int(rad_cfg.get("max_packet_size", 4096))
        self.role_class_map: Dict[str, str] = rad_cfg.get("role_class_map", {})

        # NAS client secrets: { nas_ip → shared_secret }
        self._nas_secrets: Dict[str, str] = {}
        for nas in rad_cfg.get("nas_clients", []):
            ip  = nas.get("ip", "")
            sec = self._resolve_env(nas.get("secret", ""))
            if ip and sec:
                self._nas_secrets[ip] = sec

        self._cache      = cache or get_identity_cache()
        self._sock: Optional[socket.socket] = None
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        # Stats
        self._pkt_received = 0
        self._pkt_auth_fail = 0
        self._bindings_set  = 0
        self._bindings_del  = 0

    # ── Public lifecycle ──────────────────────────────────────────────────────

    def start(self) -> None:
        if not self.enabled:
            logger.info("[RADIUS-Acct] Disabled in config — not starting")
            return
        if self._thread and self._thread.is_alive():
            return
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.settimeout(1.0)   # allows clean shutdown
            self._sock.bind((self.listen_ip, self.port))
            logger.info("[RADIUS-Acct] Listening on %s:%d", self.listen_ip, self.port)
        except OSError as exc:
            logger.error("[RADIUS-Acct] ❌ Bind failed: %s", exc)
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._recv_loop,
            name="radius-accounting",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=3)
        logger.info("[RADIUS-Acct] Stopped")

    def status(self) -> dict:
        return {
            "enabled":         self.enabled,
            "listen":          f"{self.listen_ip}:{self.port}",
            "pkt_received":    self._pkt_received,
            "pkt_auth_fail":   self._pkt_auth_fail,
            "bindings_set":    self._bindings_set,
            "bindings_deleted":self._bindings_del,
            "thread_alive":    bool(self._thread and self._thread.is_alive()),
        }

    # ── Receive loop ──────────────────────────────────────────────────────────

    def _recv_loop(self) -> None:
        logger.info("[RADIUS-Acct] Receive loop started")
        while not self._stop_event.is_set():
            try:
                data, addr = self._sock.recvfrom(self.max_pkt)
            except socket.timeout:
                continue
            except OSError:
                break
            self._pkt_received += 1
            try:
                self._handle_packet(data, addr)
            except Exception as exc:
                logger.debug("[RADIUS-Acct] Packet parse error from %s: %s", addr, exc)
        logger.info("[RADIUS-Acct] Receive loop exited")

    def _handle_packet(self, data: bytes, addr: Tuple[str, int]) -> None:
        nas_ip = addr[0]
        if len(data) < 20:
            return

        # ── RADIUS packet structure ───────────────────────────────────────────
        code, pkt_id, length = struct.unpack("!BBH", data[:4])
        authenticator        = data[4:20]

        # Code 4 = Accounting-Request
        if code != 4:
            return

        # ── Authenticator validation ──────────────────────────────────────────
        secret = self._nas_secrets.get(nas_ip, self.default_secret)
        if secret and not self._verify_authenticator(data, secret, authenticator):
            self._pkt_auth_fail += 1
            logger.warning("[RADIUS-Acct] ⚠️ Auth validation failed from %s — dropping", nas_ip)
            return

        # ── Parse attributes ──────────────────────────────────────────────────
        attrs = self._parse_attributes(data[20:length])

        status_type = attrs.get(_ATTR_ACCT_STATUS_TYPE)
        if status_type is None:
            return

        username  = attrs.get(_ATTR_USER_NAME, "")
        framed_ip = attrs.get(_ATTR_FRAMED_IP, "")

        if not username or not framed_ip:
            return

        # ── Handle event type ─────────────────────────────────────────────────
        if status_type in (_STATUS_START, _STATUS_ON):
            self._on_login(nas_ip, framed_ip, username, attrs)

        elif status_type == _STATUS_INTERIM:
            self._on_interim(nas_ip, framed_ip, username, attrs)

        elif status_type in (_STATUS_STOP, _STATUS_OFF):
            self._on_logout(nas_ip, framed_ip, username)

    def _on_login(
        self, nas_ip: str, ip: str, username: str, attrs: dict
    ) -> None:
        class_val  = attrs.get(_ATTR_CLASS, "")
        role       = self.role_class_map.get(class_val, "user")
        session_to = attrs.get(_ATTR_SESSION_TIMEOUT, self.ttl)
        mac        = attrs.get(_ATTR_CALLING_STATION_ID, "")
        nas_id     = attrs.get(_ATTR_NAS_IDENTIFIER, nas_ip)

        self._cache.set(
            ip,
            username,
            role       = role,
            department = class_val,
            source     = f"radius:{nas_id}",
            ttl        = min(int(session_to), self.ttl),
        )
        self._bindings_set += 1
        logger.info(
            "[RADIUS-Acct] LOGIN  %s → %s (NAS=%s MAC=%s)",
            ip, username, nas_id, mac,
        )
        self._publish("identity.user_login", {
            "ip": ip, "username": username, "nas": nas_id, "mac": mac,
        })

    def _on_interim(
        self, nas_ip: str, ip: str, username: str, attrs: dict
    ) -> None:
        """Session still active — refresh TTL."""
        class_val = attrs.get(_ATTR_CLASS, "")
        role      = self.role_class_map.get(class_val, "user")
        self._cache.set(
            ip, username,
            role=role, department=class_val,
            source=f"radius:{nas_ip}", ttl=self.interim_ttl,
        )
        self._bindings_set += 1
        logger.debug("[RADIUS-Acct] INTERIM %s → %s", ip, username)

    def _on_logout(self, nas_ip: str, ip: str, username: str) -> None:
        self._cache.invalidate(ip)
        self._bindings_del += 1
        logger.info("[RADIUS-Acct] LOGOUT  %s (was %s, NAS=%s)", ip, username, nas_ip)
        self._publish("identity.user_logout", {
            "ip": ip, "username": username, "nas": nas_ip,
        })

    # ── Packet parsing helpers ────────────────────────────────────────────────

    @staticmethod
    def _parse_attributes(data: bytes) -> dict:
        """Parse RADIUS attribute-value pairs into a dict."""
        attrs: dict = {}
        idx = 0
        while idx < len(data) - 1:
            attr_type = data[idx]
            attr_len  = data[idx + 1]
            if attr_len < 2 or idx + attr_len > len(data):
                break
            value = data[idx + 2: idx + attr_len]

            if attr_type == _ATTR_FRAMED_IP and len(value) == 4:
                attrs[attr_type] = ".".join(str(b) for b in value)
            elif attr_type == _ATTR_ACCT_STATUS_TYPE and len(value) == 4:
                attrs[attr_type] = struct.unpack("!I", value)[0]
            elif attr_type == _ATTR_SESSION_TIMEOUT and len(value) == 4:
                attrs[attr_type] = struct.unpack("!I", value)[0]
            elif attr_type in (
                _ATTR_USER_NAME, _ATTR_NAS_IDENTIFIER,
                _ATTR_CLASS, _ATTR_CALLING_STATION_ID, _ATTR_ACCT_SESSION_ID,
            ):
                attrs[attr_type] = value.decode("utf-8", errors="replace")
            else:
                attrs[attr_type] = value

            idx += attr_len

        return attrs

    @staticmethod
    def _verify_authenticator(pkt: bytes, secret: str, authenticator: bytes) -> bool:
        """
        Validate the RADIUS Authenticator field (RFC 2866 §3).
        For Accounting-Request, the authenticator is:
            MD5(Code + ID + Length + 16-zero-bytes + Attributes + Secret)
        """
        zeroed = pkt[:4] + b"\x00" * 16 + pkt[20:]
        expected = hashlib.md5(zeroed + secret.encode()).digest()
        return hmac.compare_digest(expected, authenticator)

    @staticmethod
    def _resolve_env(value: str) -> str:
        if value.startswith("${") and value.endswith("}"):
            return os.environ.get(value[2:-1], "")
        return value

    @staticmethod
    def _publish(topic: str, payload: dict) -> None:
        try:
            from system.events.bus import EventBus
            EventBus.publish_from_thread(topic, payload)
        except Exception:
            pass

    # ── Singleton helpers ─────────────────────────────────────────────────────

    @classmethod
    def configure_and_start(
        cls,
        cfg: dict,
        cache: Optional[IdentityCache] = None,
    ) -> "RADIUSAccountingListener":
        with cls._singleton_lock:
            if cls._singleton is not None:
                cls._singleton.stop()
            cls._singleton = cls(cfg, cache=cache)
            cls._singleton.start()
        return cls._singleton

    @classmethod
    def get(cls) -> Optional["RADIUSAccountingListener"]:
        return cls._singleton
