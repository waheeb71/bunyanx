"""                                 
Enterprise bunyanx - HA State Synchronizer

Mirrors state (like new active connections, updated database rules)
from the MASTER node to the BACKUP node to ensure a seamless failover.
"""

import json
import asyncio
import logging
import os
import secrets
import threading
import time
import hmac
import hashlib
from typing import Any, Callable, Dict, List, Optional

_HA_SYNC_DEFAULT_SECRET_SENTINEL = "ngfw-ha-default-secret-change-me"

def _load_ha_secret() -> bytes:
    """
    Load the HA sync HMAC secret from the environment.
    
    Priority:
      1. NGFW_HA_SYNC_SECRET env variable (operator-set, required in production)
      2. Random per-process secret (safe fallback — prevents split-brain auth bypass)
    
    SECURITY: Never use the template default. If the env var is missing, a random
    secret is generated so two nodes cannot sync (forcing operator intervention),
    rather than silently accepting the known default.
    """
    _logger = logging.getLogger(__name__)
    secret = os.getenv("NGFW_HA_SYNC_SECRET", "")
    if secret and secret != _HA_SYNC_DEFAULT_SECRET_SENTINEL:
        return secret.encode("utf-8")
    
    # No valid secret configured — generate ephemeral random secret.
    # This prevents cross-node HMAC verification (intentional: forces configuration).
    random_secret = secrets.token_hex(32)
    _logger.critical(
        "[HA-SECURITY] 🚨 NGFW_HA_SYNC_SECRET is not set or uses the default template value! "
        "A random ephemeral secret has been generated. HA state synchronization between "
        "nodes WILL FAIL until you set NGFW_HA_SYNC_SECRET to a shared secret in .env. "
        "Run: python -c \"import secrets; print(secrets.token_hex(32))\" to generate one."
    )
    return random_secret.encode("utf-8")


class StateSynchronizer:
    """Synchronizes state data from MASTER to BACKUP nodes."""
    
    def __init__(self, port: int = 54322, peer_ip: str = "127.0.0.1", 
                 logger: Optional[logging.Logger] = None,
                 auth_secret: Optional[str] = None):
        self.port = port
        self.peer_ip = peer_ip
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        # Use provided secret or load from environment (never use the template default)
        if auth_secret and auth_secret != _HA_SYNC_DEFAULT_SECRET_SENTINEL:
            self.auth_secret = auth_secret.encode("utf-8")
        else:
            self.auth_secret = _load_ha_secret()
        
        self.is_master = False
        self._server: Optional[asyncio.AbstractServer] = None
        self._running = False
        
        # Callbacks to update local state when receiving data
        self.flow_tracker_update_cb = None
        self.vpn_session_update_cb = None
        
    def set_flow_callback(self, cb):
        self.flow_tracker_update_cb = cb

    def set_vpn_session_callback(self, cb):
        self.vpn_session_update_cb = cb

    async def start(self, initial_is_master: bool):
        """Start the synchronization service."""
        self._running = True
        self.is_master = initial_is_master
        
        if not self.is_master:
            # If we are backup, listen for state updates
            await self._start_listener()
            
        self.logger.info(f"✅ HA State Synchronizer started (Is Master: {self.is_master})")

    async def stop(self):
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        self.logger.info("🛑 HA State Synchronizer stopped")

    def on_state_change(self, is_master: bool):
        """Handle HA state change."""
        self.is_master = is_master
        if not self.is_master and not self._server:
            asyncio.create_task(self._start_listener())
        elif self.is_master and self._server:
            self._server.close()
            self._server = None

    async def _start_listener(self):
        """Listen for state updates from the MASTER."""
        try:
            self._server = await asyncio.start_server(
                self._handle_client, '0.0.0.0', self.port
            )
            self.logger.info(f"HA Sync Listener bound to 0.0.0.0:{self.port}")
        except Exception as e:
            self.logger.error(f"Failed to start HA Sync listener: {e}")

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming state data from MASTER using length-prefixed framing."""
        try:
            while self._running and not self.is_master:
                # Read 4-byte length header first
                raw_len = await reader.readexactly(4)
                if not raw_len:
                    break
                msg_len = int.from_bytes(raw_len, byteorder='big')

                # Guard against absurdly large payloads (>10 MB) to prevent memory exhaustion
                MAX_PAYLOAD = 10 * 1024 * 1024
                if msg_len > MAX_PAYLOAD:
                    self.logger.error(
                        f"[HA-Sync] Incoming payload too large ({msg_len} bytes > {MAX_PAYLOAD}). Closing connection."
                    )
                    break

                # Read exactly msg_len bytes — no truncation
                raw_data = await reader.readexactly(msg_len)
                if not raw_data:
                    break

                payload = json.loads(raw_data.decode('utf-8'))

                msg_data = payload.get('msg', {})
                signature = payload.get('signature', '')

                # 1. Verify Timestamp (Time Drift < 2.0s)
                now = time.time()
                if abs(now - msg_data.get('timestamp', 0)) > 2.0:
                    self.logger.warning("State Sync Rejected: Time drift too large (Replay Attack)")
                    break

                # 2. Verify Cryptographic Signature
                msg_bytes = json.dumps(msg_data, sort_keys=True).encode('utf-8')
                expected_sig = self._sign_payload(msg_bytes)
                if not hmac.compare_digest(expected_sig, signature):
                    self.logger.critical("🚨 State Sync Rejected: Invalid HMAC Signature (Injection Attack Blocked!)")
                    break

                # Apply synchronized state
                if msg_data.get('type') == 'flow_update' and self.flow_tracker_update_cb:
                    self.flow_tracker_update_cb(msg_data.get('data'))
                elif msg_data.get('type') == 'vpn_session_update' and self.vpn_session_update_cb:
                    self.vpn_session_update_cb(msg_data.get('action'), msg_data.get('data'))

        except asyncio.IncompleteReadError:
            self.logger.debug("HA Sync client disconnected (incomplete read)")
        except Exception as e:
            self.logger.debug(f"Error handling sync client: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    def _sign_payload(self, msg_bytes: bytes) -> str:
        return hmac.new(self.auth_secret, msg_bytes, hashlib.sha256).hexdigest()

    async def broadcast_flow_state(self, flow_data: Dict):
        """Called by MASTER to push flow changes to BACKUP using length-prefixed framing."""
        if not self.is_master or not self._running:
            return

        msg_data = {
            'type': 'flow_update',
            'data': flow_data,
            'timestamp': time.time()
        }
        msg_bytes = json.dumps(msg_data, sort_keys=True).encode('utf-8')

        final_payload = json.dumps({
            'msg': msg_data,
            'signature': self._sign_payload(msg_bytes)
        }).encode('utf-8')

        # Prepend 4-byte big-endian length header
        framed = len(final_payload).to_bytes(4, byteorder='big') + final_payload

        try:
            reader, writer = await asyncio.open_connection(self.peer_ip, self.port)
            writer.write(framed)
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            # It's expected to fail if peer is down or not ready
            pass

    async def broadcast_vpn_session(self, action: str, session_data: Dict):
        """Called by MASTER to push VPN session changes to BACKUP."""
        if not self.is_master or not self._running:
            return
            
        msg_data = {
            'type': 'vpn_session_update',
            'action': action,
            'data': session_data,
            'timestamp': time.time()
        }
        msg_bytes = json.dumps(msg_data, sort_keys=True).encode('utf-8')
        
        final_payload = json.dumps({
            'msg': msg_data,
            'signature': self._sign_payload(msg_bytes)
        }).encode('utf-8')
        
        try:
            reader, writer = await asyncio.open_connection(self.peer_ip, self.port)
            writer.write(final_payload)
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            pass


# ══════════════════════════════════════════════════════
# Phase 7C — etcd-backed StateSyncManager (Active-Active HA)
# ══════════════════════════════════════════════════════

_logger = logging.getLogger(__name__)


class StateSyncManager:
    """
    Distributed state store backed by etcd.
    Local cache-first reads; writes go to both local + etcd.
    Cluster-wide IP block, session, and rule override replication.
    Falls back to in-memory when ha.enabled=false or etcd3 unavailable.
    """

    _instance: Optional["StateSyncManager"] = None
    _cls_lock = threading.RLock()

    def __init__(self):
        from system.config.feature_flags import FeatureFlagManager
        self._flags = FeatureFlagManager.instance()
        self._local_store: Dict[str, Any] = {}
        self._store_lock = threading.RLock()
        self._client = None
        self._enabled = self._flags.current.ha.enabled

    @classmethod
    def instance(cls) -> "StateSyncManager":
        if cls._instance is None:
            with cls._cls_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    async def start(self) -> None:
        if not self._enabled:
            _logger.info("[StateSync] HA disabled — local-only state")
            return
        try:
            endpoints = list(self._flags.current.ha.etcd_endpoints)
            host, port_str = endpoints[0].split(":")
            import etcd3
            self._client = etcd3.client(host=host, port=int(port_str))
            _logger.info(f"[StateSync] Connected to etcd at {endpoints[0]} ✓")
        except ImportError:
            _logger.warning("[StateSync] etcd3 not installed — local-only state")
            self._enabled = False
        except Exception as exc:
            _logger.error(f"[StateSync] etcd connect failed: {exc}")
            self._enabled = False

    async def put(self, key: str, value: Any) -> None:
        with self._store_lock:
            self._local_store[key] = value
        if self._enabled and self._client:
            try:
                data = json.dumps(value)
                await asyncio.get_event_loop().run_in_executor(
                    None, lambda: self._client.put(key, data)
                )
            except Exception as exc:
                _logger.warning(f"[StateSync] etcd put failed: {exc}")

    async def get(self, key: str, default: Any = None) -> Any:
        with self._store_lock:
            if key in self._local_store:
                return self._local_store[key]
        if self._enabled and self._client:
            try:
                value, _ = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: self._client.get(key)
                )
                if value:
                    parsed = json.loads(value.decode())
                    with self._store_lock:
                        self._local_store[key] = parsed
                    return parsed
            except Exception:
                pass
        return default

    async def sync_blocked_ip(self, ip: str, reason: str, duration_s: int = 3600) -> None:
        await self.put(f"blocked:{ip}", {
            "ip": ip, "reason": reason,
            "expires_at": time.time() + duration_s,
        })

    async def is_ip_blocked_cluster(self, ip: str) -> bool:
        data = await self.get(f"blocked:{ip}")
        if not data:
            return False
        return data.get("expires_at", 0) > time.time()

    def get_stats(self) -> dict:
        with self._store_lock:
            return {
                "ha_enabled":     self._enabled,
                "local_keys":     len(self._local_store),
                "etcd_connected": self._client is not None,
            }
