"""
Enterprise bunyanx - VPN Portal Manager
==========================================
Tracks active WireGuard VPN sessions, enforces per-user access policies,
and provides session lifecycle management (create / heartbeat / terminate).

This is an in-memory session tracker. For HA deployments, sessions should
be mirrored via system.ha.state_sync.

Security hardening (v2):
  - Session TTL with automatic expiry (default 24 hours).
  - O(1) public key → session lookup via secondary index.
  - Stale _user_map cleanup in summary().
"""

import logging
import uuid
from dataclasses import dataclass, field
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable

from system.events.bus import EventBus
from system.events.topics import Topics

logger = logging.getLogger(__name__)

# Default session TTL: 24 hours
_DEFAULT_SESSION_TTL_SECONDS = 86400


# ── Domain Objects ────────────────────────────────────────────────────────────

@dataclass
class VPNSession:
    """Represents one active WireGuard peer session."""
    session_id: str
    username: str
    peer_public_key: str
    allowed_ips: List[str]
    connected_at: datetime = field(default_factory=datetime.utcnow)
    last_seen: Optional[datetime] = None
    bytes_rx: int = 0
    bytes_tx: int = 0
    # Peer endpoint (IP:PORT) — populated if known at connect time
    endpoint: Optional[str] = None
    # Session TTL in seconds (set by portal on creation)
    ttl_seconds: int = _DEFAULT_SESSION_TTL_SECONDS

    @property
    def duration_seconds(self) -> float:
        """Seconds since session was created."""
        return (datetime.utcnow() - self.connected_at).total_seconds()

    @property
    def is_expired(self) -> bool:
        """Check if session has exceeded its TTL."""
        return self.duration_seconds > self.ttl_seconds

    @property
    def expires_at(self) -> datetime:
        """Absolute expiry time."""
        return self.connected_at + timedelta(seconds=self.ttl_seconds)

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "username": self.username,
            "peer_public_key": self.peer_public_key,
            "allowed_ips": self.allowed_ips,
            "endpoint": self.endpoint,
            "connected_at": self.connected_at.isoformat(),
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "expires_at": self.expires_at.isoformat(),
            "duration_seconds": round(self.duration_seconds, 1),
            "bytes_rx": self.bytes_rx,
            "bytes_tx": self.bytes_tx,
        }


# ── Portal Manager ────────────────────────────────────────────────────────────

class VPNPortal:
    """
    VPN Portal Manager.

    Responsibilities:
      - Session registry: track who is connected, when, from where.
      - One-session-per-user enforcement (configurable).
      - Heartbeat / traffic counter updates.
      - Session termination (admin-initiated or peer disconnect).
      - Automatic session expiry (TTL-based).

    Thread-safety: This implementation is single-threaded / asyncio-safe
    (no shared mutation from multiple threads). Wrap with asyncio.Lock if
    moved to a multi-threaded executor.
    """

    def __init__(
        self,
        allow_multi_session: bool = False,
        session_ttl_seconds: int = _DEFAULT_SESSION_TTL_SECONDS,
        event_callback: Optional[Callable[[str, dict], None]] = None,
    ):
        """
        Args:
            allow_multi_session: If False (default), a new session for a user
                                 automatically terminates their previous one.
            session_ttl_seconds: Maximum session duration in seconds (default 24h).
            event_callback:     Optional callback(event_type, details) for AI
                                pipeline integration.
        """
        self._sessions: Dict[str, VPNSession] = {}      # session_id → Session
        self._user_map: Dict[str, List[str]] = {}        # username  → [session_ids]
        self._pubkey_index: Dict[str, str] = {}          # peer_public_key → session_id
        self.allow_multi_session = allow_multi_session
        self.session_ttl_seconds = session_ttl_seconds
        self._event_callback = event_callback

    # ── Session Lifecycle ─────────────────────────────────────────────────────

    def create_session(
        self,
        username: str,
        peer_public_key: str,
        allowed_ips: List[str],
        endpoint: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> VPNSession:
        """
        Register a new active VPN session for a user.

        If allow_multi_session is False, any existing session for this user
        is terminated first.

        Returns:
            The newly created VPNSession.
        """
        # Clean up expired sessions first
        self.cleanup_expired()

        if not self.allow_multi_session:
            for old_sid in list(self._user_map.get(username, [])):
                self._remove_session(old_sid, reason="replaced by new session")

        session_id = session_id or str(uuid.uuid4())
        session = VPNSession(
            session_id=session_id,
            username=username,
            peer_public_key=peer_public_key,
            allowed_ips=allowed_ips,
            endpoint=endpoint,
            ttl_seconds=self.session_ttl_seconds,
        )

        self._sessions[session_id] = session
        self._user_map.setdefault(username, []).append(session_id)
        self._pubkey_index[peer_public_key] = session_id

        logger.info(
            "VPN Portal: Session created — user='%s' id=%s… peer=%s…",
            username, session_id[:8], peer_public_key[:8],
        )

        # Extract the first assigned IP for identity binding
        # allowed_ips is a list like ["10.8.0.5/32", "10.8.0.0/24"]
        # We want the host IP (the /32 entry, or the first entry stripped of prefix)
        assigned_ip = ""
        for ip_cidr in allowed_ips:
            ip_part = ip_cidr.split("/")[0]
            mask    = ip_cidr.split("/")[1] if "/" in ip_cidr else "32"
            if mask == "32":           # single host — this is the client's VPN IP
                assigned_ip = ip_part
                break
        if not assigned_ip and allowed_ips:
            assigned_ip = allowed_ips[0].split("/")[0]   # fallback

        self._fire_event("vpn.session.created", {
            "session_id":            session_id,
            "username":              username,
            "assigned_ip":           assigned_ip,
            "peer_public_key_prefix": peer_public_key[:8],
            "peer_public_key":       peer_public_key,
            "allowed_ips":           allowed_ips,
            "endpoint":              endpoint,
        })

        return session

    def terminate_session(self, session_id: str) -> bool:
        """
        Terminate a session by ID.

        Returns:
            True if the session existed and was removed, False otherwise.
        """
        return self._remove_session(session_id, reason="admin / explicit termination")

    def terminate_user_sessions(self, username: str) -> int:
        """
        Terminate all active sessions for a user.

        Returns:
            Number of sessions terminated.
        """
        session_ids = list(self._user_map.get(username, []))
        count = 0
        for sid in session_ids:
            if self._remove_session(sid, reason="all sessions for '%s' revoked" % username):
                count += 1
        return count

    # ── Session Queries ───────────────────────────────────────────────────────

    def get_session(self, session_id: str) -> Optional[VPNSession]:
        """Retrieve a session by its ID. Auto-removes if expired."""
        session = self._sessions.get(session_id)
        if session and session.is_expired:
            self._remove_session(session_id, reason="TTL expired")
            return None
        return session

    def get_session_by_pubkey(self, peer_public_key: str) -> Optional[VPNSession]:
        """Find a session by the peer's WireGuard public key (O(1) lookup)."""
        session_id = self._pubkey_index.get(peer_public_key)
        if session_id is None:
            return None
        return self.get_session(session_id)

    def get_user_sessions(self, username: str) -> List[VPNSession]:
        """Return all active sessions for a user."""
        sids = self._user_map.get(username, [])
        return [self._sessions[sid] for sid in sids if sid in self._sessions]

    def list_sessions(self) -> List[dict]:
        """Return all active sessions serialized as dicts."""
        # Cleanup expired before listing
        self.cleanup_expired()
        return [s.to_dict() for s in self._sessions.values()]

    def active_count(self) -> int:
        """Total number of active sessions."""
        return len(self._sessions)

    # ── Heartbeat & Traffic Counters ──────────────────────────────────────────

    def update_heartbeat(
        self,
        session_id: str,
        bytes_rx: int = 0,
        bytes_tx: int = 0,
    ) -> bool:
        """
        Update last-seen timestamp and cumulative traffic counters.

        Returns:
            True if session was found, False otherwise.
        """
        session = self._sessions.get(session_id)
        if not session:
            return False

        # Auto-expire on heartbeat
        if session.is_expired:
            self._remove_session(session_id, reason="TTL expired on heartbeat")
            return False

        session.last_seen = datetime.utcnow()
        session.bytes_rx += bytes_rx
        session.bytes_tx += bytes_tx
        return True

    # ── Expiry Management ─────────────────────────────────────────────────────

    def cleanup_expired(self) -> int:
        """Remove all expired sessions.

        Returns:
            Number of sessions cleaned up.
        """
        expired_ids = [
            sid for sid, s in self._sessions.items() if s.is_expired
        ]
        for sid in expired_ids:
            self._remove_session(sid, reason="TTL expired (cleanup sweep)")
        return len(expired_ids)

    # ── Summary ───────────────────────────────────────────────────────────────

    def summary(self) -> dict:
        """Return a compact status summary for health/monitoring endpoints."""
        # Clean stale user_map entries
        stale_users = [
            u for u, sids in self._user_map.items()
            if not any(sid in self._sessions for sid in sids)
        ]
        for u in stale_users:
            self._user_map.pop(u, None)

        total_rx = sum(s.bytes_rx for s in self._sessions.values())
        total_tx = sum(s.bytes_tx for s in self._sessions.values())
        return {
            "active_sessions": self.active_count(),
            "total_bytes_rx": total_rx,
            "total_bytes_tx": total_tx,
            "unique_users": len(self._user_map),
        }

    # ── Internal ──────────────────────────────────────────────────────────────

    def _remove_session(self, session_id: str, reason: str = "") -> bool:
        session = self._sessions.pop(session_id, None)
        if not session:
            return False

        # Clean user map
        user_sids = self._user_map.get(session.username, [])
        if session_id in user_sids:
            user_sids.remove(session_id)
        if not user_sids:
            self._user_map.pop(session.username, None)

        # Clean pubkey index
        self._pubkey_index.pop(session.peer_public_key, None)

        logger.info(
            "VPN Portal: Session %s… terminated (user='%s', reason='%s')",
            session_id[:8], session.username, reason,
        )

        self._fire_event("vpn.session.terminated", {
            "session_id":   session_id,
            "username":     session.username,
            # Extract assigned IP so identity bridge can invalidate the cache entry
            "assigned_ip":  session.allowed_ips[0].split("/")[0] if session.allowed_ips else "",
            "reason":       reason,
            "duration_seconds": round(session.duration_seconds, 1),
            "bytes_rx":     session.bytes_rx,
            "bytes_tx":     session.bytes_tx,
        })

        return True

    def _fire_event(self, event_type: str, details: dict) -> None:
        """
        Publish a VPN lifecycle event to the EventBus.

        Topic mapping:
          vpn.session.created    → VPN_CONNECTED    (user authenticated & assigned IP)
          vpn.session.terminated → VPN_DISCONNECTED (session torn down)
          everything else        → VPN_FAILURE / VPN_RESTORED (health events)
        """
        if self._event_callback:
            try:
                self._event_callback(event_type, details)
            except Exception as exc:
                logger.debug("VPN Portal event callback error: %s", exc)

        # Map event_type → Topic
        if event_type == "vpn.session.created":
            topic = Topics.VPN_CONNECTED
        elif event_type == "vpn.session.terminated":
            topic = Topics.VPN_DISCONNECTED
        elif "terminate" in event_type or "failure" in event_type:
            topic = Topics.VPN_FAILURE
        else:
            topic = Topics.VPN_RESTORED

        try:
            EventBus.publish_from_thread(topic, details)
        except Exception as exc:
            logger.debug("Failed to dispatch VPN event '%s': %s", topic, exc)
