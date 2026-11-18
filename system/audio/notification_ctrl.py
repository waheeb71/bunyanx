"""
bunyanx NGFW — Audio Alert System: Notification Controller
==============================================================
Manages active Server-Sent Events (SSE) connections and
pushes AudioNotification payloads to all connected frontends.

Architecture: each browser tab that connects to
  GET /api/audio/events/stream
registers an asyncio.Queue here. When an AudioNotification
is ready, it's enqueued to ALL connected clients.
"""

import asyncio
import logging
from typing import AsyncIterator

from system.audio.schemas import AudioNotification

logger = logging.getLogger(__name__)


class NotificationController:
    """
    Manages SSE subscriber queues and broadcasts audio notifications.

    Thread-safe via asyncio lock; each client gets its own queue
    so slow readers don't block fast readers (backpressure per-client).
    """

    MAX_QUEUE_SIZE   = 500    # Per-client queue limit
    MAX_CLIENTS      = 200    # Maximum simultaneous SSE connections

    def __init__(self):
        self._clients: list[asyncio.Queue] = []
        self._lock    = asyncio.Lock()

    # ── Client Lifecycle ──────────────────────────────────────────

    async def connect(self) -> asyncio.Queue:
        """
        Register a new SSE client.
        Returns the queue this client should read from.
        """
        async with self._lock:
            if len(self._clients) >= self.MAX_CLIENTS:
                logger.warning(
                    f"[AudioSSE] Max clients ({self.MAX_CLIENTS}) reached — "
                    "rejecting new connection"
                )
                raise ConnectionError("Too many SSE clients")

            q: asyncio.Queue = asyncio.Queue(maxsize=self.MAX_QUEUE_SIZE)
            self._clients.append(q)
            logger.debug(f"[AudioSSE] Client connected ({len(self._clients)} total)")
            return q

    async def disconnect(self, q: asyncio.Queue) -> None:
        """Unregister an SSE client."""
        async with self._lock:
            try:
                self._clients.remove(q)
            except ValueError:
                pass
        logger.debug(f"[AudioSSE] Client disconnected ({len(self._clients)} remaining)")

    # ── Broadcast ─────────────────────────────────────────────────

    async def broadcast(self, notification: AudioNotification) -> None:
        """
        Send an AudioNotification to all connected SSE clients.
        Slow/full client queues are silently dropped (non-blocking).
        """
        if not self._clients:
            return

        async with self._lock:
            clients = list(self._clients)

        dropped = 0
        for q in clients:
            try:
                q.put_nowait(notification)
            except asyncio.QueueFull:
                dropped += 1

        if dropped:
            logger.warning(
                f"[AudioSSE] Dropped notification for {dropped} slow client(s)"
            )

    # ── SSE Stream Generator ──────────────────────────────────────

    async def stream(self, client_queue: asyncio.Queue) -> AsyncIterator[str]:
        """
        Async generator yielding SSE-formatted strings for one client.

        Usage in FastAPI:
            async def endpoint():
                q = await ctrl.connect()
                return StreamingResponse(ctrl.stream(q), media_type="text/event-stream")
        """
        try:
            # Send initial heartbeat
            yield "event: connected\ndata: {\"status\": \"audio_stream_active\"}\n\n"

            while True:
                try:
                    notification: AudioNotification = await asyncio.wait_for(
                        client_queue.get(), timeout=25.0
                    )
                    yield notification.to_sse()
                except asyncio.TimeoutError:
                    # Keepalive comment to prevent proxy timeout
                    yield ": keepalive\n\n"
        finally:
            await self.disconnect(client_queue)

    # ── Stats ─────────────────────────────────────────────────────

    @property
    def client_count(self) -> int:
        return len(self._clients)
