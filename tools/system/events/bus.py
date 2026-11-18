"""
bunyanx NGFW — Event Bus
=============================
Async event bus with hot-swappable backends.

Backends:
  "memory"  → in-process async queue (dev/testing, no external server)
  "nats"    → NATS JetStream (production, low-latency)
  "kafka"   → Apache Kafka (enterprise, high-throughput)

The bus is controlled by features.yaml:
  features.event_bus.enabled: true
  features.event_bus.backend: "nats"

Usage:
    bus = await EventBus.instance()
    await bus.publish(Topics.THREAT_DETECTED, event.to_dict())
    await bus.subscribe(Topics.THREAT_DETECTED, my_handler)
"""

import asyncio
import inspect
import json
import logging
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import Callable, Awaitable, Optional

from system.config.feature_flags import FeatureFlagManager
from system.events.topics import Topics

logger = logging.getLogger(__name__)

Handler = Callable[[dict], Awaitable[None]]


# ──────────────────────────────────────────────────────────────────────
# Abstract Backend
# ──────────────────────────────────────────────────────────────────────

class EventBusBackend(ABC):
    """All backends must implement this interface."""

    @abstractmethod
    async def connect(self) -> None: ...

    @abstractmethod
    async def disconnect(self) -> None: ...

    @abstractmethod
    async def publish(self, topic: str, payload: dict) -> None: ...

    @abstractmethod
    async def subscribe(self, topic: str, handler: Handler) -> None: ...

    def _write_dlq(self, topic: str, payload: dict, reason: str) -> None:
        try:
            import json
            import os
            dlq_path = os.path.join(os.path.dirname(__file__), "dlq.jsonl")
            dlq_entry = {"topic": topic, "reason": reason, "payload": payload}
            with open(dlq_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(dlq_entry) + "\n")
        except Exception as e:
            logger.error(f"[EventBus:DLQ] Failed to write to DLQ: {e}")


# ──────────────────────────────────────────────────────────────────────
# Memory Backend (In-process — dev/testing)
# ──────────────────────────────────────────────────────────────────────

class MemoryBackend(EventBusBackend):
    """
    In-process async pub/sub using asyncio.Queue.
    No external server needed. Suitable for development and unit tests.
    """

    def __init__(self):
        self._subscriptions: dict[str, list[Handler]] = defaultdict(list)
        self._lock = asyncio.Lock()
        self._queue: Optional[asyncio.Queue] = None
        self._worker_task: Optional[asyncio.Task] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    async def connect(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._queue = asyncio.Queue(maxsize=10000)
        self._worker_task = asyncio.create_task(self._worker_loop())
        logger.info("[EventBus:memory] Connected (in-process, true queue)")

    async def disconnect(self) -> None:
        if self._queue:
            try:
                # Send poison pill to stop the worker gracefully
                self._queue.put_nowait(None)
            except asyncio.QueueFull:
                pass
        if self._worker_task:
            await self._worker_task
        logger.info("[EventBus:memory] Disconnected")

    async def _safe_execute(self, handler, topic, payload):
        try:
            if inspect.iscoroutinefunction(handler):
                await handler(payload)
            else:
                res = handler(payload)
                if inspect.iscoroutine(res) or asyncio.iscoroutine(res):
                    await res
        except Exception as e:
            logger.error(f"[EventBus:memory] Handler error on {topic}: {e}")
            self._write_dlq(topic, payload, f"handler_error: {str(e)}")

    async def _worker_loop(self):
        while True:
            try:
                item = await self._queue.get()
                if item is None:  # Poison pill received
                    self._queue.task_done()
                    break
                    
                topic, payload = item
                handlers = self._subscriptions.get(topic, [])
                if handlers:
                    tasks = [asyncio.create_task(self._safe_execute(h, topic, payload)) for h in handlers]
                    if tasks:
                        await asyncio.gather(*tasks)
                self._queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[EventBus:memory] Worker error: {e}")

    async def publish(self, topic: str, payload: dict) -> None:
        if not self._queue:
            return
        
        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None

        try:
            if current_loop == self._loop:
                self._queue.put_nowait((topic, payload))
            else:
                self._loop.call_soon_threadsafe(self._queue.put_nowait, (topic, payload))
        except asyncio.QueueFull:
            logger.warning(f"[EventBus:memory] ⚠️ Backpressure limit reached! Moving event to DLQ: {topic}")
            self._write_dlq(topic, payload, "queue_full")

    async def subscribe(self, topic: str, handler: Handler) -> None:
        async with self._lock:
            self._subscriptions[topic].append(handler)
        logger.debug(f"[EventBus:memory] Subscribed to {topic}")


# ──────────────────────────────────────────────────────────────────────
# NATS Backend (Production — low latency)
# ──────────────────────────────────────────────────────────────────────

class NATSBackend(EventBusBackend):
    """
    NATS JetStream backend.
    Requires: pip install nats-py
    Requires: NATS server running (features.event_bus.nats_url)
    """

    def __init__(self, nats_url: str, reconnect_wait: int = 2, max_reconnect: int = 60):
        self._url = nats_url
        self._reconnect_wait = reconnect_wait
        self._max_reconnect = max_reconnect
        self._nc = None
        self._subscriptions: list = []

    async def connect(self) -> None:
        try:
            import nats                                              # noqa: F401
            self._nc = await nats.connect(
                servers=self._url,
                reconnect_time_wait=self._reconnect_wait,
                max_reconnect_attempts=self._max_reconnect,
                error_cb=self._on_error,
                disconnected_cb=lambda: logger.warning("[EventBus:nats] Disconnected"),
                reconnected_cb=lambda: logger.info("[EventBus:nats] Reconnected ✓"),
            )
            logger.info(f"[EventBus:nats] Connected to {self._url}")
        except Exception as exc:
            logger.error(f"[EventBus:nats] Connection failed: {exc}")
            raise

    async def disconnect(self) -> None:
        if self._nc:
            await self._nc.drain()

    async def publish(self, topic: str, payload: dict) -> None:
        data = json.dumps(payload).encode()
        await self._nc.publish(topic, data)

    async def subscribe(self, topic: str, handler: Handler) -> None:
        async def _wrapper(msg):
            data = {}
            try:
                data = json.loads(msg.data.decode())
                if inspect.iscoroutinefunction(handler):
                    await handler(data)
                else:
                    res = handler(data)
                    if inspect.iscoroutine(res) or asyncio.iscoroutine(res):
                        await res
            except Exception as exc:
                logger.error(f"[EventBus:nats] Handler error on {topic}: {exc}")
                self._write_dlq(topic, data, f"handler_error: {str(exc)}")

        sub = await self._nc.subscribe(topic, cb=_wrapper)
        self._subscriptions.append(sub)
        logger.debug(f"[EventBus:nats] Subscribed to {topic}")

    @staticmethod
    async def _on_error(exc):
        logger.error(f"[EventBus:nats] Error: {exc}")


# ──────────────────────────────────────────────────────────────────────
# Null Backend (when event_bus.enabled = false)
# ──────────────────────────────────────────────────────────────────────

class NullBackend(EventBusBackend):
    """No-op backend. Used when event bus is disabled in feature flags."""

    async def connect(self) -> None:
        logger.debug("[EventBus:null] Event bus disabled — using null backend")

    async def disconnect(self) -> None:
        pass

    async def publish(self, topic: str, payload: dict) -> None:
        pass   # Silently discard

    async def subscribe(self, topic: str, handler: Handler) -> None:
        pass   # Silently ignore subscriptions


# ──────────────────────────────────────────────────────────────────────
# EventBus — Public API (Singleton)
# ──────────────────────────────────────────────────────────────────────

class EventBus:
    """
    Feature-flag-aware event bus singleton.

    When event_bus.enabled = false → uses NullBackend (silent no-ops).
    When event_bus.backend = "memory" → MemoryBackend (in-process).
    When event_bus.backend = "nats"  → NATSBackend (production).

    All modules use ONLY this class — never import a backend directly.
    """

    _instance: Optional["EventBus"] = None

    def __init__(self, backend: EventBusBackend):
        self._backend = backend
        self._connected = False

    # ── Singleton ──────────────────────────────────────────────────

    @classmethod
    async def instance(cls) -> "EventBus":
        if cls._instance is None:
            cls._instance = await cls._create()
        return cls._instance

    @classmethod
    async def _create(cls) -> "EventBus":
        flags = FeatureFlagManager.instance().current.event_bus

        if not FeatureFlagManager.instance().current.event_bus.enabled:
            backend: EventBusBackend = NullBackend()
            logger.info("[EventBus] Disabled — using NullBackend")
        elif flags.backend == "nats":
            backend = NATSBackend(
                nats_url=flags.nats_url,
                reconnect_wait=flags.reconnect_wait_s,
                max_reconnect=flags.max_reconnect,
            )
        elif flags.backend == "memory":
            backend = MemoryBackend()
        else:
            logger.warning(f"[EventBus] Unknown backend '{flags.backend}' — using memory")
            backend = MemoryBackend()

        bus = cls(backend)
        await bus._connect()
        return bus

    # ── Public API ─────────────────────────────────────────────────

    async def publish(self, topic: str, payload: dict) -> None:
        """Publish an event to a topic. Non-blocking on NullBackend and MemoryBackend."""
        # --- Schema Sanity Check (Auto-Validation) ---
        if 'event_id' not in payload:
            import uuid
            payload['event_id'] = str(uuid.uuid4())
        if 'timestamp' not in payload:
            from datetime import datetime, timezone
            payload['timestamp'] = datetime.now(timezone.utc).isoformat()
            
        if 'trace_id' not in payload:
            try:
                from system.telemetry.otel_tracer import OTelTracer
                trace_id = OTelTracer.instance().get_current_trace_id()
                if trace_id:
                    payload['trace_id'] = trace_id
            except Exception:
                pass
        # ---------------------------------------------

        try:
            await asyncio.wait_for(
                self._backend.publish(topic, payload),
                timeout=1.0,
            )
        except asyncio.TimeoutError:
            logger.warning(f"[EventBus] Publish timeout on topic: {topic}")
        except Exception as exc:
            logger.error(f"[EventBus] Publish error ({topic}): {exc}")

    async def subscribe(self, topic: str, handler: Handler) -> None:
        """Subscribe an async handler to a topic."""
        await self._backend.subscribe(topic, handler)

    async def disconnect(self) -> None:
        await self._backend.disconnect()
        self._connected = False

    # ── Internal ───────────────────────────────────────────────────

    async def _connect(self) -> None:
        await self._backend.connect()
        self._connected = True
        # ── Store the running event loop so worker threads can use it ──────────
        # publish_from_thread() needs to schedule coroutines back onto this loop.
        try:
            EventBus._main_loop = asyncio.get_running_loop()
        except RuntimeError:
            EventBus._main_loop = None

    # ── Thread-safe publish (for use inside asyncio.to_thread callbacks) ──────

    _main_loop: Optional[asyncio.AbstractEventLoop] = None

    @classmethod
    def publish_from_thread(cls, topic: str, payload: dict) -> None:
        """
        Publish an event to the EventBus from a worker thread (non-async context).

        Use this instead of `await bus.publish()` when calling from inside
        asyncio.to_thread(), threading.Thread, or any sync code that runs
        outside the main event loop.

        Example:
            # Inside a sync inspect() method called via asyncio.to_thread():
            EventBus.publish_from_thread(Topics.WAF_BLOCK, payload)
        """
        loop = cls._main_loop
        if loop is None or not loop.is_running():
            logger.debug(
                "[EventBus] publish_from_thread: no running loop — topic=%s dropped", topic
            )
            return

        async def _pub():
            try:
                bus = await cls.instance()
                await bus.publish(topic, payload)
                logger.debug("[EventBus] published from thread: %s", topic)
            except Exception as exc:
                logger.warning("[EventBus] publish_from_thread error (%s): %s", topic, exc)

        asyncio.run_coroutine_threadsafe(_pub(), loop)

