"""
bunyanx NGFW — Audio Alert System: Audio Manager
=====================================================
Central singleton that orchestrates the entire Audio Alert pipeline.

Lifecycle:
  1. AudioManager.instance()  → get or create singleton
  2. await manager.start()    → start all sub-services
  3. await manager.stop()     → graceful shutdown

Event Pipeline:
  EventSubscriber.on_event(topic, payload)
    → PriorityEngine.evaluate()         [assign level, check storm/cooldown]
    → MuteController.is_muted()         [check global/timed/role mute]
    → SoundRouter.route()               [resolve sound profile]
    → NotificationController.broadcast() [push to all SSE clients]
"""

import asyncio
import logging
from collections import deque
from datetime import datetime, timezone
from typing import Optional

from system.audio.schemas          import (
    AudioNotification, AudioPriority, AudioSettings
)
from system.audio.priority_engine  import PriorityEngine
from system.audio.mute_controller  import MuteController
from system.audio.sound_router     import SoundRouter
from system.audio.notification_ctrl import NotificationController
from system.audio.event_subscriber import EventSubscriber
from system.audio.native_player    import NativePlayer

logger = logging.getLogger(__name__)

# Ring-buffer size for sound history
HISTORY_SIZE = 500


class AudioManager:
    """
    Singleton Audio Alert Manager.

    All modules interact with this class only:
        manager = await AudioManager.instance()
        await manager.process_event(topic, payload)   # called by EventSubscriber
        await manager.test_sound(sound_id)            # called by REST API
    """

    _instance: Optional["AudioManager"] = None
    _lock = asyncio.Lock()

    def __init__(self):
        self.priority_engine   = PriorityEngine()
        self.mute_controller   = MuteController()
        self.sound_router      = SoundRouter()
        self.notification_ctrl = NotificationController()
        self.event_subscriber  = EventSubscriber(self)

        # Ring buffer: last HISTORY_SIZE audio notifications
        self._history: deque[dict] = deque(maxlen=HISTORY_SIZE)
        self._started = False

    # ── Singleton ─────────────────────────────────────────────────

    @classmethod
    async def instance(cls) -> "AudioManager":
        async with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset singleton (for testing)."""
        cls._instance = None

    # ── Lifecycle ─────────────────────────────────────────────────

    async def start(self) -> None:
        """Start all Audio Alert sub-services and subscribe to EventBus."""
        if self._started:
            return
        await self.mute_controller.start()
        await self.event_subscriber.subscribe_all()
        self._started = True
        logger.info("[AudioManager] ✅ Audio Alert System started")

    async def stop(self) -> None:
        """Graceful shutdown."""
        await self.mute_controller.stop()
        self._started = False
        logger.info("[AudioManager] Audio Alert System stopped")

    # ── Core Pipeline ─────────────────────────────────────────────

    async def process_event(self, topic: str, payload: dict) -> None:
        """
        Main event processing pipeline.
        Called by EventSubscriber for every matching bus event.
        """
        try:
            # 1. Priority evaluation + storm prevention
            should_play, notification, count = await self.priority_engine.evaluate(
                topic, payload
            )

            # 2. Check mute state
            is_muted = await self.mute_controller.is_muted()
            if is_muted and notification.priority < AudioPriority.EMERGENCY:
                notification.suppressed = True
                should_play = False
                logger.debug(f"[AudioManager] Suppressed (muted): {topic}")

            # 3. Resolve sound profile
            profile = await self.mute_controller.get_profile()
            sound_dict = self.sound_router.route(topic, notification.priority)

            # Apply volume from settings
            volume = await self.mute_controller.get_volume()
            sound_dict = self._apply_volume(sound_dict, volume)

            notification.sound_profile = sound_dict

            # 4. Store in history
            entry = notification.to_dict()
            entry["played"] = should_play
            entry["profile"] = profile
            self._history.appendleft(entry)

            # 5. Native server-side playback (plays on firewall machine speakers)
            #    Only for Warning (3) and above — Informational & Notice events
            #    stay silent on the server and use browser synthesized tones instead.
            if should_play and notification.priority >= AudioPriority.WARNING:
                settings = await self.mute_controller.get_settings()
                if settings.native_playback_enabled:
                    sound_id = sound_dict.get("sound_id", topic)
                    asyncio.get_running_loop().run_in_executor(
                        None,
                        NativePlayer.play_sound,
                        sound_id,
                        notification.priority,
                        volume,
                    )
                    logger.debug(
                        f"[AudioManager] 🔔 Native playback: {sound_id} "
                        f"| priority={notification.priority} | vol={volume:.0%}"
                    )

            # 6. Broadcast to all SSE clients (for visual notifications in browser)
            await self.notification_ctrl.broadcast(notification)

        except Exception as e:
            logger.error(f"[AudioManager] Pipeline error for {topic}: {e}", exc_info=True)

    # ── REST API Methods ──────────────────────────────────────────

    async def test_sound(self, sound_id: str) -> AudioNotification:
        """
        Trigger a test sound by sound_id.
        Bypasses mute and cooldown — always plays.
        Plays natively on the server AND broadcasts SSE to browser UI.
        Used by the Sound Tester UI page.
        """
        # Find topic matching this sound_id
        topic = sound_id.replace("_", ".", 1) if "_" in sound_id else sound_id
        priority = self.priority_engine.get_priority(topic)
        sound_dict = self.sound_router.route(topic, priority)

        volume = await self.mute_controller.get_volume()
        sound_dict = self._apply_volume(sound_dict, volume)

        notification = AudioNotification(
            event_type    = topic,
            source_module = "audio_tester",
            priority      = priority,
            priority_name = AudioPriority.NAMES.get(priority, "Unknown"),
            priority_color= AudioPriority.COLORS.get(priority, "#ffffff"),
            sound_id      = sound_id,
            sound_profile = sound_dict,
            title         = f"🔊 اختبار: {sound_dict.get('label', sound_id)}",
            message       = "صوت اختباري من لوحة التحكم",
            suppressed    = False,
        )

        # Native server-side playback (test always bypasses mute/native toggle)
        settings = await self.mute_controller.get_settings()
        if settings.native_playback_enabled:
            asyncio.get_running_loop().run_in_executor(
                None,
                NativePlayer.play_sound,
                sound_id,
                priority,
                volume,
            )
            logger.info(f"[AudioManager] 🔊 Native test playback: {sound_id}")

        # Broadcast SSE to browser (for visual notification)
        await self.notification_ctrl.broadcast(notification)
        return notification

    async def get_settings(self) -> AudioSettings:
        return await self.mute_controller.get_settings()

    async def update_settings(self, updates: dict) -> AudioSettings:
        settings = await self.mute_controller.update_settings(updates)
        # Sync profile to sound router
        self.sound_router.set_profile(settings.profile)
        return settings

    async def mute(self, duration_minutes: Optional[int] = None) -> None:
        await self.mute_controller.mute(duration_minutes)

    async def unmute(self) -> None:
        await self.mute_controller.unmute()

    async def get_history(self, limit: int = 100) -> list[dict]:
        """Return recent audio notification history."""
        return list(self._history)[:limit]

    def get_event_map(self) -> list[dict]:
        """Return full event → sound mapping."""
        return self.sound_router.get_full_event_map()

    def set_event_override(self, topic: str, profile_dict: dict) -> None:
        self.sound_router.set_override(topic, profile_dict)

    def clear_event_override(self, topic: str) -> None:
        self.sound_router.clear_override(topic)

    # ── Internal Helpers ──────────────────────────────────────────

    @staticmethod
    def _apply_volume(sound_dict: dict, master_volume: float) -> dict:
        """Scale all tone volumes by the master volume setting."""
        import copy
        d = copy.deepcopy(sound_dict)
        if "tones" in d and isinstance(d["tones"], list):
            for tone in d["tones"]:
                if "volume" in tone:
                    tone["volume"] = min(1.0, tone["volume"] * master_volume)
        return d

    @property
    def is_started(self) -> bool:
        return self._started

    @property
    def stats(self) -> dict:
        return {
            "started": self._started,
            "history_count": len(self._history),
            "sse_clients": self.notification_ctrl.client_count,
            "profile": self.sound_router._active_profile,
        }
