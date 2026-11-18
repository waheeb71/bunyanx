"""
bunyanx NGFW — Audio Alert System: Event Subscriber
=======================================================
Subscribes to ALL EventBus topics at startup and routes
incoming events through the Audio Alert pipeline.

Pipeline:
  EventBus → EventSubscriber → PriorityEngine →
  MuteController → SoundRouter → NotificationController → SSE → Browser
"""

import asyncio
import logging
from typing import TYPE_CHECKING

from system.events.bus   import EventBus
from system.events.topics import Topics
from system.audio.schemas import AudioPriority

if TYPE_CHECKING:
    from system.audio.audio_manager import AudioManager

logger = logging.getLogger(__name__)

# All topics the Audio system subscribes to
# Derived from Topics class + new audio-specific topics
AUDIO_SUBSCRIBED_TOPICS = [
    # System Lifecycle
    Topics.SYSTEM_STARTED,
    Topics.SYSTEM_SHUTDOWN,
    Topics.SYSTEM_CORE_FAILURE,
    Topics.SYSTEM_MEMORY_CRITICAL,
    Topics.SYSTEM_CPU_CRITICAL,

    # Module Lifecycle
    Topics.MODULE_STARTED,
    Topics.MODULE_STOPPED,
    Topics.MODULE_HEALTH,

    # Auth
    Topics.AUTH_LOGIN_SUCCESS,
    Topics.AUTH_LOGIN_FAILURE,
    Topics.AUTH_BRUTE_FORCE,

    # Config
    Topics.CONFIG_SAVED,
    Topics.CONFIG_RELOADED,

    # Threats
    Topics.THREAT_DETECTED,
    Topics.RESPONSE_BLOCK,
    Topics.RESPONSE_QUARANTINE,
    Topics.RESPONSE_ALERT,

    # Malware
    Topics.MALWARE_DETECTED,

    # IDS
    Topics.IDS_PORT_SCAN,
    Topics.ANOMALY_SCORED,

    # WAF & DNS & Web Filter
    Topics.WAF_BLOCK,
    Topics.WAF_ALERT,
    Topics.DNS_THREAT,
    Topics.DNS_SUSPICIOUS,
    Topics.WEB_FILTER_BLOCK,

    # DLP & Email
    Topics.DLP_INCIDENT,
    Topics.EMAIL_THREAT,

    # AI
    Topics.AI_SCORE_GENERATED,

    # VPN
    Topics.VPN_FAILURE,
    Topics.VPN_RESTORED,

    # PKI
    Topics.PKI_CERT_EXPIRING,
    Topics.PKI_CERT_INVALID,

    # HA
    Topics.HA_FAILOVER,

    # SIEM
    Topics.SIEM_INCIDENT_CREATED,
    Topics.SIEM_INCIDENT_ESCALATED,
    Topics.SIEM_INCIDENT_CLOSED,

    # Intelligence
    Topics.INTEL_UPDATED,
    Topics.CORRELATION_TRIGGERED,
]


class EventSubscriber:
    """
    Subscribes to all relevant EventBus topics and feeds events
    into the AudioManager processing pipeline.

    Non-blocking: each handler is a fast async function that
    delegates heavy lifting to AudioManager.
    """

    def __init__(self, manager: "AudioManager"):
        self._manager   = manager
        self._subscribed = False

    async def subscribe_all(self) -> None:
        """Subscribe to all audio-relevant EventBus topics."""
        if self._subscribed:
            return

        bus = await EventBus.instance()

        for topic in AUDIO_SUBSCRIBED_TOPICS:
            # Capture topic in closure
            async def _handler(payload: dict, _topic: str = topic) -> None:
                await self._on_event(_topic, payload)

            await bus.subscribe(topic, _handler)

        self._subscribed = True
        logger.info(
            f"[AudioSubscriber] Subscribed to {len(AUDIO_SUBSCRIBED_TOPICS)} topics"
        )

    async def _on_event(self, topic: str, payload: dict) -> None:
        """
        Called for every matching EventBus event.
        Dispatches to AudioManager pipeline (non-blocking).
        Always runs inside the event loop (EventBus handler), so
        asyncio.create_task() is always safe here.
        """
        try:
            asyncio.create_task(
                self._manager.process_event(topic, payload),
                name=f"audio_event_{topic}",
            )
        except Exception as e:
            logger.error(f"[AudioSubscriber] Failed to dispatch {topic}: {e}")
