"""
bunyanx Voice Alert Service (CVAS) - Event Subscriber
======================================================
Async EventBus subscriber that feeds security events and log anomalies into the CVAS pipeline.
Completely non-blocking and decoupled from main event loop.

FIX (ARCH-06): subscribe_all() now retries up to 5 times with exponential backoff
               if EventBus is not yet ready at service startup.
"""

import asyncio
import logging
from typing import Dict, Any, Optional

from system.events.bus import EventBus
from system.events.topics import Topics

logger = logging.getLogger(__name__)

# Full list of event topics CVAS listens to across the enterprise platform
CVAS_SUBSCRIBED_TOPICS = [
    Topics.SYSTEM_STARTED,
    Topics.SYSTEM_SHUTDOWN,
    Topics.SYSTEM_CORE_FAILURE,
    Topics.SYSTEM_MEMORY_CRITICAL,
    Topics.SYSTEM_CPU_CRITICAL,
    Topics.AUTH_LOGIN_SUCCESS,
    Topics.AUTH_LOGIN_FAILURE,
    Topics.AUTH_BRUTE_FORCE,
    Topics.HA_FAILOVER,
    Topics.SIEM_INCIDENT_CREATED,
    Topics.SIEM_INCIDENT_ESCALATED,
    Topics.SIEM_INCIDENT_CLOSED,
    Topics.MALWARE_DETECTED,
    Topics.THREAT_DETECTED,
    Topics.RESPONSE_BLOCK,
    Topics.RESPONSE_QUARANTINE,
    Topics.RESPONSE_ALERT,
    Topics.WAF_BLOCK,
    Topics.WAF_ALERT,
    Topics.IDS_PORT_SCAN,
    Topics.DLP_INCIDENT,
    Topics.EMAIL_THREAT,
    Topics.DNS_THREAT,
    Topics.DNS_SUSPICIOUS,
    Topics.WEB_FILTER_BLOCK,
    Topics.VPN_FAILURE,
    Topics.VPN_RESTORED,
    Topics.VPN_CONNECTED,
    Topics.VPN_DISCONNECTED,
    Topics.ANOMALY_SCORED,
    Topics.AI_SCORE_GENERATED,
    Topics.PKI_CERT_EXPIRING,
    Topics.PKI_CERT_INVALID,
    Topics.CORRELATION_TRIGGERED,
    Topics.MODULE_HEALTH,
    Topics.CAPTIVE_PORTAL_LOGIN,
    Topics.CAPTIVE_PORTAL_LOGOUT,
]

_MAX_RETRY_ATTEMPTS = 5
_RETRY_BASE_DELAY_S = 2.0   # exponential backoff: 2, 4, 8, 16, 32 seconds


class CVASSubscriber:
    """
    Subscribes CVAS to EventBus topics.
    Each handler is a fast async function that delegates enrichment
    and synthesis to worker components.
    """

    def __init__(self, orchestrator: Any):
        self.orchestrator = orchestrator
        self._subscribed = False

    async def subscribe_all(self) -> None:
        """
        Subscribe to all CVAS topics on the EventBus.
        FIX (ARCH-06): Retries with exponential backoff if EventBus is unavailable,
        because CVAS may start before the EventBus is fully initialized.
        """
        if self._subscribed:
            return

        for attempt in range(1, _MAX_RETRY_ATTEMPTS + 1):
            try:
                bus = await EventBus.instance()

                subscribed_count = 0
                for topic in CVAS_SUBSCRIBED_TOPICS:
                    # Capture topic in closure — required to avoid late-binding bug
                    async def _handler(payload: dict, _topic: str = topic) -> None:
                        await self._on_event(_topic, payload)

                    await bus.subscribe(topic, _handler)
                    subscribed_count += 1

                self._subscribed = True
                logger.info(
                    f"[CVAS:Subscriber] Subscribed to {subscribed_count} EventBus topics "
                    f"(attempt {attempt}/{_MAX_RETRY_ATTEMPTS})."
                )
                return  # success

            except Exception as e:
                delay = _RETRY_BASE_DELAY_S * (2 ** (attempt - 1))
                if attempt < _MAX_RETRY_ATTEMPTS:
                    logger.warning(
                        f"[CVAS:Subscriber] EventBus not ready (attempt {attempt}/{_MAX_RETRY_ATTEMPTS}): "
                        f"{e}. Retrying in {delay:.0f}s..."
                    )
                    await asyncio.sleep(delay)
                else:
                    logger.error(
                        f"[CVAS:Subscriber] Failed to subscribe after {_MAX_RETRY_ATTEMPTS} attempts: {e}. "
                        "CVAS will operate without real-time event feed."
                    )

    async def _on_event(self, topic: str, payload: dict) -> None:
        """
        Fast non-blocking handler. Offloads event to CVAS orchestrator
        via asyncio.create_task so the EventBus callback returns immediately.
        """
        try:
            asyncio.create_task(
                self.orchestrator.process_event_async(topic, payload),
                name=f"cvas_event_{topic}",
            )
        except Exception as e:
            logger.error(f"[CVAS:Subscriber] Error dispatching event {topic}: {e}")
