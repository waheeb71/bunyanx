"""
bunyanx NGFW — Audio Alert System: Priority Engine
======================================================
Evaluates incoming events, assigns priority levels,
enforces storm prevention and cooldown windows.

Anti-noise rules:
  - Per-topic cooldown TTL prevents repeated sounds
  - Storm detection: >N identical events in T seconds → aggregate
  - Emergency (Level 6) always bypasses all suppression
"""

import asyncio
import logging
import time
from collections import defaultdict, deque
from typing import Optional, Tuple

from system.audio.schemas import AudioPriority, AudioNotification, SoundProfile

logger = logging.getLogger(__name__)


# ── Event → Priority mapping ────────────────────────────────────────

EVENT_PRIORITY_MAP: dict[str, int] = {
    # System Lifecycle
    "system.started":           AudioPriority.INFORMATIONAL,
    "system.shutdown":          AudioPriority.NOTICE,
    "system.core_failure":      AudioPriority.EMERGENCY,
    "system.memory_critical":   AudioPriority.CRITICAL,
    "system.cpu_critical":      AudioPriority.CRITICAL,

    # Module Lifecycle
    "module.started":           AudioPriority.INFORMATIONAL,
    "module.stopped":           AudioPriority.NOTICE,
    "module.health":            AudioPriority.NOTICE,

    # Auth
    "auth.login_success":       AudioPriority.INFORMATIONAL,
    "auth.login_failure":       AudioPriority.WARNING,
    "auth.brute_force":         AudioPriority.CRITICAL,

    # Configuration
    "config.saved":             AudioPriority.INFORMATIONAL,
    "config.reloaded":          AudioPriority.NOTICE,

    # Threats
    "threat.detected":          AudioPriority.SECURITY_ALERT,
    "response.block":           AudioPriority.SECURITY_ALERT,
    "response.quarantine":      AudioPriority.SECURITY_ALERT,
    "response.alert":           AudioPriority.WARNING,

    # Malware
    "malware.detected":         AudioPriority.CRITICAL,

    # IDS/IPS
    "ids.port_scan":            AudioPriority.SECURITY_ALERT,
    "anomaly.scored":           AudioPriority.SECURITY_ALERT,

    # WAF & DNS
    "waf.block":                AudioPriority.CRITICAL,
    "waf.alert":                AudioPriority.WARNING,
    "dns.threat":               AudioPriority.SECURITY_ALERT,
    "web_filter.block":         AudioPriority.WARNING,
    "email.threat":             AudioPriority.SECURITY_ALERT,

    # DNS
    "dns.suspicious":           AudioPriority.SECURITY_ALERT,

    # DLP
    "dlp.incident":             AudioPriority.CRITICAL,

    # VPN
    "vpn.failure":              AudioPriority.SECURITY_ALERT,
    "vpn.restored":             AudioPriority.NOTICE,

    # PKI
    "pki.cert_expiring":        AudioPriority.WARNING,
    "pki.cert_invalid":         AudioPriority.CRITICAL,

    # HA
    "ha.failover":              AudioPriority.CRITICAL,

    # SIEM
    "siem.incident_created":    AudioPriority.SECURITY_ALERT,
    "siem.incident_escalated":  AudioPriority.CRITICAL,
    "siem.incident_closed":     AudioPriority.NOTICE,

    # Intelligence
    "intel.updated":            AudioPriority.INFORMATIONAL,
    "correlation.triggered":    AudioPriority.SECURITY_ALERT,
}


class PriorityEngine:
    """
    Assigns priority levels to audio events and enforces anti-noise rules.

    Anti-storm rules per priority level:
      - Cooldown TTL: once a sound plays, no repeat until TTL expires
      - Storm detection: >N same events in T seconds → play once with count
      - Level 6 (Emergency): always plays, no suppression
    """

    def __init__(self):
        # Per-topic: last time the sound was played (Unix timestamp)
        self._last_played: dict[str, float] = {}
        # Per-topic: sliding window of event timestamps for storm detection
        self._event_windows: dict[str, deque] = defaultdict(lambda: deque(maxlen=50))
        self._lock = asyncio.Lock()

    def get_priority(self, topic: str) -> int:
        """Return priority level for a topic. Defaults to INFORMATIONAL."""
        return EVENT_PRIORITY_MAP.get(topic, AudioPriority.INFORMATIONAL)

    async def evaluate(
        self,
        topic: str,
        payload: dict,
    ) -> Tuple[bool, AudioNotification, int]:
        """
        Evaluate an incoming event for audio playback.

        Returns:
            (should_play: bool, notification: AudioNotification, aggregated_count: int)

        should_play=True  → send to frontend and play sound
        should_play=False → suppressed (cooldown / storm / mute)
        """
        priority = self.get_priority(topic)
        now = time.monotonic()

        async with self._lock:
            # ── Level 6: Emergency — ALWAYS play ──────────────────
            if priority == AudioPriority.EMERGENCY:
                self._last_played[topic] = now
                notification = self._build_notification(topic, payload, priority, 1, False)
                return True, notification, 1

            # ── Storm detection ────────────────────────────────────
            window = self._event_windows[topic]
            window.append(now)

            max_events, window_s = AudioPriority.STORM_THRESHOLD[priority]
            # Count events within the window
            cutoff = now - window_s
            recent = sum(1 for t in window if t >= cutoff)

            if recent > max_events:
                # Storm — aggregate and suppress until cooldown
                aggregated = recent
                last = self._last_played.get(topic, 0)
                cooldown = AudioPriority.COOLDOWNS[priority]
                if (now - last) < cooldown:
                    # Still in cooldown — full suppress
                    notification = self._build_notification(
                        topic, payload, priority, aggregated, True
                    )
                    return False, notification, aggregated
                else:
                    # Play aggregated sound once
                    self._last_played[topic] = now
                    notification = self._build_notification(
                        topic, payload, priority, aggregated, False
                    )
                    return True, notification, aggregated

            # ── Cooldown window check ──────────────────────────────
            last = self._last_played.get(topic, 0)
            cooldown = AudioPriority.COOLDOWNS[priority]
            if cooldown > 0 and (now - last) < cooldown:
                notification = self._build_notification(
                    topic, payload, priority, 1, True
                )
                logger.debug(
                    f"[AudioPriority] Suppressed {topic} "
                    f"(cooldown {cooldown - (now - last):.1f}s remaining)"
                )
                return False, notification, 1

            # ── All clear — play sound ─────────────────────────────
            self._last_played[topic] = now
            notification = self._build_notification(topic, payload, priority, 1, False)
            return True, notification, 1

    def _build_notification(
        self,
        topic: str,
        payload: dict,
        priority: int,
        count: int,
        suppressed: bool,
    ) -> AudioNotification:
        """Construct an AudioNotification from event data."""
        source = payload.get("module", payload.get("source_module", "system"))
        title  = self._make_title(topic, payload, count)
        msg    = payload.get("reason", payload.get("message", ""))

        return AudioNotification(
            event_type      = topic,
            source_module   = source,
            priority        = priority,
            priority_name   = AudioPriority.NAMES.get(priority, "Unknown"),
            priority_color  = AudioPriority.COLORS.get(priority, "#ffffff"),
            sound_id        = self._topic_to_sound_id(topic),
            title           = title,
            message         = str(msg)[:200],
            suppressed      = suppressed,
            aggregated_count= count,
        )

    @staticmethod
    def _make_title(topic: str, payload: dict, count: int) -> str:
        """Generate a human-readable alert title."""
        label_map = {
            "system.started":           "النظام بدأ",
            "system.shutdown":          "إيقاف النظام",
            "system.core_failure":      "⚠ فشل حرج في النظام",
            "system.memory_critical":   "ذاكرة حرجة",
            "system.cpu_critical":      "CPU حرج",
            "module.started":           f"وحدة بدأت: {payload.get('module_name', '')}",
            "module.stopped":           f"وحدة توقفت: {payload.get('module_name', '')}",
            "auth.login_success":       "تسجيل دخول ناجح",
            "auth.login_failure":       "فشل تسجيل الدخول",
            "auth.brute_force":         "🚨 هجوم Brute Force",
            "config.saved":             "تم حفظ الإعدادات",
            "config.reloaded":          "تم تحديث السياسة",
            "threat.detected":          "🛡 تهديد مكتشف",
            "response.block":           "تم حجب التهديد",
            "malware.detected":         "🦠 برمجية خبيثة مكتشفة",
            "ids.port_scan":            "مسح المنافذ مكتشف",
            "dns.suspicious":           "نشاط DNS مشبوه",
            "dlp.incident":             "🔒 حادثة تسرب بيانات",
            "vpn.failure":              "فشل VPN",
            "vpn.restored":             "VPN استعاد الاتصال",
            "pki.cert_expiring":        "شهادة SSL قاربت على الانتهاء",
            "pki.cert_invalid":         "شهادة SSL غير صالحة",
            "ha.failover":              "HA Failover نشط",
            "siem.incident_created":    "حادثة أمنية جديدة",
            "siem.incident_escalated":  "تصعيد حادثة أمنية",
            "siem.incident_closed":     "إغلاق حادثة أمنية",
        }
        title = label_map.get(topic, topic)
        if count > 1:
            title = f"{title} (×{count})"
        return title

    @staticmethod
    def _topic_to_sound_id(topic: str) -> str:
        """Convert topic string to sound_id."""
        return topic.replace(".", "_")

    def reset(self) -> None:
        """Clear all cooldown and storm tracking state."""
        self._last_played.clear()
        self._event_windows.clear()
