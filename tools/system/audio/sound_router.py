"""
bunyanx NGFW — Audio Alert System: Sound Router
====================================================
Maps EventBus topics to SoundProfile definitions.
Supports per-topic overrides and fallback to default profile.
"""

import logging
from typing import Optional

from system.audio.schemas import SoundProfile, AudioPriority
from system.audio.profiles import get_profile_map

logger = logging.getLogger(__name__)


class SoundRouter:
    """
    Routes EventBus topics to the correct SoundProfile
    based on the currently active sound profile/theme.

    Profile lookup order:
      1. Active profile map (default / night / silent)
      2. Per-user overrides (stored in runtime override dict)
      3. Fallback: generic profile based on priority level
    """

    # Generic fallback tones for when no specific mapping exists
    _FALLBACK_PROFILES: dict[int, dict] = {
        AudioPriority.INFORMATIONAL: {
            "sound_id": "generic_info",
            "label": "معلومة",
            "priority": 1,
            "tones": [{"frequency_hz": 880, "duration_ms": 100, "waveform": "sine",
                       "volume": 0.3, "attack_ms": 20, "decay_ms": 40,
                       "sustain_level": 0.6, "release_ms": 60}],
            "repeat": 1, "gap_ms": 0, "silent": False,
        },
        AudioPriority.NOTICE: {
            "sound_id": "generic_notice",
            "label": "إشعار",
            "priority": 2,
            "tones": [{"frequency_hz": 660, "duration_ms": 150, "waveform": "sine",
                       "volume": 0.4, "attack_ms": 20, "decay_ms": 40,
                       "sustain_level": 0.65, "release_ms": 70}],
            "repeat": 1, "gap_ms": 0, "silent": False,
        },
        AudioPriority.WARNING: {
            "sound_id": "generic_warning",
            "label": "تحذير",
            "priority": 3,
            "tones": [{"frequency_hz": 440, "duration_ms": 200, "waveform": "square",
                       "volume": 0.55, "attack_ms": 10, "decay_ms": 30,
                       "sustain_level": 0.7, "release_ms": 60}],
            "repeat": 2, "gap_ms": 100, "silent": False,
        },
        AudioPriority.SECURITY_ALERT: {
            "sound_id": "generic_alert",
            "label": "تنبيه أمني",
            "priority": 4,
            "tones": [{"frequency_hz": 880, "duration_ms": 150, "waveform": "square",
                       "volume": 0.7, "attack_ms": 5, "decay_ms": 20,
                       "sustain_level": 0.8, "release_ms": 40}],
            "repeat": 3, "gap_ms": 120, "silent": False,
        },
        AudioPriority.CRITICAL: {
            "sound_id": "generic_critical",
            "label": "حرج",
            "priority": 5,
            "tones": [{"frequency_hz": 660, "duration_ms": 200, "waveform": "sawtooth",
                       "volume": 0.85, "attack_ms": 5, "decay_ms": 15,
                       "sustain_level": 0.9, "release_ms": 30}],
            "repeat": 4, "gap_ms": 180, "silent": False,
        },
        AudioPriority.EMERGENCY: {
            "sound_id": "generic_emergency",
            "label": "طوارئ",
            "priority": 6,
            "tones": [
                {"frequency_hz": 960, "duration_ms": 200, "waveform": "square",
                 "volume": 1.0, "attack_ms": 5, "decay_ms": 10,
                 "sustain_level": 1.0, "release_ms": 10},
                {"frequency_hz": 480, "duration_ms": 200, "waveform": "square",
                 "volume": 1.0, "attack_ms": 5, "decay_ms": 10,
                 "sustain_level": 1.0, "release_ms": 10},
            ],
            "repeat": 99, "gap_ms": 100, "silent": False,
        },
    }

    def __init__(self):
        self._active_profile: str = "default"
        # Per-topic overrides set via the API
        self._overrides: dict[str, dict] = {}

    def set_profile(self, profile_name: str) -> None:
        """Switch the active sound profile."""
        self._active_profile = profile_name
        logger.info(f"[SoundRouter] Switched to profile: {profile_name}")

    def set_override(self, topic: str, profile_dict: dict) -> None:
        """Set a per-topic sound override (from the EventSoundMap UI)."""
        self._overrides[topic] = profile_dict
        logger.info(f"[SoundRouter] Override set for topic: {topic}")

    def clear_override(self, topic: str) -> None:
        """Remove a per-topic override."""
        self._overrides.pop(topic, None)

    def get_all_overrides(self) -> dict:
        """Return all current per-topic overrides."""
        return dict(self._overrides)

    def route(self, topic: str, priority: int) -> dict:
        """
        Resolve a topic to a sound profile dict.

        Returns a serializable dict of SoundProfile.
        """
        # 1. Per-topic override (highest priority)
        if topic in self._overrides:
            return self._overrides[topic]

        # 2. Active profile map
        profile_map = get_profile_map(self._active_profile)
        profile: Optional[SoundProfile] = profile_map.get(topic)

        if profile:
            return profile.to_dict()

        # 3. Fallback generic profile based on priority
        logger.debug(
            f"[SoundRouter] No specific profile for '{topic}' "
            f"— using generic fallback (priority={priority})"
        )
        return self._FALLBACK_PROFILES.get(
            priority,
            self._FALLBACK_PROFILES[AudioPriority.INFORMATIONAL]
        )

    def get_full_event_map(self) -> list[dict]:
        """
        Return complete event → sound mapping for the active profile.
        Used by the EventSoundMap UI page.
        """
        profile_map = get_profile_map(self._active_profile)
        result = []
        for topic, profile in profile_map.items():
            entry = profile.to_dict()
            entry["topic"] = topic
            entry["has_override"] = topic in self._overrides
            result.append(entry)
        return result
