"""
bunyanx NGFW — Night Mode Sound Profile
============================================
Quieter, softer sounds for overnight SOC operations.
Inherits from default but reduces volume & repeat counts.
Only Critical and Emergency sounds play at full intensity.
"""

import copy
from system.audio.profiles.default import DEFAULT_PROFILE_MAP
from system.audio.schemas import AudioPriority

# Deep-copy default map and apply night-mode overrides
NIGHT_PROFILE_MAP = {}

for topic, profile in DEFAULT_PROFILE_MAP.items():
    p = copy.deepcopy(profile)

    if p.priority <= AudioPriority.NOTICE:
        # Informational & Notice: reduce volume significantly, no repeats
        for tone in p.tones:
            tone.volume = max(0.1, tone.volume * 0.35)
        p.repeat = 1

    elif p.priority == AudioPriority.WARNING:
        # Warning: moderate reduction
        for tone in p.tones:
            tone.volume = max(0.2, tone.volume * 0.5)
        p.repeat = 1

    elif p.priority == AudioPriority.SECURITY_ALERT:
        # Security Alert: slight reduction, limit repeats
        for tone in p.tones:
            tone.volume = max(0.35, tone.volume * 0.65)
        p.repeat = min(p.repeat, 2)

    elif p.priority == AudioPriority.CRITICAL:
        # Critical: mild reduction, limit repeats
        for tone in p.tones:
            tone.volume = max(0.5, tone.volume * 0.75)
        p.repeat = min(p.repeat, 3)

    # Emergency (Level 6): unchanged — always full intensity

    NIGHT_PROFILE_MAP[topic] = p
