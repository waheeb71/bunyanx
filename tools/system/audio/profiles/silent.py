"""
bunyanx NGFW — Silent Sound Profile
========================================
Visual-only mode: all audio playback is disabled.
Events are still delivered to the frontend as notifications
(visual flashes / toast messages) but no sounds are played.

Emergency (Level 6) overrides silent mode for sound.
"""

import copy
from system.audio.profiles.default import DEFAULT_PROFILE_MAP
from system.audio.schemas import AudioPriority

SILENT_PROFILE_MAP = {}

for topic, profile in DEFAULT_PROFILE_MAP.items():
    p = copy.deepcopy(profile)

    if p.priority < AudioPriority.EMERGENCY:
        # Mark as silent — frontend will show visual-only notification
        p.silent = True
        for tone in p.tones:
            tone.volume = 0.0

    # Emergency (Level 6) plays even in silent mode
    SILENT_PROFILE_MAP[topic] = p
