"""
bunyanx NGFW — Audio Alert System: Schemas
==============================================
Strongly-typed dataclasses for all audio alert payloads.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional, List
import uuid


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _uid() -> str:
    return str(uuid.uuid4())


# ──────────────────────────────────────────────────────────────────────
# Priority Levels
# ──────────────────────────────────────────────────────────────────────

class AudioPriority:
    """Priority levels for audio alerts. Higher = more urgent."""
    INFORMATIONAL   = 1   # Routine info — soft blip, single play
    NOTICE          = 2   # Notable event — chime, single play
    WARNING         = 3   # Attention needed — double beep
    SECURITY_ALERT  = 4   # Security event — triple alert, repeated
    CRITICAL        = 5   # Critical incident — siren, repeated
    EMERGENCY       = 6   # Emergency — klaxon, repeat until acknowledged

    NAMES = {
        1: "Informational",
        2: "Notice",
        3: "Warning",
        4: "Security Alert",
        5: "Critical Incident",
        6: "Emergency",
    }

    COLORS = {
        1: "#448aff",    # Blue
        2: "#00c8ff",    # Cyan
        3: "#ffab40",    # Amber
        4: "#ff4d6a",    # Red
        5: "#c084fc",    # Purple
        6: "#ff0000",    # Emergency Red
    }

    COOLDOWNS = {
        1: 30,   # seconds
        2: 20,
        3: 10,
        4: 5,
        5: 3,
        6: 0,    # Never suppressed
    }

    STORM_THRESHOLD = {
        1: (3, 30),    # (max events, per N seconds)
        2: (3, 30),
        3: (3, 15),
        4: (5, 30),
        5: (3, 10),
        6: (999, 1),   # Effectively never suppressed
    }


# ──────────────────────────────────────────────────────────────────────
# Waveform / Sound Profile
# ──────────────────────────────────────────────────────────────────────

@dataclass
class ToneConfig:
    """Configuration for a single synthesized tone."""
    frequency_hz: float = 440.0
    duration_ms: int    = 300
    waveform: str       = "sine"       # sine | square | sawtooth | triangle
    volume: float       = 0.6          # 0.0 – 1.0
    # ADSR envelope
    attack_ms: int      = 20
    decay_ms: int       = 50
    sustain_level: float = 0.7
    release_ms: int     = 80


@dataclass
class SoundProfile:
    """Full sound specification for one event type."""
    sound_id: str                        # Unique identifier
    label: str                           # Human-readable name (Arabic or English)
    priority: int = AudioPriority.INFORMATIONAL
    tones: List[ToneConfig] = field(default_factory=list)  # Sequence of tones
    repeat: int  = 1                     # Times to repeat full sequence
    gap_ms: int  = 100                   # Gap between repeats
    # Visual-only flag (for silent profile)
    silent: bool = False
    # ── TTS (Text-to-Speech) — ADDITIVE FEATURE ──────────────────────
    # Optional text to speak aloud after the tone plays.
    # None = no TTS for this event. Supports Arabic and English.
    tts_text: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


# ──────────────────────────────────────────────────────────────────────
# Audio Event (emitted from backend → frontend via SSE)
# ──────────────────────────────────────────────────────────────────────

@dataclass
class AudioNotification:
    """Payload sent to the frontend to trigger a sound."""
    notification_id: str        = field(default_factory=_uid)
    timestamp: str              = field(default_factory=_now)
    event_type: str             = ""      # e.g. "threat.detected"
    source_module: str          = ""      # e.g. "ids_ips"
    priority: int               = 1
    priority_name: str          = "Informational"
    priority_color: str         = "#448aff"
    sound_id: str               = ""
    sound_profile: Optional[dict] = None  # Serialized SoundProfile
    title: str                  = ""
    message: str                = ""
    suppressed: bool            = False   # True = visual only (muted/storm)
    aggregated_count: int       = 1       # >1 = storm aggregation
    # ── TTS — ADDITIVE FEATURE ────────────────────────────────────────
    # Text to speak aloud on the frontend. None = no TTS.
    tts_text: Optional[str]     = None

    def to_dict(self) -> dict:
        return asdict(self)

    def to_sse(self) -> str:
        """Format as Server-Sent Event string."""
        import json
        return f"data: {json.dumps(self.to_dict())}\n\n"


# ──────────────────────────────────────────────────────────────────────
# Audio Settings (persisted)
# ──────────────────────────────────────────────────────────────────────

@dataclass
class AudioSettings:
    """Persisted audio alert system settings."""
    enabled: bool           = True
    volume: float           = 0.7          # 0.0 – 1.0
    muted: bool             = False
    mute_until: Optional[str] = None       # ISO timestamp or None
    profile: str            = "default"    # "default" | "night" | "silent"
    # Day/Night auto-switch
    auto_switch_enabled: bool = False
    day_start_hour: int     = 8            # 08:00
    night_start_hour: int   = 22           # 22:00
    # Role-based: max priority level to play per role
    role_max_priority: dict = field(default_factory=lambda: {
        "admin":    6,
        "analyst":  5,
        "operator": 4,
        "viewer":   2,
    })
    # ── Native Playback (Server-Side) ────────────────────────────────
    # Plays alert MP3s directly on the server host's speakers via PowerShell.
    # When True, audio is played on the firewall machine itself — no browser needed.
    native_playback_enabled: bool = True   # Default: ON (server-side playback)

    # ── TTS Settings — ADDITIVE FEATURE ──────────────────────────────
    tts_enabled: bool       = True         # Master TTS switch
    tts_language: str       = "ar-SA"      # BCP-47 language tag
    tts_rate: float         = 0.95         # Speech rate 0.1 – 2.0
    tts_pitch: float        = 1.0          # Pitch 0.0 – 2.0
    tts_volume: float       = 1.0          # TTS volume 0.0 – 1.0
    tts_min_priority: int   = 3            # Minimum priority to trigger TTS
    tts_muted: bool         = False        # TTS-specific mute (tone still plays)

    def to_dict(self) -> dict:
        return asdict(self)
