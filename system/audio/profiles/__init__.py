"""
bunyanx NGFW — Audio Profiles Package
=========================================
Registry of all sound profiles.
"""

from system.audio.profiles.default import DEFAULT_PROFILE_MAP
from system.audio.profiles.night   import NIGHT_PROFILE_MAP
from system.audio.profiles.silent  import SILENT_PROFILE_MAP

PROFILE_REGISTRY: dict[str, dict] = {
    "default": DEFAULT_PROFILE_MAP,
    "night":   NIGHT_PROFILE_MAP,
    "silent":  SILENT_PROFILE_MAP,
}


def get_profile_map(profile_name: str) -> dict:
    """Return the sound profile map for a given profile name."""
    return PROFILE_REGISTRY.get(profile_name, DEFAULT_PROFILE_MAP)


__all__ = ["PROFILE_REGISTRY", "get_profile_map",
           "DEFAULT_PROFILE_MAP", "NIGHT_PROFILE_MAP", "SILENT_PROFILE_MAP"]
