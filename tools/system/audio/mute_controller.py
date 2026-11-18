"""
bunyanx NGFW — Audio Alert System: Mute Controller
======================================================
Manages all mute/volume state for the audio alert system.

Features:
  - Global mute
  - Timed mute (auto-expiring)
  - Role-based audio suppression
  - Day/Night mode auto-scheduling
  - Volume control
  - Settings persistence to var/audio_settings.json
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

from system.audio.schemas import AudioPriority, AudioSettings

logger = logging.getLogger(__name__)

# ── Settings File Path ─────────────────────────────────────────────────
# Auto-detect from project root (same logic as NativePlayer):
#   mute_controller.py lives at <project_root>/system/audio/mute_controller.py
#   Settings file:              <project_root>/var/audio_settings.json
_THIS_FILE    = Path(__file__).resolve()
_PROJECT_ROOT = _THIS_FILE.parent.parent.parent

def _resolve_settings_path() -> Path:
    """
    Resolve settings file path in priority order:
      1. NGFW_VAR_DIR/audio_settings.json  — if NGFW_VAR_DIR is set
      2. <project_root>/var/audio_settings.json — auto-detected (default)
    """
    if os.environ.get("NGFW_VAR_DIR"):
        return Path(os.environ["NGFW_VAR_DIR"]) / "audio_settings.json"
    return _PROJECT_ROOT / "var" / "audio_settings.json"

_SETTINGS_PATH = _resolve_settings_path()


class MuteController:
    """
    Controls mute state, volume, and role-based audio filtering.
    All state is persisted to disk and reloaded on startup.
    """

    def __init__(self):
        self._settings = AudioSettings()
        self._lock     = asyncio.Lock()
        self._scheduler_task: Optional[asyncio.Task] = None

    # ── Lifecycle ─────────────────────────────────────────────────

    async def start(self) -> None:
        """Load settings from disk and start the auto-scheduler."""
        await self._load_settings()
        self._scheduler_task = asyncio.create_task(self._auto_scheduler())
        logger.info("[AudioMute] MuteController started")

    async def stop(self) -> None:
        """Cancel the scheduler task."""
        if self._scheduler_task:
            self._scheduler_task.cancel()
            try:
                await self._scheduler_task
            except asyncio.CancelledError:
                pass
        logger.info("[AudioMute] MuteController stopped")

    # ── Mute Control ──────────────────────────────────────────────

    async def is_muted(self) -> bool:
        """Check if audio is currently muted (global or timed)."""
        async with self._lock:
            if not self._settings.enabled:
                return True
            if self._settings.muted:
                # Check if timed mute has expired
                if self._settings.mute_until:
                    try:
                        until = datetime.fromisoformat(self._settings.mute_until)
                        if datetime.now(timezone.utc) >= until:
                            # Auto-unmute
                            self._settings.muted = False
                            self._settings.mute_until = None
                            await self._save_settings()
                            logger.info("[AudioMute] Timed mute expired — unmuted")
                            return False
                    except Exception:
                        pass
                return True
            return False

    async def mute(self, duration_minutes: Optional[int] = None) -> None:
        """
        Mute audio.
        If duration_minutes is given, auto-unmute after that period.
        """
        async with self._lock:
            self._settings.muted = True
            if duration_minutes:
                until = datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)
                self._settings.mute_until = until.isoformat()
                logger.info(f"[AudioMute] Timed mute for {duration_minutes}m until {until}")
            else:
                self._settings.mute_until = None
                logger.info("[AudioMute] Global mute enabled")
            await self._save_settings()

    async def unmute(self) -> None:
        """Unmute audio."""
        async with self._lock:
            self._settings.muted     = False
            self._settings.mute_until = None
            logger.info("[AudioMute] Unmuted")
            await self._save_settings()

    async def toggle_mute(self) -> bool:
        """Toggle mute state. Returns new muted state."""
        if await self.is_muted():
            await self.unmute()
            return False
        else:
            await self.mute()
            return True

    # ── Volume Control ────────────────────────────────────────────

    async def get_volume(self) -> float:
        """Return current volume (0.0 – 1.0)."""
        async with self._lock:
            return self._settings.volume

    async def set_volume(self, level: float) -> None:
        """Set volume level (0.0 – 1.0)."""
        level = max(0.0, min(1.0, level))
        async with self._lock:
            self._settings.volume = level
            await self._save_settings()
        logger.info(f"[AudioMute] Volume set to {level:.0%}")

    # ── Role-Based Filtering ──────────────────────────────────────

    async def is_allowed_for_role(self, role: str, priority: int) -> bool:
        """
        Check if a user role is allowed to hear this priority level.
        Each role has a max_priority cap.
        """
        async with self._lock:
            max_p = self._settings.role_max_priority.get(role, 6)
            return priority <= max_p

    async def set_role_max_priority(self, role: str, max_priority: int) -> None:
        """Configure maximum audio priority level for a role."""
        async with self._lock:
            self._settings.role_max_priority[role] = max_priority
            await self._save_settings()

    # ── Profile / Theme ───────────────────────────────────────────

    async def get_profile(self) -> str:
        """Return current sound profile name."""
        async with self._lock:
            return self._settings.profile

    async def set_profile(self, profile: str) -> None:
        """Set sound profile ('default', 'night', 'silent')."""
        async with self._lock:
            self._settings.profile = profile
            await self._save_settings()
        logger.info(f"[AudioMute] Sound profile switched to '{profile}'")

    # ── Settings Access ───────────────────────────────────────────

    async def get_settings(self) -> AudioSettings:
        """Return a copy of current settings."""
        async with self._lock:
            return AudioSettings(**self._settings.to_dict())

    async def update_settings(self, updates: dict) -> AudioSettings:
        """Apply a partial settings update dict."""
        async with self._lock:
            current = self._settings.to_dict()
            current.update({k: v for k, v in updates.items()
                            if k in current and k not in ("role_max_priority",)})
            # Handle nested dict
            if "role_max_priority" in updates:
                current["role_max_priority"].update(updates["role_max_priority"])
            self._settings = AudioSettings(**current)
            await self._save_settings()
        return await self.get_settings()

    # ── Day/Night Auto-Scheduler ──────────────────────────────────

    async def _auto_scheduler(self) -> None:
        """Periodically check if day/night profile switch should occur."""
        while True:
            try:
                await asyncio.sleep(60)  # Check every minute
                async with self._lock:
                    if not self._settings.auto_switch_enabled:
                        continue
                    hour = datetime.now().hour
                    day_h   = self._settings.day_start_hour
                    night_h = self._settings.night_start_hour

                    if day_h < night_h:
                        is_day = day_h <= hour < night_h
                    else:
                        # Overnight schedule (e.g. day starts at 8 AM, night starts at 2 AM)
                        is_day = hour >= day_h or hour < night_h
                    desired = "default" if is_day else "night"

                    if self._settings.profile != desired:
                        self._settings.profile = desired
                        await self._save_settings()
                        logger.info(
                            f"[AudioMute] Auto-switched to '{desired}' profile "
                            f"(hour={hour})"
                        )
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[AudioMute] Scheduler error: {e}")

    # ── Persistence ───────────────────────────────────────────────

    async def _load_settings(self) -> None:
        """Load settings from JSON file. Use defaults if missing."""
        try:
            if _SETTINGS_PATH.exists():
                data = json.loads(_SETTINGS_PATH.read_text(encoding="utf-8"))
                # Merge with defaults to handle new fields gracefully
                defaults = AudioSettings().to_dict()
                defaults.update(data)
                if isinstance(defaults.get("role_max_priority"), dict):
                    self._settings = AudioSettings(**defaults)
                else:
                    self._settings = AudioSettings()
                logger.info(f"[AudioMute] Loaded settings from {_SETTINGS_PATH}")
            else:
                self._settings = AudioSettings()
                await self._save_settings()
                logger.info("[AudioMute] Created default settings file")
        except Exception as e:
            logger.error(f"[AudioMute] Failed to load settings: {e} — using defaults")
            self._settings = AudioSettings()

    async def _save_settings(self) -> None:
        """Persist current settings to JSON file."""
        try:
            _SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
            _SETTINGS_PATH.write_text(
                json.dumps(self._settings.to_dict(), indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception as e:
            logger.error(f"[AudioMute] Failed to save settings: {e}")
