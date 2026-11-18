"""
bunyanx NGFW — Native Sound Player (Server-Side Speaker Playback)
==================================================================
Plays alert MP3 files directly on the Windows server host machine's
default audio output (speakers) using PowerShell's Windows Media Player
COM interface.

Audio file path resolution (in priority order):
  1. NGFW_AUDIO_DIR env var        ← explicit override
  2. NGFW_VAR_DIR/audio/alerts     ← if NGFW_VAR_DIR is set
  3. <project_root>/var/audio/alerts ← auto-detected from __file__ (default)

The project root is the directory containing this file at:
  system/audio/native_player.py  →  ../../  =  project root
"""

import os
import json
import logging
import subprocess
from typing import Optional
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Path Resolution ────────────────────────────────────────────────────
# Auto-detect project root from this file's location:
#   native_player.py lives at  <project_root>/system/audio/native_player.py
#   so project root is         <project_root> = parent.parent.parent
_THIS_FILE   = Path(__file__).resolve()
_PROJECT_ROOT = _THIS_FILE.parent.parent.parent   # system/audio/native_player.py → root

def _resolve_alerts_dir() -> Path:
    """
    Resolve the audio alerts directory in priority order:
      1. NGFW_AUDIO_DIR            — explicit full path override
      2. NGFW_VAR_DIR/audio/alerts — if NGFW_VAR_DIR is set (e.g. /var/lib/ngfw)
      3. <project_root>/var/audio/alerts — always correct auto-detection
    """
    # 1. Explicit override
    if os.environ.get("NGFW_AUDIO_DIR"):
        return Path(os.environ["NGFW_AUDIO_DIR"])

    # 2. NGFW_VAR_DIR (the parent "var" directory, NOT the data dir)
    if os.environ.get("NGFW_VAR_DIR"):
        return Path(os.environ["NGFW_VAR_DIR"]) / "audio" / "alerts"

    # 3. Auto-detect from project root (works on Windows dev AND Linux production
    #    as long as the project is cloned/deployed with its var/ directory)
    return _PROJECT_ROOT / "var" / "audio" / "alerts"

ALERTS_DIR    = _resolve_alerts_dir()
MANIFEST_PATH = ALERTS_DIR / "manifest.json"

logger.debug(f"[NativePlayer] Audio alerts directory: {ALERTS_DIR}")


class NativePlayer:
    _manifest: dict = {}
    _manifest_loaded: bool = False

    # ── Manifest ──────────────────────────────────────────────────────

    @classmethod
    def _ensure_alerts_dir(cls) -> None:
        """Ensure the audio/alerts directory exists."""
        if not ALERTS_DIR.exists():
            try:
                ALERTS_DIR.mkdir(parents=True, exist_ok=True)
                logger.info(f"[NativePlayer] Created audio alerts directory: {ALERTS_DIR}")
            except Exception as e:
                logger.error(f"[NativePlayer] Failed to create audio alerts directory: {e}")

    @classmethod
    def _load_manifest(cls) -> None:
        cls._ensure_alerts_dir()
        if cls._manifest_loaded:
            return
        if MANIFEST_PATH.exists():
            try:
                with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
                    cls._manifest = json.load(f)
                cls._manifest_loaded = True
                logger.info(
                    f"[NativePlayer] Manifest loaded from {MANIFEST_PATH}: "
                    f"{len(cls._manifest)} entries"
                )
            except Exception as e:
                logger.error(f"[NativePlayer] Failed to load manifest: {e}")
        else:
            logger.warning(f"[NativePlayer] Manifest not found at {MANIFEST_PATH}")

    @classmethod
    def reload_manifest(cls) -> None:
        """Force-reload manifest from disk (e.g., after user uploads new files)."""
        cls._manifest_loaded = False
        cls._load_manifest()

    # ── Playback ──────────────────────────────────────────────────────

    @classmethod
    def _resolve_filepath(cls, sound_id: str, priority: int) -> Optional[Path]:
        """
        Resolve sound_id to an MP3 file path.

        Lookup order:
          1. Exact match from manifest (supports arrays for random pick)
          2. Priority-generic fallback: p{N}_generic.mp3 (N = 3..6)
          3. Absolute fallback: p3_generic.mp3
        """
        cls._load_manifest()

        # 1. Try manifest lookup
        entry = cls._manifest.get(sound_id)
        filename = None
        if isinstance(entry, list) and entry:
            import random
            filename = random.choice(entry)
        elif isinstance(entry, str):
            filename = entry

        if filename:
            fp = ALERTS_DIR / filename
            if fp.exists():
                return fp
            logger.warning(
                f"[NativePlayer] Manifest entry '{filename}' for '{sound_id}' "
                f"not found on disk — falling back to generic"
            )

        # 2. Priority-generic fallback
        gen_p = min(6, max(3, priority))
        generic_fp = ALERTS_DIR / f"p{gen_p}_generic.mp3"
        if generic_fp.exists():
            return generic_fp

        # 3. Absolute fallback
        fallback_fp = ALERTS_DIR / "p3_generic.mp3"
        if fallback_fp.exists():
            return fallback_fp

        return None

    @classmethod
    def play_sound(cls, sound_id: str, priority: int, volume: float = 1.0) -> None:
        """
        Play an alert sound on the server's default audio output.

        Uses PowerShell + Windows Media Player COM interface.
        Runs asynchronously (subprocess.Popen) — does not block the caller.

        Args:
            sound_id:  Event sound identifier (e.g. "threat_detected")
            priority:  Audio priority level (1-6), used for generic fallback
            volume:    Playback volume 0.0–1.0
        """
        filepath = cls._resolve_filepath(sound_id, priority)

        if not filepath:
            logger.warning(
                f"[NativePlayer] No audio file found for sound_id='{sound_id}' "
                f"priority={priority} — checked {ALERTS_DIR}"
            )
            return

        # Clamp volume to valid range
        volume = max(0.0, min(1.0, volume))

        # Escape single quotes in path for PowerShell
        filepath_str = str(filepath.resolve()).replace("'", "''")
        logger.info(f"[NativePlayer] ▶ {filepath.name} (vol={volume:.0%})")

        # PowerShell: load assembly → create player → open → set volume → play → sleep 8s
        ps_cmd = (
            f"[void][System.Reflection.Assembly]::LoadWithPartialName('PresentationCore'); "
            f"$p = New-Object System.Windows.Media.MediaPlayer; "
            f"$p.Open('{filepath_str}'); "
            f"$p.Volume = {volume}; "
            f"$p.Play(); "
            f"Start-Sleep -Seconds 8"
        )

        try:
            subprocess.Popen(
                ["powershell", "-Command", ps_cmd],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as e:
            logger.error(f"[NativePlayer] Failed to start PowerShell playback: {e}")

    @classmethod
    def speak_text(cls, text: str) -> None:
        """
        Speak Arabic/English text via Windows TTS (SpeechSynthesizer).
        Runs asynchronously — does not block the caller.
        """
        if not text:
            return
        logger.info(f"[NativePlayer] 🔊 TTS: {text}")
        text_escaped = text.replace("'", "''")
        ps_cmd = (
            f"Add-Type -AssemblyName System.Speech; "
            f"$s = New-Object System.Speech.Synthesis.SpeechSynthesizer; "
            f"$s.Speak('{text_escaped}')"
        )
        try:
            subprocess.Popen(
                ["powershell", "-Command", ps_cmd],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as e:
            logger.error(f"[NativePlayer] Failed to speak TTS: {e}")

    # ── Diagnostics ───────────────────────────────────────────────────

    @classmethod
    def get_status(cls) -> dict:
        """Return diagnostic info for the audio system."""
        cls._load_manifest()
        files = list(ALERTS_DIR.glob("*.mp3")) if ALERTS_DIR.exists() else []
        return {
            "alerts_dir":       str(ALERTS_DIR),
            "alerts_dir_exists": ALERTS_DIR.exists(),
            "manifest_loaded":  cls._manifest_loaded,
            "manifest_entries": len(cls._manifest),
            "mp3_count":        len(files),
            "mp3_files":        [f.name for f in sorted(files)],
        }
