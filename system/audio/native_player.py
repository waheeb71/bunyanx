"""
bunyanx NGFW — Native Sound Player (Server-Side Speaker Playback)
==================================================================

Plays alert MP3 and WAV files directly on the host machine's default
audio output (speakers) on Linux (Ubuntu/Debian/RHEL) and Windows.

Linux Audio Architecture:
  - PipeWire (pw-play) → Ubuntu 22.04 / 24.04+ default
  - PulseAudio (paplay for WAV, mpg123 for MP3)
  - ALSA direct (aplay for WAV, mpg123 -o alsa for MP3)
  - FFmpeg (ffplay -nodisp -autoexit)
  - Headless VLC (cvlc) / SoX (play)

Audio file path resolution:
  1. NGFW_AUDIO_DIR env var          ← explicit override
  2. NGFW_VAR_DIR/audio/alerts       ← if NGFW_VAR_DIR is set
  3. <project_root>/var/audio/alerts ← auto-detected from __file__ (default)
"""

import os
import sys
import json
import random
import shutil
import logging
import subprocess
import threading
from typing import Optional, List
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Path Resolution ────────────────────────────────────────────────────
_THIS_FILE    = Path(__file__).resolve()
_PROJECT_ROOT = _THIS_FILE.parent.parent.parent


def _resolve_alerts_dir() -> Path:
    """Resolve the audio alerts directory (called lazily on first use)."""
    if os.environ.get("NGFW_AUDIO_DIR"):
        return Path(os.environ["NGFW_AUDIO_DIR"])
    if os.environ.get("NGFW_VAR_DIR"):
        return Path(os.environ["NGFW_VAR_DIR"]) / "audio" / "alerts"
    return _PROJECT_ROOT / "var" / "audio" / "alerts"


ALERTS_DIR    = _resolve_alerts_dir()
MANIFEST_PATH = ALERTS_DIR / "manifest.json"


class NativePlayer:
    _manifest: dict = {}
    _manifest_loaded: bool = False
    _alerts_dir_cache: Optional[Path] = None
    _tones_enabled: bool = True
    _manifest_mtime: float = 0.0

    @classmethod
    def _alerts_dir(cls) -> Path:
        """Lazy path accessor — resolves on first call."""
        if cls._alerts_dir_cache is None:
            cls._alerts_dir_cache = _resolve_alerts_dir()
            logger.info(f"[NativePlayer] Audio alerts directory: {cls._alerts_dir_cache}")
        return cls._alerts_dir_cache

    # ── Manifest ──────────────────────────────────────────────────────

    @classmethod
    def _ensure_alerts_dir(cls) -> None:
        """Ensure the audio/alerts directory exists."""
        alerts_dir = cls._alerts_dir()
        if not alerts_dir.exists():
            try:
                alerts_dir.mkdir(parents=True, exist_ok=True)
                logger.info(f"[NativePlayer] Created audio alerts directory: {alerts_dir}")
            except Exception as e:
                logger.error(f"[NativePlayer] Failed to create audio alerts directory: {e}")

    @classmethod
    def set_tones_enabled(cls, enabled: bool) -> None:
        """Enable or disable alert tone playback globally."""
        cls._tones_enabled = enabled
        state = "enabled" if enabled else "disabled"
        logger.info(f"[NativePlayer] Alert tones {state} by operator")

    @classmethod
    def get_tones_enabled(cls) -> bool:
        return cls._tones_enabled

    @classmethod
    def _load_manifest(cls) -> None:
        cls._ensure_alerts_dir()
        manifest_path = cls._alerts_dir() / "manifest.json"
        if manifest_path.exists():
            try:
                mtime = manifest_path.stat().st_mtime
                if cls._manifest_loaded and mtime == cls._manifest_mtime:
                    return
                with open(manifest_path, "r", encoding="utf-8") as f:
                    cls._manifest = json.load(f)
                cls._manifest_loaded = True
                cls._manifest_mtime = mtime
                logger.info(
                    f"[NativePlayer] Manifest loaded/refreshed from {manifest_path}: "
                    f"{len(cls._manifest)} entries"
                )
            except Exception as e:
                logger.error(f"[NativePlayer] Failed to load manifest: {e}")
        else:
            logger.warning(f"[NativePlayer] Manifest not found at {manifest_path}")

    @classmethod
    def reload_manifest(cls) -> None:
        """Force-reload manifest from disk."""
        cls._manifest_loaded = False
        cls._alerts_dir_cache = None
        cls._load_manifest()

    # ── Playback Resolution ───────────────────────────────────────────

    @classmethod
    def _resolve_filepath(cls, sound_id: str, priority: int) -> Optional[Path]:
        """
        Resolve sound_id to an existing WAV or MP3 audio file path.
        Selects randomly when multiple candidate files exist.
        """
        cls._load_manifest()
        alerts_dir = cls._alerts_dir()

        # Keys to try in manifest: exact, dotted, underscored, lowercase
        candidates_keys = [
            sound_id,
            sound_id.replace(".", "_"),
            sound_id.replace("_", "."),
            sound_id.lower(),
            sound_id.lower().replace(".", "_"),
            sound_id.lower().replace("_", "."),
        ]

        entry = None
        for k in candidates_keys:
            if k in cls._manifest:
                entry = cls._manifest[k]
                break

        if entry:
            if isinstance(entry, list) and entry:
                # Find all listed files that actually exist on disk
                existing = [alerts_dir / f for f in entry if (alerts_dir / f).is_file()]
                if existing:
                    return random.choice(existing)
            elif isinstance(entry, str):
                fp = alerts_dir / entry
                if fp.is_file():
                    return fp

        # Fallback 1: Try direct file named sound_id.wav or sound_id.mp3
        clean_name = sound_id.replace(".", "_")
        for ext in (".wav", ".mp3"):
            direct_fp = alerts_dir / f"{clean_name}{ext}"
            if direct_fp.is_file():
                return direct_fp

        # Fallback 2: Priority-generic fallback: p{N}_generic.wav / p{N}_generic.mp3
        gen_p = min(6, max(3, priority))
        generic_candidates = [
            alerts_dir / f"p{gen_p}_generic.wav",
            alerts_dir / f"p{gen_p}_generic.mp3",
        ]
        existing_generic = [fp for fp in generic_candidates if fp.is_file()]
        if existing_generic:
            return random.choice(existing_generic)

        # Fallback 3: Absolute fallback
        abs_fallbacks = [
            alerts_dir / "p3_generic.wav",
            alerts_dir / "p3_generic.mp3",
        ]
        existing_abs = [fp for fp in abs_fallbacks if fp.is_file()]
        if existing_abs:
            return random.choice(existing_abs)

        return None

    # ── Linux / Ubuntu Player Engine ──────────────────────────────────

    @classmethod
    def _pulse_env(cls) -> dict:
        """Build subprocess environment with detected PulseAudio / PipeWire socket."""
        import glob
        env = os.environ.copy()
        if env.get("PULSE_SERVER"):
            return env

        candidates = []
        try:
            uid = os.getuid()
            candidates.append(f"/run/user/{uid}/pulse/native")
            candidates.append(f"/run/user/{uid}/pulse.native")
        except AttributeError:
            pass

        candidates += sorted(glob.glob("/run/user/*/pulse/native"))
        candidates += sorted(glob.glob("/run/user/*/pulse.native"))
        candidates += ["/run/pulse/native"]
        candidates += sorted(glob.glob("/tmp/pulse-*/native"))

        for sock in candidates:
            if os.path.exists(sock):
                env["PULSE_SERVER"]       = f"unix:{sock}"
                env["PULSE_RUNTIME_PATH"] = os.path.dirname(sock)
                xdg = os.path.dirname(os.path.dirname(sock))
                if os.path.isdir(xdg):
                    env.setdefault("XDG_RUNTIME_DIR", xdg)
                return env

        return env

    @classmethod
    def _pulse_is_alive(cls, env: dict) -> bool:
        """Check if PulseAudio / PipeWire daemon is responding."""
        pactl = shutil.which("pactl")
        if not pactl:
            return False
        try:
            r = subprocess.run(
                [pactl, "info"],
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=1,
            )
            return r.returncode == 0
        except Exception:
            return False

    @classmethod
    def _find_alsa_devices(cls) -> list:
        """Find available ALSA devices."""
        devices = ["default"]
        try:
            r = subprocess.run(
                ["aplay", "-l"], capture_output=True, text=True, timeout=1
            )
            for line in r.stdout.splitlines():
                if line.startswith("card "):
                    parts = line.split(":")
                    card_num = parts[0].split()[1]
                    plug = f"plughw:{card_num},0"
                    if plug not in devices:
                        devices.append(plug)
        except Exception:
            pass
        return devices

    @classmethod
    def _try_play_async(cls, cmd: List[str], env: dict, label: str) -> bool:
        """
        Launch playback command asynchronously with zero delay.
        Monitors completion in a lightweight background thread.
        """
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=env,
            )
            # Immediate check to catch instant command failure (e.g. missing shared lib)
            rc = proc.poll()
            if rc is not None and rc != 0:
                logger.debug(f"[NativePlayer] {label} failed immediately (rc={rc})")
                return False

            threading.Thread(
                target=cls._watch_proc, args=(proc, label), daemon=True
            ).start()
            logger.info(f"[NativePlayer] ▶ {label} playing: {' '.join(cmd[:3])}")
            return True
        except Exception as e:
            logger.debug(f"[NativePlayer] {label} launch error: {e}")
            return False

    @classmethod
    def _watch_proc(cls, proc, name: str) -> None:
        """Watch background playback process without blocking caller."""
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            try:
                proc.terminate()
            except Exception:
                pass
        except Exception:
            pass

    @classmethod
    def _play_linux(cls, filepath: Path, volume: float) -> None:
        """
        Play audio file (WAV or MP3) on Linux/Ubuntu.
        Uses format-aware, low-latency player detection.
        """
        gain      = int(volume * 100)
        pulse_vol = int(volume * 65536)
        fpath     = str(filepath.resolve())
        suffix    = filepath.suffix.lower()
        is_wav    = (suffix == ".wav")
        env_pulse = cls._pulse_env()
        pulse_ok  = cls._pulse_is_alive(env_pulse)

        # ── 1. For WAV files: Use fast kernel/audio-daemon players ──
        if is_wav:
            # 1a. PipeWire pw-play (perfect low latency for WAV)
            if shutil.which("pw-play"):
                cmd = ["pw-play", f"--volume={volume:.2f}", fpath]
                if cls._try_play_async(cmd, env_pulse, "pw-play-wav"):
                    return

            # 1b. PulseAudio paplay
            if pulse_ok and shutil.which("paplay"):
                cmd = ["paplay", f"--volume={pulse_vol}", "--property=media.role=event", fpath]
                if cls._try_play_async(cmd, env_pulse, "paplay-wav"):
                    return

            # 1c. ALSA aplay
            if shutil.which("aplay"):
                for dev in cls._find_alsa_devices()[:2]:
                    cmd = ["aplay", "-q", "-D", dev, fpath]
                    if cls._try_play_async(cmd, os.environ.copy(), f"aplay-{dev}"):
                        return
                cmd = ["aplay", "-q", fpath]
                if cls._try_play_async(cmd, os.environ.copy(), "aplay-default"):
                    return

        # ── 2. For MP3 files: Use dedicated MP3 decoders ──
        else:
            # 2a. mpg123 / mpg321 (instant hardware MP3 decoder)
            for p in ("mpg123", "mpg321"):
                if shutil.which(p):
                    cmd = [p, "-q", "-g", str(gain), fpath]
                    if cls._try_play_async(cmd, env_pulse, f"{p}-auto"):
                        return
                    for dev in cls._find_alsa_devices()[:2]:
                        cmd = [p, "-q", "-o", "alsa", "-a", dev, "-g", str(gain), fpath]
                        if cls._try_play_async(cmd, os.environ.copy(), f"{p}-alsa"):
                            return
                    break

            # 2b. FFplay (handles all MP3 files)
            if shutil.which("ffplay"):
                cmd = ["ffplay", "-nodisp", "-autoexit", "-loglevel", "error", "-volume", str(gain), fpath]
                if cls._try_play_async(cmd, env_pulse, "ffplay-mp3"):
                    return

            # 2c. If MP3 decoder not installed, check if sibling .wav exists on disk and play it!
            sibling_wav = filepath.with_suffix(".wav")
            if sibling_wav.is_file():
                logger.info(f"[NativePlayer] Falling back from MP3 to pristine WAV sibling: {sibling_wav.name}")
                cls._play_linux(sibling_wav, volume)
                return

        # ── 3. Universal Fallbacks (ffplay / play / cvlc) ──
        if shutil.which("ffplay"):
            cmd = ["ffplay", "-nodisp", "-autoexit", "-loglevel", "error", "-volume", str(gain), fpath]
            if cls._try_play_async(cmd, env_pulse, "ffplay"):
                return

        if shutil.which("play"):
            cmd = ["play", "-q", "-v", f"{volume:.2f}", fpath]
            if cls._try_play_async(cmd, env_pulse, "sox-play"):
                return

        if shutil.which("cvlc"):
            cmd = ["cvlc", "--intf", "dummy", "--play-and-exit", fpath]
            if cls._try_play_async(cmd, env_pulse, "cvlc"):
                return

        logger.error(
            f"[NativePlayer] Playback failed for '{filepath.name}' on Linux. "
            "Ensure pulseaudio/pipewire/alsa or ffmpeg/mpg123 is installed."
        )

    # ── Windows Player Engine ─────────────────────────────────────────

    @classmethod
    def _play_windows(cls, filepath: Path, volume: float) -> None:
        """Play MP3 / WAV on Windows using PowerShell asynchronously."""
        filepath_str = str(filepath.resolve()).replace("'", "''")
        suffix = filepath.suffix.lower()

        if suffix == ".wav":
            ps_cmd = (
                f"$p = New-Object System.Media.SoundPlayer; "
                f"$p.SoundLocation = '{filepath_str}'; "
                f"$p.Play(); "
                f"Start-Sleep -Seconds 5"
            )
        else:
            ps_cmd = (
                f"[void][System.Reflection.Assembly]::LoadWithPartialName('PresentationCore'); "
                f"$p = New-Object System.Windows.Media.MediaPlayer; "
                f"$p.Open([System.Uri]'{filepath_str}'); "
                f"$p.Volume = {volume}; "
                f"$p.Play(); "
                f"Start-Sleep -Seconds 6"
            )

        try:
            subprocess.Popen(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as e:
            logger.error(f"[NativePlayer] PowerShell playback failed: {e}")

    # ── Public Play API ───────────────────────────────────────────────

    @classmethod
    def play_sound(cls, sound_id: str, priority: int, volume: float = 1.0) -> None:
        """
        Play an alert sound on the server's default audio output.
        Cross-platform (Linux / Ubuntu / Windows) and non-blocking.
        """
        if not cls._tones_enabled:
            logger.debug(f"[NativePlayer] Tones disabled — skipping '{sound_id}'")
            return

        filepath = cls._resolve_filepath(sound_id, priority)
        if not filepath:
            logger.warning(
                f"[NativePlayer] No audio file found for sound_id='{sound_id}' "
                f"priority={priority} — checked {cls._alerts_dir()}"
            )
            return

        volume = max(0.0, min(1.0, volume))
        logger.info(f"[NativePlayer] 🔔 Playing {filepath.name} for '{sound_id}' (vol={volume:.0%})")

        if sys.platform == "win32":
            cls._play_windows(filepath, volume)
        else:
            cls._play_linux(filepath, volume)

    # ── Text-to-Speech Engine ─────────────────────────────────────────

    @classmethod
    def speak_text(cls, text: str) -> None:
        """Speak text aloud (Arabic / English) via system TTS engine."""
        if not text:
            return
        logger.info(f"[NativePlayer] 🗣 TTS: {text}")

        if sys.platform == "win32":
            text_escaped = text.replace("'", "''")
            ps_cmd = (
                f"Add-Type -AssemblyName System.Speech; "
                f"$s = New-Object System.Speech.Synthesis.SpeechSynthesizer; "
                f"$s.Speak('{text_escaped}')"
            )
            try:
                subprocess.Popen(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except Exception as e:
                logger.error(f"[NativePlayer] Windows TTS error: {e}")
        else:
            tts_cmd = None
            if shutil.which("spd-say"):
                tts_cmd = ["spd-say", "-l", "ar", text]
            elif shutil.which("espeak-ng"):
                tts_cmd = ["espeak-ng", "-v", "ar", text]
            elif shutil.which("espeak"):
                tts_cmd = ["espeak", text]
            elif shutil.which("festival"):
                tts_cmd = ["festival", "--tts"]

            if tts_cmd:
                try:
                    if "festival" in tts_cmd:
                        proc = subprocess.Popen(
                            tts_cmd,
                            stdin=subprocess.PIPE,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
                        proc.communicate(input=text.encode())
                    else:
                        subprocess.Popen(
                            tts_cmd,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
                except Exception as e:
                    logger.error(f"[NativePlayer] Linux TTS error: {e}")

    # ── Diagnostics ───────────────────────────────────────────────────

    @classmethod
    def get_status(cls) -> dict:
        """Return diagnostic information for the audio system."""
        cls._load_manifest()
        alerts_dir = cls._alerts_dir()
        mp3_files = list(alerts_dir.glob("*.mp3")) if alerts_dir.exists() else []
        wav_files = list(alerts_dir.glob("*.wav")) if alerts_dir.exists() else []
        all_files = mp3_files + wav_files

        if sys.platform == "win32":
            player_info = "powershell (Windows Media Player / SoundPlayer)"
        else:
            candidates = [p for p in ("pw-play", "paplay", "mpg123", "aplay", "ffplay", "cvlc", "play") if shutil.which(p)]
            player_info = ", ".join(candidates) if candidates else "none — install ffmpeg, mpg123, or pulseaudio-utils"

        return {
            "platform":          sys.platform,
            "audio_player":      player_info,
            "alerts_dir":        str(alerts_dir),
            "alerts_dir_exists": alerts_dir.exists(),
            "manifest_loaded":   cls._manifest_loaded,
            "manifest_entries":  len(cls._manifest),
            "file_count":        len(all_files),
            "mp3_count":         len(mp3_files),
            "wav_count":         len(wav_files),
            "audio_files":       [f.name for f in sorted(all_files)],
        }
