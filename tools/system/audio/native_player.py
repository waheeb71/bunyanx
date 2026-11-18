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
import sys
import json
import shutil
import logging
import subprocess
from typing import Optional
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Path Resolution ────────────────────────────────────────────────────
# Project root auto-detected from this file's location:
#   native_player.py  →  <project_root>/system/audio/native_player.py
#   project root      →  parent.parent.parent
_THIS_FILE    = Path(__file__).resolve()
_PROJECT_ROOT = _THIS_FILE.parent.parent.parent

def _resolve_alerts_dir() -> Path:
    """
    Resolve the audio alerts directory (called lazily on first use).

    Priority order:
      1. NGFW_AUDIO_DIR env var              — explicit override
      2. NGFW_VAR_DIR/audio/alerts           — e.g. /var/lib/ngfw/audio/alerts
      3. <project_root>/var/audio/alerts     — auto-detected (default)

    NOTE: Called lazily inside NativePlayer methods so that .env is
    guaranteed to be loaded before the path is resolved.
    """
    if os.environ.get("NGFW_AUDIO_DIR"):
        return Path(os.environ["NGFW_AUDIO_DIR"])
    if os.environ.get("NGFW_VAR_DIR"):
        return Path(os.environ["NGFW_VAR_DIR"]) / "audio" / "alerts"
    return _PROJECT_ROOT / "var" / "audio" / "alerts"

# Module-level reference — updated lazily via NativePlayer._alerts_dir()
# Do NOT use this directly; use NativePlayer._alerts_dir() instead.
ALERTS_DIR    = _resolve_alerts_dir()
MANIFEST_PATH = ALERTS_DIR / "manifest.json"


class NativePlayer:
    _manifest: dict = {}
    _manifest_loaded: bool = False
    _alerts_dir_cache: Optional[Path] = None   # lazy cache, reset on reload

    @classmethod
    def _alerts_dir(cls) -> Path:
        """
        Lazy path accessor — resolves on first call after .env is loaded.
        Caches the result to avoid repeated os.environ lookups.
        """
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
    def _load_manifest(cls) -> None:
        cls._ensure_alerts_dir()
        if cls._manifest_loaded:
            return
        manifest_path = cls._alerts_dir() / "manifest.json"
        if manifest_path.exists():
            try:
                with open(manifest_path, "r", encoding="utf-8") as f:
                    cls._manifest = json.load(f)
                cls._manifest_loaded = True
                logger.info(
                    f"[NativePlayer] Manifest loaded from {manifest_path}: "
                    f"{len(cls._manifest)} entries"
                )
            except Exception as e:
                logger.error(f"[NativePlayer] Failed to load manifest: {e}")
        else:
            logger.warning(f"[NativePlayer] Manifest not found at {manifest_path}")

    @classmethod
    def reload_manifest(cls) -> None:
        """Force-reload manifest from disk (e.g., after user uploads new files)."""
        cls._manifest_loaded = False
        cls._alerts_dir_cache = None   # reset path cache too
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
        alerts_dir = cls._alerts_dir()

        # 1. Try manifest lookup
        entry = cls._manifest.get(sound_id)
        filename = None
        if isinstance(entry, list) and entry:
            import random
            filename = random.choice(entry)
        elif isinstance(entry, str):
            filename = entry

        if filename:
            fp = alerts_dir / filename
            if fp.exists():
                return fp
            logger.warning(
                f"[NativePlayer] Manifest entry '{filename}' for '{sound_id}' "
                f"not found on disk — falling back to generic"
            )

        # 2. Priority-generic fallback
        gen_p = min(6, max(3, priority))
        generic_fp = alerts_dir / f"p{gen_p}_generic.mp3"
        if generic_fp.exists():
            return generic_fp

        # 3. Absolute fallback
        fallback_fp = alerts_dir / "p3_generic.mp3"
        if fallback_fp.exists():
            return fallback_fp

        return None

    # ── OS-Aware Playback ──────────────────────────────────────────────

    # Linux player command cache: e.g. ["mpg123", "-q"]
    _linux_player: Optional[list] = None
    _linux_player_detected: bool  = False

    # Linux MP3 players tried in order (name → base args)
    _LINUX_PLAYERS = [
        ("paplay",  []),
        ("mpg123",  ["-q"]),
        ("mpg321",  ["-q"]),
        ("ffplay",  ["-nodisp", "-autoexit", "-loglevel", "error"]),
        ("cvlc",    ["--intf", "dummy", "--play-and-exit"]),
        ("aplay",   []),
    ]

    @classmethod
    def _detect_linux_player(cls) -> Optional[list]:
        """
        Detect the first available MP3 player on Linux.
        Respects NGFW_AUDIO_PLAYER env var for manual override.
        Returns the command prefix list, e.g. ['paplay'], or None.
        """
        if cls._linux_player_detected:
            return cls._linux_player
        cls._linux_player_detected = True

        # Manual override via env var
        forced = os.environ.get("NGFW_AUDIO_PLAYER", "").strip()
        if forced:
            path = shutil.which(forced)
            if path:
                cls._linux_player = [forced]
                logger.info(f"[NativePlayer] Linux audio player (forced): {forced}")
                return cls._linux_player
            else:
                logger.warning(f"[NativePlayer] NGFW_AUDIO_PLAYER={forced!r} not found, auto-detecting")

        for name, args in cls._LINUX_PLAYERS:
            if shutil.which(name):
                cls._linux_player = [name] + args
                logger.info(f"[NativePlayer] Linux audio player: {name}")
                return cls._linux_player
        logger.warning(
            "[NativePlayer] No audio player found on Linux. "
            "Install one: sudo apt install ffmpeg  # or mpg123"
        )
        return None

    @classmethod
    def _pulse_env(cls) -> dict:
        """
        Build subprocess environment with explicit PulseAudio/PipeWire socket.

        Uses glob to find sockets across ALL user sessions — works even when
        running under sudo, as a service, or with missing XDG_RUNTIME_DIR.
        Search order:
          1. PULSE_SERVER already in env  (keep it)
          2. /run/user/<current-uid>/pulse/native  (own session)
          3. /run/user/*/pulse/native  (any logged-in user, glob)
          4. /run/pulse/native         (system-wide PulseAudio)
          5. /tmp/pulse-*/native       (non-standard install)
        """
        import glob
        env = os.environ.copy()

        # Already set — honour it
        if env.get("PULSE_SERVER"):
            return env

        # Build candidate socket paths
        candidates = []

        # Own UID first (most likely correct)
        try:
            uid = os.getuid()
            candidates.append(f"/run/user/{uid}/pulse/native")
            candidates.append(f"/run/user/{uid}/pulse.native")
        except AttributeError:
            pass  # Windows

        # All other logged-in users (covers sudo / service launch)
        candidates += sorted(glob.glob("/run/user/*/pulse/native"))
        candidates += sorted(glob.glob("/run/user/*/pulse.native"))

        # System-wide and non-standard
        candidates += ["/run/pulse/native"]
        candidates += sorted(glob.glob("/tmp/pulse-*/native"))

        for sock in candidates:
            if os.path.exists(sock):
                env["PULSE_SERVER"]       = f"unix:{sock}"
                env["PULSE_RUNTIME_PATH"] = os.path.dirname(sock)
                xdg = os.path.dirname(os.path.dirname(sock))
                if os.path.isdir(xdg):
                    env.setdefault("XDG_RUNTIME_DIR", xdg)
                logger.info(f"[NativePlayer] PulseAudio socket: {sock}")
                return env

        logger.debug("[NativePlayer] No PulseAudio socket found — will rely on ALSA/ffplay")
        return env

    @classmethod
    def _find_alsa_devices(cls) -> list:
        """
        Find working ALSA devices, ordered best-first.
        Returns list of device strings for mpg123 -a.
        'default' is always first — it works on most modern systems.
        """
        devices = ["default"]
        try:
            r = subprocess.run(
                ["aplay", "-l"], capture_output=True, text=True, timeout=3
            )
            for line in r.stdout.splitlines():
                if line.startswith("card "):
                    parts = line.split(":")
                    card_num = parts[0].split()[1]
                    plug = f"plughw:{card_num},0"
                    hw   = f"hw:{card_num},0"
                    if plug not in devices:
                        devices.append(plug)
                    if hw not in devices:
                        devices.append(hw)
        except Exception:
            pass
        if "plughw:0,0" not in devices:
            devices.append("plughw:0,0")
        return devices

    @classmethod
    def _find_alsa_device(cls) -> str:
        """Alias kept for compatibility — returns best ALSA device."""
        return cls._find_alsa_devices()[0]

    @classmethod
    def _play_linux(cls, filepath: Path, volume: float) -> None:
        """
        Play MP3 on Linux — four-stage strategy.

        Stage 1 — paplay  (PulseAudio native, most reliable on Ubuntu)
                  mpg123 -o pulse  (fallback if paplay absent)
        Stage 2 — ffplay  (uses ALSA or auto-detected backend)
        Stage 3 — mpg123 auto-output  (no -o, player chooses)
        Stage 4 — mpg123 ALSA direct  (tries default, plughw:N,0)
        Stage 5 — cvlc headless

        NOTE: paplay is tried FIRST on Ubuntu because it reliably talks to
        PipeWire/PulseAudio even from service contexts when the socket is
        explicitly provided via PULSE_SERVER.
        """
        gain      = int(volume * 100)
        fpath     = str(filepath)
        env_pulse = cls._pulse_env()
        has_pulse = bool(env_pulse.get("PULSE_SERVER"))

        # -- Stage 1: PulseAudio / PipeWire — paplay first (most reliable) ---
        if has_pulse:
            # paplay: PulseAudio native tool, always works when socket is found
            if shutil.which("paplay"):
                cmd = ["paplay", "--volume=65536",   # 65536 = 100% in PulseAudio units
                       fpath]
                logger.info(f"[NativePlayer] [paplay] CMD: {' '.join(cmd)}")
                if cls._try_play(cmd, env_pulse, "paplay"):
                    return

            # mpg123 + explicit pulse socket
            if shutil.which("mpg123"):
                cmd = ["mpg123", "-q", "-o", "pulse", "-g", str(gain), fpath]
                logger.info(f"[NativePlayer] [mpg123-pulse] CMD: {' '.join(cmd)}")
                if cls._try_play(cmd, env_pulse, "mpg123-pulse"):
                    return
        else:
            logger.info("[NativePlayer] No PulseAudio socket found — skipping Stage 1")

        # -- Stage 2: ffplay — passes PULSE_SERVER in env ---------------------
        if shutil.which("ffplay"):
            cmd = ["ffplay", "-nodisp", "-autoexit",
                   "-loglevel", "warning",
                   "-volume", str(gain), fpath]
            logger.info(f"[NativePlayer] [ffplay] CMD: {' '.join(cmd)}")
            if cls._try_play(cmd, env_pulse, "ffplay"):
                return

        # -- Stage 3: mpg123 auto-output (no -o, player chooses) -------------
        for _p in ("mpg123", "mpg321"):
            if shutil.which(_p):
                cmd = [_p, "-q", "-g", str(gain), fpath]
                logger.info(f"[NativePlayer] [auto] CMD: {' '.join(cmd)}")
        gain      = int(volume * 100)
        pulse_vol = int(volume * 65536)
        fpath     = str(filepath)
        suffix    = filepath.suffix.lower()
        is_wav    = (suffix == ".wav")
        env_pulse = cls._pulse_env()

        # -- Stage 1: PulseAudio / PipeWire (paplay / pw-play) ---------------
        pulse_alive = cls._pulse_is_alive(env_pulse)
        if not pulse_alive and env_pulse.get("PULSE_SERVER"):
            pulse_alive = cls._ensure_pulse_running(env_pulse)

        if pulse_alive:
            if shutil.which("paplay"):
                cmd = ["paplay", f"--volume={pulse_vol}",
                       "--property=media.role=event",
                       fpath]
                logger.info(f"[NativePlayer] [paplay] CMD: {' '.join(cmd)}")
                if cls._try_play(cmd, env_pulse, "paplay"):
                    return

            if shutil.which("pw-play"):
                cmd = ["pw-play", f"--volume={volume:.2f}", fpath]
                logger.info(f"[NativePlayer] [pw-play] CMD: {' '.join(cmd)}")
                if cls._try_play(cmd, env_pulse, "pw-play"):
                    return

            if not is_wav and shutil.which("mpg123"):
                cmd = ["mpg123", "-q", "-o", "pulse", "-g", str(gain), fpath]
                logger.info(f"[NativePlayer] [mpg123-pulse] CMD: {' '.join(cmd)}")
                if cls._try_play(cmd, env_pulse, "mpg123-pulse"):
                    return
        else:
            logger.debug("[NativePlayer] PulseAudio not available — proceeding to ALSA/standalone players")

        # -- Stage 2 (WAV): aplay (native ALSA WAV player) --------------------
        if is_wav and shutil.which("aplay"):
            for _dev in cls._find_alsa_devices():
                cmd = ["aplay", "-q", "-D", _dev, fpath]
                logger.info(f"[NativePlayer] [aplay] CMD: {' '.join(cmd)}")
                if cls._try_play(cmd, os.environ.copy(), f"aplay-{_dev}"):
                    return
            # Plain aplay fallback
            cmd = ["aplay", "-q", fpath]
            logger.info(f"[NativePlayer] [aplay-default] CMD: {' '.join(cmd)}")
            if cls._try_play(cmd, os.environ.copy(), "aplay-default"):
                return

        # -- Stage 2 (MP3): mpg123 / mpg321 (auto & ALSA direct) -------------
        if not is_wav:
            for _p in ("mpg123", "mpg321"):
                if shutil.which(_p):
                    cmd = [_p, "-q", "-g", str(gain), fpath]
                    logger.info(f"[NativePlayer] [auto] CMD: {' '.join(cmd)}")
                    if cls._try_play(cmd, env_pulse, f"{_p}-auto"):
                        return
                    for _dev in cls._find_alsa_devices():
                        cmd = [_p, "-q", "-o", "alsa", "-a", _dev, "-g", str(gain), fpath]
                        logger.info(f"[NativePlayer] [alsa] CMD: {' '.join(cmd)}")
                        if cls._try_play(cmd, os.environ.copy(), f"{_p}-alsa"):
                            return
                    break

        # -- Stage 3: ffplay (handles both WAV and MP3) -----------------------
        if shutil.which("ffplay"):
            cmd = ["ffplay", "-nodisp", "-autoexit",
                   "-loglevel", "warning",
                   "-volume", str(gain), fpath]
            logger.info(f"[NativePlayer] [ffplay] CMD: {' '.join(cmd)}")
            if cls._try_play(cmd, env_pulse, "ffplay"):
                return

        # -- Stage 4: cvlc headless ------------------------------------------
        if shutil.which("cvlc"):
            cmd = ["cvlc", "--intf", "dummy", "--play-and-exit", fpath]
            logger.info(f"[NativePlayer] [cvlc] CMD: {' '.join(cmd)}")
            if cls._try_play(cmd, env_pulse, "cvlc"):
                return

        logger.error(
            f"[NativePlayer] All playback methods failed for '{filepath.name}'. "
            "Check: pactl info / aplay -l / PULSE_SERVER env var"
        )

    @classmethod
    def _try_play(cls, cmd: list, env: dict, label: str) -> bool:
        """
        Launch a playback command and verify it started successfully.

        Logic:
          - Sleep 1.0s then poll the process.
          - rc=None  → still running → playing normally → True
          - rc=0     → exited cleanly → played OK (short file) → True
          - rc!=0    → exited with error → log warning → False
        """
        import threading, time
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                env=env,
            )
            time.sleep(1.0)
            rc = proc.poll()

            if rc is None:
                # Still running after 1s — audio is playing
                logger.info(f"[NativePlayer] {label} ▶ playing")
                threading.Thread(
                    target=cls._watch_proc, args=(proc, label), daemon=True
                ).start()
                return True

            # Exited already — read stderr for diagnostics
            stderr_raw = proc.stderr.read() if proc.stderr else b""
            err = stderr_raw.decode(errors="replace").strip()

            if rc == 0:
                # Clean exit — file played OK (short clip finished before poll)
                if err:
                    logger.info(f"[NativePlayer] {label} ✓ done (rc=0) | {err[:150]}")
                else:
                    logger.info(f"[NativePlayer] {label} ✓ done (rc=0)")
                return True

            # Non-zero exit — real failure
            logger.warning(f"[NativePlayer] {label} ✗ failed (rc={rc}): {err[:200] or '(no stderr)'}")
            return False

        except Exception as e:
            logger.warning(f"[NativePlayer] {label} launch error: {e}")
            return False

    @classmethod
    def _watch_proc(cls, proc, name: str) -> None:
        """Watch a background playback process and log any errors after it exits."""
        try:
            _, stderr_bytes = proc.communicate(timeout=30)
            rc = proc.returncode
            if rc and rc != 0:
                err = (stderr_bytes or b"").decode(errors="replace").strip()
                real_err = "\n".join(
                    l for l in err.splitlines()
                    if not any(skip in l.lower() for skip in
                               ["deprecated", "warning: the parameter"])
                ).strip()
                if real_err:
                    logger.error(f"[NativePlayer] {name} error (rc={rc}): {real_err[:300]}")
            else:
                logger.debug(f"[NativePlayer] {name} finished (rc={rc})")
        except subprocess.TimeoutExpired:
            logger.debug(f"[NativePlayer] {name} still playing after 30s")
        except Exception as ex:
            logger.debug(f"[NativePlayer] _watch_proc({name}): {ex}")


    @classmethod
    def _play_windows(cls, filepath: Path, volume: float) -> None:
        """
        Play MP3 / WAV on Windows using PowerShell.
        Uses System.Media.SoundPlayer for .wav or System.Windows.Media.MediaPlayer with System.Uri for .mp3.
        """
        filepath_str = str(filepath.resolve()).replace("'", "''")
        suffix = filepath.suffix.lower()
        if suffix == ".wav":
            ps_cmd = (
                f"$p = New-Object System.Media.SoundPlayer; "
                f"$p.SoundLocation = '{filepath_str}'; "
                f"$p.Play(); "
                f"Start-Sleep -Seconds 6"
            )
        else:
            ps_cmd = (
                f"[void][System.Reflection.Assembly]::LoadWithPartialName('PresentationCore'); "
                f"$p = New-Object System.Windows.Media.MediaPlayer; "
                f"$p.Open([System.Uri]'{filepath_str}'); "
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
            logger.error(f"[NativePlayer] PowerShell playback failed: {e}")

    @classmethod
    def play_sound(cls, sound_id: str, priority: int, volume: float = 1.0) -> None:
        """
        Play an alert sound on the server's default audio output.
        Cross-platform: PowerShell on Windows, mpg123/aplay/ffplay/paplay on Linux.
        Runs asynchronously (subprocess.Popen) — does not block the caller.

        Args:
            sound_id:  Event sound identifier (e.g. "threat_detected")
            priority:  Audio priority level (1-6), used for generic fallback
            volume:    Playback volume 0.0–1.0
        """
        # Operator toggle: tones disabled → skip silently (TTS speech unaffected)
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
        logger.info(f"[NativePlayer] ▶ {filepath.name} (vol={volume:.0%})")

        if sys.platform == "win32":
            cls._play_windows(filepath, volume)
        else:
            cls._play_linux(filepath, volume)

    @classmethod
    def speak_text(cls, text: str) -> None:
        """
        Speak text via TTS. Windows: SpeechSynthesizer. Linux: espeak/festival.
        Runs asynchronously — does not block the caller.
        """
        if not text:
            return
        logger.info(f"[NativePlayer] TTS: {text}")

        if sys.platform == "win32":
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
                logger.error(f"[NativePlayer] Windows TTS failed: {e}")
        else:
            tts_cmd = None
            if shutil.which("espeak-ng"):
                tts_cmd = ["espeak-ng", text]
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
                    logger.error(f"[NativePlayer] Linux TTS failed: {e}")
            else:
                logger.debug("[NativePlayer] No TTS engine found on Linux (espeak/festival)")

    # ── Diagnostics ───────────────────────────────────────────────────

    @classmethod
    def get_status(cls) -> dict:
        """Return diagnostic info for the audio system."""
        cls._load_manifest()
        alerts_dir = cls._alerts_dir()
        mp3_files = list(alerts_dir.glob("*.mp3")) if alerts_dir.exists() else []
        wav_files = list(alerts_dir.glob("*.wav")) if alerts_dir.exists() else []
        all_files = mp3_files + wav_files

        # Detect available player on current OS
        if sys.platform == "win32":
            player_info = "powershell (Windows)"
        else:
            player = cls._detect_linux_player()
            player_info = player[0] if player else "none — install ffmpeg or mpg123"

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

