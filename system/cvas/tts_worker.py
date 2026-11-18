"""
bunyanx Voice Alert Service (CVAS) — TTS Worker Thread
==========================================================
Isolated background worker driving speech synthesis for security alerts.

Linux audio strategy (ordered by reliability on Ubuntu servers):
  1. paplay via PulseAudio/PipeWire  ← confirmed alive via pactl before use
  2. pw-play (PipeWire native CLI)
  3. ffplay  (libav — auto-selects backend, does not block on pulse socket)
  4. mpg123  (lightweight, auto-detects output)
  5. aplay   (raw ALSA — last resort, fails on many headless/VM setups)

Core design rules:
  ─ PulseAudio liveness is VERIFIED with `pactl info` (2 s timeout) before
    paplay is ever launched.  A dead socket makes paplay block indefinitely;
    the 1-second liveness poll cannot tell that apart from real playback.
  ─ Exactly ONE audio process runs at a time.  Once a player is alive after
    the 1-second poll it is waited on with a duration-aware timeout; on
    natural or timeout termination we return immediately without cascading
    to the next backend.
  ─ The stop_event is checked every 0.5 s for clean emergency preemption.
  ─ All runtime settings (language, speed, volume, pitch, tts_engine,
    audio_effect) are read from cvas_config.yaml via self.config at
    call-time so that a hot-reload propagates immediately.
"""

import os
import re
import sys
import glob
import shutil
import hashlib
import tempfile
import subprocess
import threading
import logging
import time
from typing import Optional, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)

# Absolute path to the bundled voices directory (next to this file: system/cvas/voices/).
# Using __file__ avoids CWD-dependence when the server is launched from any directory.
_VOICES_DIR = Path(__file__).parent / "voices"

try:
    import pyttsx3
    PYTTSX3_AVAILABLE = True
except ImportError:
    PYTTSX3_AVAILABLE = False

# ── Piper neural TTS (Python API — preferred over CLI subprocess) ──────────
# piper-tts installs as a Python package in the same venv as the server.
# Using the Python API avoids all PATH / binary-not-found issues that occur
# when the server is launched via `sudo venv/bin/python main.py` (venv/bin is
# NOT in PATH in that case, so shutil.which("piper") always returns None).
try:
    from piper.voice import PiperVoice as _PiperVoice  # piper-tts >= 1.2
    PIPER_PYTHON_AVAILABLE = True
except ImportError:
    try:
        from piper import PiperVoice as _PiperVoice     # older piper-tts builds
        PIPER_PYTHON_AVAILABLE = True
    except ImportError:
        PIPER_PYTHON_AVAILABLE = False

# Model cache: load each .onnx file only once per process (expensive cold-load ~1-3 s).
_piper_voice_cache: dict        = {}
_piper_voice_cache_lock         = threading.Lock()


# ── PulseAudio / PipeWire helpers ─────────────────────────────────────────────

def _get_pulse_env() -> dict:
    """Return os.environ copy augmented with the best PulseAudio socket found."""
    env = os.environ.copy()
    if env.get("PULSE_SERVER"):
        return env

    candidates: list = []
    try:
        uid = os.getuid()
        candidates += [
            f"/run/user/{uid}/pulse/native",
            f"/run/user/{uid}/pulse.native",
        ]
    except AttributeError:
        pass  # Windows

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
            logger.debug(f"[CVAS:TTSWorker] PulseAudio socket: {sock}")
            return env

    logger.debug("[CVAS:TTSWorker] No PulseAudio socket found")
    return env


def _pulse_is_alive(env: dict) -> bool:
    """
    Verify PulseAudio/PipeWire daemon is *actually responding* — not just
    that the socket file exists on disk.

    A dead socket causes paplay to block indefinitely.  The 1-second
    liveness poll used by _launch_and_wait() cannot distinguish that
    "process is alive but frozen" from "process is alive and playing".

    Runs: pactl info  with a 2-second hard timeout.
    Returns True only when pactl exits 0.
    """
    pactl = shutil.which("pactl")
    if not pactl or not env.get("PULSE_SERVER"):
        return False
    try:
        r = subprocess.run(
            [pactl, "info"],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
        )
        return r.returncode == 0
    except Exception:
        return False


def _ensure_pulse_running(env: dict) -> bool:
    """
    Attempt to start the PulseAudio / PipeWire daemon if it is not responding.
    Tries (in order):
      1. pulseaudio --start --daemonize=yes
      2. systemctl --user start pulseaudio
      3. systemctl --user start pipewire pipewire-pulse

    Waits 1.5 s after each attempt before re-checking.
    Returns True if the daemon is alive after the attempt.
    """
    start_cmds = [
        ["pulseaudio", "--start", "--daemonize=yes", "--exit-idle-time=-1"],
        ["systemctl", "--user", "start", "pulseaudio"],
        ["systemctl", "--user", "start", "pipewire", "pipewire-pulse"],
    ]
    for cmd in start_cmds:
        if not shutil.which(cmd[0]):
            continue
        try:
            logger.info(f"[CVAS:TTSWorker] Starting audio daemon: {' '.join(cmd)}")
            subprocess.run(
                cmd, env=env, timeout=6,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            time.sleep(1.5)  # give daemon time to bind its socket
            if _pulse_is_alive(env):
                logger.info("[CVAS:TTSWorker] PulseAudio daemon started successfully")
                return True
        except Exception as exc:
            logger.debug(f"[CVAS:TTSWorker] daemon start attempt failed: {exc}")

    logger.warning("[CVAS:TTSWorker] PulseAudio unavailable — skipping paplay/pw-play")
    return False


# ── Worker Thread ──────────────────────────────────────────────────────────────

class CVASWorkerThread(threading.Thread):
    """
    Dedicated daemon thread managing speech synthesis for CVAS alerts.
    Zero blocking impact on firewall packet processing or FastAPI event loop.
    Exactly one audio process runs at a time — no simultaneous streams.
    """

    def __init__(self, priority_engine: Any, config: Dict[str, Any]):
        """Args:
            priority_engine: PriorityEngine instance providing fetch_next_alert().
            config: The FULL top-level config dict (containing the 'cvas' key).
                    We store the 'cvas' sub-dict so that settings are read
                    directly via self.config.get("language") etc., and a
                    hot-reload can replace self.config atomically.
        """
        super().__init__(daemon=True, name="CVAS_WorkerThread")
        self.priority_engine         = priority_engine
        # Store the cvas sub-dict. CVASService.reload() replaces this atomically.
        self.config: Dict[str, Any]  = config.get("cvas", {})
        self.running                 = False
        self.engine: Optional[Any]   = None
        self._current_item: Optional[Any] = None
        self._stop_event             = threading.Event()
        self._current_proc: Optional[subprocess.Popen] = None
        self._consecutive_failures   = 0   # for watchdog circuit breaker

    # ── pyttsx3 init ──────────────────────────────────────────────────────────

    def initialize_tts_engine(self) -> bool:
        # pyttsx3 on Linux wraps espeak with an ALSA backend.  When ALSA is
        # unavailable (service/headless context), espeak fails silently without
        # raising a Python exception.  _speak_text() then returns thinking TTS
        # succeeded, and _speak_linux() is never called.
        # On Linux we always use our own CLI pipeline (WAV + PulseAudio + fallbacks)
        # which has proper liveness checks and multi-backend support.
        if sys.platform.startswith("linux"):
            logger.info(
                "[CVAS:TTSWorker] Linux detected — using CLI audio pipeline "
                "(pyttsx3 bypassed: ALSA backend fails silently in server contexts)"
            )
            return False

        if not PYTTSX3_AVAILABLE:
            logger.warning("[CVAS:TTSWorker] pyttsx3 not available — using Linux CLI pipeline.")
            return False
        try:
            self.engine = pyttsx3.init()
            speed  = self.config.get("speed_wpm", 175)
            volume = self.config.get("volume",    0.9)
            self.engine.setProperty("rate",   speed)
            self.engine.setProperty("volume", volume)

            desired = self.config.get("language", "ar-SA")
            voices  = self.engine.getProperty("voices") or []
            for v in voices:
                vid  = (getattr(v, "id",   "") or "").lower()
                name = (getattr(v, "name", "") or "").lower()
                hit  = desired in vid or ("arabic" in name if "ar" in desired else "english" in name)
                if hit:
                    self.engine.setProperty("voice", v.id)
                    break

            logger.info(f"[CVAS:TTSWorker] pyttsx3 ready (rate={speed}, vol={volume})")
            return True
        except Exception as e:
            logger.warning(f"[CVAS:TTSWorker] pyttsx3 init failed: {e} — using CLI pipeline.")
            self.engine = None
            return False

    # ── Thread lifecycle ──────────────────────────────────────────────────────

    def stop(self) -> None:
        self.running = False
        self._stop_event.set()
        if self.engine:
            try:
                self.engine.stop()
            except Exception:
                pass
        if self._current_proc:
            try:
                self._current_proc.terminate()
            except Exception:
                pass

    def run(self) -> None:
        self.running = True
        has_tts = self.initialize_tts_engine()
        logger.info("[CVAS:TTSWorker] Background speech worker started.")

        while self.running and not self._stop_event.is_set():
            try:
                item = self.priority_engine.fetch_next_alert(timeout=0.5)
                if not item:
                    continue

                self._current_item = item
                spoken_text        = item.spoken_text

                logger.info(
                    f"[CVAS:VoiceOut] [{item.topic}] ({item.level_key}) "
                    f"Spoken: \"{spoken_text}\""
                )

                self._speak_text(spoken_text, has_tts)
                self.priority_engine.record_spoken()
                self.priority_engine.mark_done()
                self._current_item = None

            except Exception as e:
                logger.error(f"[CVAS:TTSWorker] Worker loop error: {e}")
                time.sleep(0.5)

        logger.info("[CVAS:TTSWorker] Background speech worker stopped.")

    # ── Speech dispatch ───────────────────────────────────────────────────────

    def _speak_text(self, spoken_text: str, has_tts: bool) -> None:
        """
        Route speech to the appropriate TTS backend.

        Linux  → always _speak_linux() (WAV synthesis + PulseAudio-verified paplay
                  + ffplay/mpg123 fallbacks).  pyttsx3 is NOT used on Linux because
                  its espeak/ALSA backend fails silently in server/headless contexts:
                  ALSA returns 'Host is down' without raising a Python exception, so
                  _speak_text() would return thinking speech succeeded.

        Windows / macOS → pyttsx3 (SAPI / NSSpeechSynthesizer — reliable).
        """
        if sys.platform.startswith("linux"):
            self._speak_linux(spoken_text)
            return

        # Windows / macOS path
        if has_tts and self.engine:
            try:
                self.engine.say(spoken_text)
                self.engine.runAndWait()
            except Exception as e:
                logger.warning(f"[CVAS:TTSWorker] pyttsx3 failed: {e}")

    # ─────────────────────────────────────────────────────────────────────────
    # TTS SYNTHESIS HELPERS
    # ─────────────────────────────────────────────────────────────────────────

    def _find_piper_binary(self) -> Optional[str]:
        """
        Locate the piper (or piper-tts) CLI executable binary on Linux.

        Searches:
          1. $PATH via shutil.which()
          2. Python venv directory running the server (sys.executable.parent)
          3. /usr/local/bin/piper & /usr/bin/piper
          4. /home/*/.local/bin/piper (scans all user homes regardless of root/sudo)
        """
        found = shutil.which("piper") or shutil.which("piper-tts")
        if found:
            return found

        # 2. Check current venv bin directory
        venv_bin = Path(sys.executable).parent
        for candidate_name in ("piper", "piper-tts"):
            cand = venv_bin / candidate_name
            if cand.exists() and os.access(cand, os.X_OK):
                logger.info(f"[CVAS:Piper] Binary found in venv: {cand}")
                return str(cand)

        # 3. Explicit list & glob search across system and /home/*/
        candidates = [
            "/usr/local/bin/piper",
            "/usr/local/bin/piper-tts",
            "/usr/bin/piper",
            "/opt/piper/piper",
        ]

        import glob as _glob
        candidates.extend(_glob.glob("/home/*/.local/bin/piper"))
        candidates.extend(_glob.glob("/home/*/.local/bin/piper-tts"))
        try:
            candidates.append(str(Path.home() / ".local" / "bin" / "piper"))
        except Exception:
            pass

        for c in candidates:
            p = Path(c)
            if p.exists() and os.access(p, os.X_OK):
                logger.info(f"[CVAS:Piper] Binary found (explicit scan): {p}")
                return str(p)

        logger.debug("[CVAS:Piper] piper binary not found")
        return None

    def _find_piper_model(self, lang: str, voice_gender: str = "female") -> Optional[Path]:
        """
        Locate a Piper voice model (.onnx) on the host filesystem.
        """
        is_arabic = "ar" in lang

        if is_arabic:
            model_names = (
                [
                    "ar_female",
                    "arabic_female",
                    "ar_AE-emirati",
                    "ar_OM-karimah-medium",
                    "ar_SA-hafsa-medium",
                    "ar_JO-kareem-medium",
                ]
                if voice_gender.lower() == "female"
                else ["ar_JO-kareem-medium", "ar_female", "ar_OM-karimah-medium", "ar_SA-hafsa-medium"]
            )
        else:
            model_names = (
                ["en_US-lessac-medium", "en_GB-alan-medium", "en_US-ryan-medium"]
                if voice_gender.lower() == "female"
                else ["en_US-ryan-medium", "en_US-lessac-medium", "en_GB-alan-medium"]
            )

        search_dirs = [
            _VOICES_DIR,                                          # system/cvas/voices/ (bundled)
            Path("/usr/share/piper-voices"),                     # apt package
            Path("/usr/local/share/piper-voices"),               # sudo pip install
            Path("/opt/piper/models"),                           # manual install
            Path("/usr/lib/piper"),                              # distro package
        ]

        # Scan all user home directories for .local/share/piper-voices
        import glob as _glob
        for home_dir in _glob.glob("/home/*/.local/share/piper-voices"):
            p_dir = Path(home_dir)
            if p_dir not in search_dirs:
                search_dirs.append(p_dir)

        try:
            p_user = Path.home() / ".local" / "share" / "piper-voices"
            if p_user not in search_dirs:
                search_dirs.append(p_user)
        except Exception:
            pass

        # 1. Exact model name match
        for name in model_names:
            for d in search_dirs:
                candidate = d / f"{name}.onnx"
                if candidate.exists():
                    logger.info(f"[CVAS:Piper] Voice model found: {candidate}")
                    return candidate

        # 2. Glob fallback for female voice files if voice_gender == female
        if voice_gender.lower() == "female":
            for d in search_dirs:
                if d.exists() and d.is_dir():
                    for candidate in d.glob("*female*.onnx"):
                        logger.info(f"[CVAS:Piper] Voice model found (female glob match): {candidate}")
                        return candidate

        # 3. Glob fallback for any ar_*.onnx or en_*.onnx in search_dirs
        prefix = "ar" if is_arabic else "en"
        for d in search_dirs:
            if d.exists() and d.is_dir():
                for candidate in d.glob(f"{prefix}*.onnx"):
                    logger.info(f"[CVAS:Piper] Voice model found (glob match): {candidate}")
                    return candidate
                for candidate in d.glob("*.onnx"):
                    logger.info(f"[CVAS:Piper] Voice model found (any onnx match): {candidate}")
                    return candidate

        logger.debug(f"[CVAS:Piper] No .onnx model found for lang={lang}")
        return None

    def _synthesise_with_piper(self, spoken_text: str, lang: str, speed: int = 175, voice_gender: str = "female") -> Optional[str]:
        """
        Synthesise spoken_text using Piper neural TTS (CLI subprocess primary,
        Python API secondary fallback).
        """
        piper_bin  = self._find_piper_binary()
        model_path = self._find_piper_model(lang, voice_gender)

        if not model_path:
            logger.info("[CVAS:Piper] No .onnx model found — falling back to espeak-ng")
            return None

        # ── Audio Cache Check (Zero CPU cost on repeated alerts) ───────────────
        cache_dir = Path(__file__).resolve().parents[2] / "var" / "audio" / "alerts" / "cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        text_hash = hashlib.md5(f"{spoken_text}:{lang}:{voice_gender}:{speed}".encode('utf-8')).hexdigest()
        cached_wav = cache_dir / f"tts_{text_hash}.wav"

        if cached_wav.exists() and cached_wav.stat().st_size >= 512:
            logger.info(f"[CVAS:Piper] ⚡ Reusing cached neural WAV clip (0 CPU): {cached_wav.name}")
            return str(cached_wav)

        # Calculate length_scale from requested speed WPM (lower = faster speech)
        length_scale = round(max(0.5, min(1.3, 140.0 / float(max(90, speed)))), 2)

        # ── Method 1: CLI Subprocess (Primary — works everywhere CLI is installed) ───
        if piper_bin:
            wav_path = str(cached_wav)

            try:
                sub_env = os.environ.copy()
                venv_bin = str(Path(sys.executable).parent)
                sub_env["PATH"] = f"{venv_bin}:/usr/local/bin:/usr/bin:{sub_env.get('PATH', '')}"

                cmd = [
                    piper_bin,
                    "--model", str(model_path),
                    "--output_file", wav_path,
                    "--length_scale", str(length_scale),
                    "--sentence_silence", "0.1",
                ]
                logger.debug(f"[CVAS:Piper] Executing: {' '.join(cmd[:6])} ...")

                result = subprocess.run(
                    cmd,
                    input=spoken_text.encode("utf-8"),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    env=sub_env,
                    timeout=30,
                )

                if result.returncode == 0 and os.path.exists(wav_path) and os.path.getsize(wav_path) >= 512:
                    size = os.path.getsize(wav_path)
                    logger.info(
                        f"[CVAS:Piper] ✓ Neural WAV synthesised (CLI) → {size // 1024} KB  "
                        f"model={model_path.name}  length_scale={length_scale} (speed={speed}wpm)"
                    )
                    return wav_path
                else:
                    err = (result.stderr or b"").decode(errors="replace").strip()[:120]
                    logger.warning(f"[CVAS:Piper] CLI failed (rc={result.returncode}): {err}")
                    if os.path.exists(wav_path):
                        os.remove(wav_path)

            except Exception as e:
                logger.warning(f"[CVAS:Piper] CLI exception: {e}")
                if 'wav_path' in locals() and os.path.exists(wav_path):
                    try:
                        os.remove(wav_path)
                    except Exception:
                        pass

        # ── Method 2: Python API (Fallback if installed as Python module) ────────────
        if PIPER_PYTHON_AVAILABLE:
            model_key = str(model_path)
            with _piper_voice_cache_lock:
                if model_key not in _piper_voice_cache:
                    try:
                        _piper_voice_cache[model_key] = _PiperVoice.load(
                            str(model_path), use_cuda=False
                        )
                        logger.info(f"[CVAS:Piper] Python API model loaded: {model_path.name}")
                    except Exception as load_err:
                        logger.warning(f"[CVAS:Piper] Python API load error: {load_err}")
                        return None
                voice = _piper_voice_cache[model_key]

            tf = tempfile.NamedTemporaryFile(suffix=".wav", delete=False)
            wav_path = tf.name
            tf.close()

            try:
                import wave
                with wave.open(wav_path, "w") as wav_file:
                    try:
                        voice.synthesize(spoken_text, wav_file, length_scale=length_scale)
                    except TypeError:
                        voice.synthesize(spoken_text, wav_file)

                size = os.path.getsize(wav_path)
                if size >= 512:
                    logger.info(
                        f"[CVAS:Piper] ✓ Neural WAV synthesised (Python API) → {size // 1024} KB  "
                        f"model={model_path.name}  length_scale={length_scale}"
                    )
                    return wav_path
                else:
                    os.remove(wav_path)
            except Exception as e:
                logger.warning(f"[CVAS:Piper] Python API error: {e}")
                if os.path.exists(wav_path):
                    try:
                        os.remove(wav_path)
                    except Exception:
                        pass

        logger.info("[CVAS:Piper] All Piper synthesis attempts failed — falling back to espeak-ng")
        return None

    def _synthesise_with_espeak(self, spoken_text: str, lang: str, speed: int, voice_gender: str = "female", pitch: float = 1.0) -> Optional[str]:
        """
        Synthesise spoken_text using espeak-ng.
        """
        espeak_bin = shutil.which("espeak-ng") or shutil.which("espeak")
        if not espeak_bin:
            logger.warning("[CVAS:TTSWorker] espeak-ng / espeak not found.")
            return None

        # Select variant based on gender
        gender_variant = "+f3" if voice_gender.lower() == "female" else "+m3"
        base_voice     = "ar" if "ar" in lang else "en"
        voice          = f"{base_voice}{gender_variant}"

        clarity_speed = min(speed, 145) if "ar" in lang else speed
        espeak_pitch  = int(max(10, min(99, pitch * 50)))

        tf = tempfile.NamedTemporaryFile(suffix=".wav", delete=False)
        wav_path = tf.name
        tf.close()

        synth_cmd = [
            espeak_bin,
            "-v", voice,
            "-s", str(clarity_speed),
            "-a", "175",   # amplitude (louder = clearer)
            "-g", "4",     # 40 ms inter-word gap
            "-p", str(espeak_pitch),
            "-w", wav_path,
            spoken_text,
        ]
        logger.debug(f"[CVAS:espeak] CMD: {' '.join(synth_cmd[:7])} ...")

        try:
            result = subprocess.run(
                synth_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=15,
            )

            if result.returncode != 0:
                err = (result.stderr or b"").decode(errors="replace").strip()[:120]
                logger.warning(f"[CVAS:espeak] Synthesis failed (rc={result.returncode}): {err}")
                os.remove(wav_path)
                return None

            if not os.path.exists(wav_path) or os.path.getsize(wav_path) == 0:
                logger.warning("[CVAS:espeak] Empty WAV produced")
                os.remove(wav_path)
                return None

            size = os.path.getsize(wav_path)
            logger.info(
                f"[CVAS:espeak] WAV synthesised → {size} B "
                f"(≈{size//32000+1}s, voice={voice}, speed={clarity_speed} wpm, pitch={espeak_pitch})"
            )
            return wav_path

        except Exception as e:
            logger.warning(f"[CVAS:espeak] Exception: {e}")
            try:
                os.remove(wav_path)
            except Exception:
                pass
            return None

    def _synthesise_wav(self, spoken_text: str, lang: str, speed: int, voice_gender: str = "female", pitch: float = 1.0) -> Optional[str]:
        """
        Synthesise spoken_text → WAV.
        Supports tts_engine choice: "espeak" (robotic formant), "piper" (neural), or "auto".
        All settings read from self.config (the cvas sub-dict from cvas_config.yaml).
        """
        # self.config IS the cvas sub-dict — read keys directly (FIX: BUG-02)
        engine_choice = str(self.config.get("tts_engine", "auto")).lower()
        audio_effect  = str(self.config.get("audio_effect", "none")).lower()

        # If user explicitly selected espeak engine or espeak effect, use espeak-ng formant synthesizer
        if engine_choice == "espeak" or "espeak" in audio_effect:
            logger.info("[CVAS:TTSWorker] Using espeak-ng formant synthesizer (classic robotic alarm voice)")
            wav_path = self._synthesise_with_espeak(spoken_text, lang, speed, voice_gender, pitch)
            if wav_path:
                return wav_path
            logger.warning("[CVAS:TTSWorker] espeak-ng failed — falling back to Piper neural TTS")

        # If user explicitly selected piper engine
        if engine_choice == "piper":
            wav_path = self._synthesise_with_piper(spoken_text, lang, speed, voice_gender)
            if wav_path:
                return wav_path
            logger.warning("[CVAS:TTSWorker] Piper neural TTS failed — falling back to espeak-ng")
            return self._synthesise_with_espeak(spoken_text, lang, speed, voice_gender, pitch)

        # Default / Auto: Piper first, then espeak fallback
        wav_path = self._synthesise_with_piper(spoken_text, lang, speed, voice_gender)
        if not wav_path:
            wav_path = self._synthesise_with_espeak(spoken_text, lang, speed, voice_gender, pitch)
        return wav_path

    def _apply_audio_effect(self, wav_path: str, effect_type: str) -> str:
        """
        Apply real-time DSP audio filter (Robotic, Cyber-AI, Tactical Radio)
        to synthesised speech WAV file via ffmpeg.

        Compatible with ffmpeg 4.x+ (Debian Buster/Bullseye/Bookworm).
        Falls back to a simpler variant if the full chain fails.
        """
        if not effect_type or effect_type in ("none", "natural"):
            return wav_path

        # Try ffmpeg from venv-adjacent bin first, then PATH
        ffmpeg_bin = None
        for candidate in [
            str(Path(sys.executable).parent / "ffmpeg"),
            shutil.which("ffmpeg") or "",
            "/usr/bin/ffmpeg",
            "/usr/local/bin/ffmpeg",
        ]:
            if candidate and os.path.isfile(candidate):
                ffmpeg_bin = candidate
                break

        if not ffmpeg_bin:
            logger.warning("[CVAS:Effect] ffmpeg not found — install with: sudo apt install ffmpeg")
            return wav_path

        # ── DSP filter chains ─────────────────────────────────────────────
        # All filters use width_type=h (Hz) — universally supported across ffmpeg versions.
        # Each entry is (primary_chain, fallback_chain).
        FILTERS: dict[str, tuple[str, str]] = {
            # Vintage emergency alarm system: horn PA speaker bandpass + tight metallic comb delay (5ms) + bit-crush
            "robotic": (
                # Primary: authentic retro sci-fi alarm system voice
                "highpass=f=350,"
                "lowpass=f=3400,"
                "flanger=delay=3:depth=8:regen=80:width=85,"
                "aecho=0.9:0.85:6:0.5,"
                "equalizer=f=1500:width_type=h:width=800:g=6,"
                "acrusher=level_in=1.2:level_out=1:bits=9:mode=log,"
                "volume=1.4",
                # Fallback: tight metallic comb delay + bandpass
                "highpass=f=350,"
                "lowpass=f=3400,"
                "aecho=0.9:0.85:6:0.5,"
                "volume=1.3",
            ),
            # 80s Vintage computer warning voice: SPO256 digital chip synthesis style
            "retro_computer": (
                "highpass=f=300,"
                "lowpass=f=3000,"
                "aecho=0.95:0.9:4:0.65,"
                "aecho=0.8:0.8:10:0.5,"
                "acrusher=level_in=1.5:level_out=1:bits=8:mode=log,"
                "volume=1.45",
                "highpass=f=300,"
                "lowpass=f=3000,"
                "aecho=0.9:0.8:8:0.5,"
                "volume=1.3",
            ),
            # Sci-Fi AI voice: modern synthetic shimmer + crisp presence boost
            "cyber_ai": (
                # Primary: AI synthetic shimmer
                "flanger=delay=2:depth=5:regen=65:width=70,"
                "aecho=0.95:0.75:10:0.45,"
                "equalizer=f=250:width_type=h:width=300:g=-8,"
                "equalizer=f=2500:width_type=h:width=1500:g=6,"
                "equalizer=f=7000:width_type=h:width=3000:g=5,"
                "volume=1.3",
                # Fallback: echo + hi-shelf boost
                "aecho=0.9:0.8:12:0.4,"
                "equalizer=f=3000:width_type=h:width=4000:g=5,"
                "volume=1.2",
            ),
            # Tactical radio: telephone bandpass + bit-crunch + crackling echo
            "radio_comm": (
                # Primary: AM radio voice
                "highpass=f=300,"
                "lowpass=f=3400,"
                "equalizer=f=1500:width_type=h:width=800:g=5,"
                "acrusher=level_in=1.8:level_out=1:bits=10:mode=log:aa=1,"
                "aecho=0.45:0.3:18:0.15,"
                "volume=1.5",
                # Fallback: bandpass only
                "highpass=f=300,"
                "lowpass=f=3400,"
                "volume=1.3",
            ),
        }

        chains = FILTERS.get(effect_type.lower())
        if not chains:
            logger.warning(f"[CVAS:Effect] Unknown effect '{effect_type}' — skipped")
            return wav_path

        primary_chain, fallback_chain = chains

        def _run_ffmpeg(af_filter: str) -> str | None:
            out_tf = tempfile.NamedTemporaryFile(suffix=".wav", delete=False)
            out_path = out_tf.name
            out_tf.close()
            cmd = [
                ffmpeg_bin, "-y",
                "-i", wav_path,
                "-af", af_filter,
                "-ar", "22050",
                "-acodec", "pcm_s16le",
                out_path,
            ]
            try:
                result = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=15,
                )
                if result.returncode == 0 and os.path.exists(out_path) and os.path.getsize(out_path) >= 512:
                    return out_path
                err = result.stderr.decode(errors="replace")[-500:]
                logger.debug(f"[CVAS:Effect] ffmpeg rc={result.returncode}  stderr: {err}")
            except Exception as exc:
                logger.debug(f"[CVAS:Effect] ffmpeg exception: {exc}")
            try:
                os.remove(out_path)
            except Exception:
                pass
            return None

        # Try primary chain first, then fallback
        out_path = _run_ffmpeg(primary_chain)
        if out_path:
            logger.info(f"[CVAS:Effect] ✓ Applied '{effect_type}' (primary) → {out_path}")
        else:
            logger.warning(f"[CVAS:Effect] Primary chain failed for '{effect_type}' — trying fallback")
            out_path = _run_ffmpeg(fallback_chain)
            if out_path:
                logger.info(f"[CVAS:Effect] ✓ Applied '{effect_type}' (fallback) → {out_path}")
            else:
                logger.warning(f"[CVAS:Effect] Both chains failed for '{effect_type}' — using original audio")
                return wav_path

        # Replace original WAV
        try:
            os.remove(wav_path)
        except Exception:
            pass
        return out_path

    # ── Linux audio pipeline ──────────────────────────────────────────────────

    def _speak_linux(self, spoken_text: str) -> None:
        """
        Synthesise spoken_text → WAV → play via first working audio backend.
        All settings read from self.config (cvas sub-dict). FIX: BUG-03.
        """
        env          = _get_pulse_env()
        # self.config IS the cvas sub-dict — read keys directly (FIX: BUG-03)
        lang         = self.config.get("language", "ar-SA")
        speed        = int(self.config.get("speed_wpm", 175))
        voice_gender = self.config.get("voice_gender", "female")
        pitch        = float(self.config.get("pitch", 1.0))
        volume       = float(self.config.get("volume", 0.9))
        audio_effect = self.config.get("audio_effect", "none")

        # PulseAudio linear volume (0..65536)
        pulse_vol = int(max(0.0, min(1.0, volume)) * 65536)

        # ── Step 1: Synthesise → WAV ──────────────────────────────────────────
        wav_path = self._synthesise_wav(spoken_text, lang, speed, voice_gender, pitch)
        if not wav_path:
            logger.error("[CVAS:TTSWorker] All TTS backends failed — no audio output.")
            return

        # Apply Sci-Fi / Robotic / Tactical Radio audio filter if configured
        wav_path = self._apply_audio_effect(wav_path, audio_effect)

        # Duration-aware play timeout
        word_count   = max(1, len(spoken_text.split()))
        est_secs     = (word_count / max(80, speed)) * 60
        play_timeout = max(20, int(est_secs * 2) + 10)

        try:
            # ── Step 2: check PulseAudio liveness ─────────────────────────────
            pulse_alive = _pulse_is_alive(env)
            if not pulse_alive and env.get("PULSE_SERVER"):
                # Socket file exists but daemon not responding — try to start it
                pulse_alive = _ensure_pulse_running(env)
                if pulse_alive:
                    # Refresh env after daemon restart (socket path may change)
                    env = _get_pulse_env()

            # ── Step 3: build ordered player list ─────────────────────────────
            #   paplay / pw-play  → only when pulse is confirmed alive
            #   ffplay / mpg123   → auto-detect backend, never block on pulse
            #   aplay             → raw ALSA, last resort (fails on most servers)
            players: list = []
            if pulse_alive:
                if shutil.which("paplay"):
                    # media.role=announcement → PulseAudio automatically ducks
                    # concurrent event/notification streams so speech is clearly
                    # heard over the alert tone.  This is the correct SOC behaviour.
                    players.append(("paplay", [
                        "paplay",
                        "--property=media.role=announcement",
                        wav_path,
                    ], env))
                if shutil.which("pw-play"):
                    players.append(("pw-play", [
                        "pw-play",
                        "--property=media.role=announcement",
                        wav_path,
                    ], env))

            if shutil.which("ffplay"):
                players.append(("ffplay", [
                    "ffplay", "-nodisp", "-autoexit", "-loglevel", "quiet", wav_path,
                ], env))
            if shutil.which("mpg123"):
                players.append(("mpg123", ["mpg123", "-q", wav_path], env))
            # aplay last — often unavailable in service/headless contexts
            if shutil.which("aplay"):
                players.append(("aplay",  ["aplay",  "-q", wav_path], os.environ.copy()))

            if not players:
                logger.warning("[CVAS:TTSWorker] No audio playback binary found.")
                return

            # ── Step 4: try players until one succeeds ─────────────────────────
            for name, cmd, player_env in players:
                if self._stop_event.is_set():
                    break
                if self._launch_and_wait(name, cmd, player_env, play_timeout):
                    return  # success — do NOT cascade to next backend

            logger.warning(
                "[CVAS:TTSWorker] All audio backends failed. "
                "Run: pactl info / aplay -l  to diagnose."
            )

        except Exception as e:
            logger.error(f"[CVAS:TTSWorker] Speech pipeline error: {e}")
        finally:
            try:
                os.remove(wav_path)
            except Exception:
                pass

    def _launch_and_wait(
        self,
        name: str,
        cmd: list,
        env: dict,
        timeout_secs: int,
    ) -> bool:
        """
        Launch an audio player and wait for it to finish.

        Liveness detection (mirrors NativePlayer._try_play):
          Poll after 1 s:
            rc is None → still running → audio IS playing → wait to finish
            rc == 0    → short clip finished cleanly → success
            rc != 0    → player failed immediately → return False (try next)

        The wait loop polls every 0.5 s and honours stop_event for clean
        emergency preemption.  On timeout the player is terminated and we
        return True (it was playing — don't cascade to another backend).
        """
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                env=env,
            )
            self._current_proc = proc

            # 1-second liveness check
            time.sleep(1.0)
            rc = proc.poll()

            if rc is not None and rc != 0:
                err_raw = b""
                try:
                    err_raw = proc.stderr.read(200) if proc.stderr else b""
                except Exception:
                    pass
                msg = err_raw.decode(errors="replace").strip().splitlines()
                logger.debug(
                    f"[CVAS:TTSWorker] [{name}] failed immediately (rc={rc}): "
                    f"{msg[0] if msg else '(no stderr)'}"
                )
                return False   # try next backend

            if rc == 0:
                logger.info(f"[CVAS:TTSWorker] [{name}] ✓ done (short clip)")
                return True

            # rc is None — process is alive → audio is playing
            logger.info(f"[CVAS:TTSWorker] [{name}] ▶ playing speech")

            # Wait for natural finish with stop-event awareness
            deadline = time.time() + timeout_secs
            while time.time() < deadline:
                if self._stop_event.is_set():
                    proc.terminate()
                    logger.debug(f"[CVAS:TTSWorker] [{name}] interrupted by stop event")
                    return True

                try:
                    proc.wait(timeout=0.5)
                    logger.debug(f"[CVAS:TTSWorker] [{name}] ✓ finished (rc={proc.returncode})")
                    return True
                except subprocess.TimeoutExpired:
                    continue

            # Duration timeout — terminate cleanly; don't try another backend
            logger.warning(f"[CVAS:TTSWorker] [{name}] exceeded {timeout_secs}s — terminating")
            proc.terminate()
            return True   # it was playing — do not cascade

        except Exception as e:
            logger.warning(f"[CVAS:TTSWorker] [{name}] launch error: {e}")
            return False

    # ── Emergency preemption ──────────────────────────────────────────────────

    def interrupt_for_critical(self) -> None:
        """
        Stop current speech immediately when a CRITICAL Level-1 alert arrives.
        FIX (BUG-01): old condition was `priority > 10` which NEVER fires for
        critical alerts (priority=10). Correct logic: interrupt ANY ongoing
        speech regardless of its priority, because a new critical has arrived.
        """
        if self._current_item is None:
            return  # Nothing playing — nothing to interrupt

        logger.info(
            f"[CVAS:TTSWorker] ⚡ Emergency interrupt — halting "
            f"'{self._current_item.topic}' (priority={self._current_item.priority}) "
            f"for incoming CRITICAL alert"
        )
        if self.engine:
            try:
                self.engine.stop()
            except Exception:
                pass
        if self._current_proc:
            try:
                self._current_proc.terminate()
            except Exception:
                pass
