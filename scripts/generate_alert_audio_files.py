#!/usr/bin/env python3
"""
bunyanx NGFW -- Production Alert Tone Synthesizer v2  (10/10 Edition)
======================================================================
Generates premium, enterprise-grade 44.1 kHz / 16-bit PCM WAV alert files.

Improvements over v1:
  - True per-harmonic exponential decay  --> realistic metallic chime/bell
  - Logarithmic frequency sweep          --> natural ear-correct sweep
  - Full 4-stage ADSR envelope           --> professional sound shaping
  - Convolution reverb tail              --> spatial depth on critical events
  - Repeated alarm pulses                --> urgency on emergency events
  - Rich soft-square (8 harmonics)       --> warm cyber pulse texture
  - FM modulation on sweep               --> sci-fi / SOC aesthetic
  - Normalized output with headroom      --> consistent loudness (-3 dBFS peak)
"""

import json
import math
import numpy as np
import scipy.io.wavfile as wavfile
from pathlib import Path

THIS_FILE    = Path(__file__).resolve()
PROJECT_ROOT = THIS_FILE.parent.parent
ALERTS_DIR   = PROJECT_ROOT / "var" / "audio" / "alerts"
MANIFEST_PATH = ALERTS_DIR / "manifest.json"

SR = 44100   # sample rate


# ══════════════════════════════════════════════════════════════════════════════
#  LOW-LEVEL SYNTHESIS PRIMITIVES
# ══════════════════════════════════════════════════════════════════════════════

def _t(dur_s: float) -> np.ndarray:
    """Time array for duration (seconds)."""
    return np.linspace(0, dur_s, int(SR * dur_s), endpoint=False)


def adsr(n: int,
         attack_ms: float = 12,
         decay_ms:  float = 60,
         sustain:   float = 0.75,
         release_ms:float = 80) -> np.ndarray:
    """Full 4-stage ADSR amplitude envelope, returns float32 array of length n."""
    env = np.ones(n, dtype=np.float32)
    a = min(int(SR * attack_ms  / 1000), n)
    d = min(int(SR * decay_ms   / 1000), n - a)
    r = min(int(SR * release_ms / 1000), n)

    # Attack: 0 -> 1  (quarter-sine curve — no click)
    if a > 0:
        env[:a] = np.sin(np.linspace(0, math.pi / 2, a))

    # Decay: 1 -> sustain  (exponential feel via cosine mapping)
    if d > 0:
        env[a:a+d] = sustain + (1.0 - sustain) * np.cos(
            np.linspace(0, math.pi / 2, d))

    # Sustain: constant
    s_start = a + d
    s_end   = max(s_start, n - r)
    env[s_start:s_end] = sustain

    # Release: sustain -> 0  (cosine, smooth)
    if r > 0 and s_end < n:
        env[s_end:] = sustain * np.cos(
            np.linspace(0, math.pi / 2, n - s_end))

    return env


def chime(freq: float, dur_s: float,
          vol: float = 0.55,
          decay_rate: float = 8.0) -> np.ndarray:
    """
    Metallic / crystalline chime with per-harmonic exponential decay.
    Each partial fades at 2x the rate of the one below -- mimics struck metal.
    """
    t = _t(dur_s)
    n = len(t)
    # harmonic series: amplitude * individual exp decay
    partials = [
        (1.00, 1.0,  decay_rate * 0.5),   # fundamental
        (0.55, 2.0,  decay_rate * 1.0),   # octave
        (0.30, 3.0,  decay_rate * 2.0),   # 5th (octave+5th)
        (0.15, 4.0,  decay_rate * 4.0),   # 2nd octave
        (0.08, 5.27, decay_rate * 8.0),   # major 3rd (inharmonic -- bell colour)
    ]
    sig = np.zeros(n, dtype=np.float64)
    for amp, ratio, dr in partials:
        decay = np.exp(-dr * t)
        sig  += amp * decay * np.sin(2 * math.pi * freq * ratio * t)

    # Normalise to [-1, 1] then scale to vol
    peak = np.max(np.abs(sig)) or 1.0
    sig  = (sig / peak) * vol

    # Short attack only (decay is handled per-partial above)
    n_atk = min(int(SR * 0.005), n)
    if n_atk > 0:
        sig[:n_atk] *= np.sin(np.linspace(0, math.pi / 2, n_atk))

    return sig.astype(np.float32)


def soft_pulse(freq: float, dur_s: float,
               vol: float = 0.60,
               n_harmonics: int = 9,
               atk_ms: float = 8,
               rel_ms: float = 60) -> np.ndarray:
    """
    Rich soft-square / cyber pulse: sum of odd harmonics with
    bandwidth-limited amplitude rolloff (1/k^1.4) for warmth.
    8 harmonics = thick but not harsh.
    """
    t   = _t(dur_s)
    sig = np.zeros(len(t), dtype=np.float64)
    for k in range(1, n_harmonics * 2, 2):          # odd harmonics: 1,3,5,7,...
        amp = 1.0 / (k ** 1.4)
        sig += amp * np.sin(2 * math.pi * freq * k * t)

    peak = np.max(np.abs(sig)) or 1.0
    sig  = (sig / peak) * vol
    env  = adsr(len(t), attack_ms=atk_ms, decay_ms=40, sustain=0.80, release_ms=rel_ms)
    return (sig * env).astype(np.float32)


def triangle_tone(freq: float, dur_s: float,
                  vol: float = 0.50,
                  atk_ms: float = 12,
                  rel_ms: float = 80) -> np.ndarray:
    """
    Clean triangle wave (warm, soft).  Uses Gibbs-free Fourier series.
    """
    t   = _t(dur_s)
    sig = np.zeros(len(t), dtype=np.float64)
    for k in range(1, 8, 2):
        amp = ((-1) ** ((k - 1) // 2)) / (k ** 2)
        sig += amp * np.sin(2 * math.pi * freq * k * t)
    sig *= (8 / (math.pi ** 2))

    peak = np.max(np.abs(sig)) or 1.0
    sig  = (sig / peak) * vol
    env  = adsr(len(t), attack_ms=atk_ms, decay_ms=50, sustain=0.75, release_ms=rel_ms)
    return (sig * env).astype(np.float32)


def log_sweep(f_start: float, f_end: float, dur_s: float,
              vol: float = 0.55,
              fm_depth: float = 0.0,
              fm_rate: float = 6.0) -> np.ndarray:
    """
    Logarithmic frequency sweep (ear-correct) with optional FM shimmer.
    fm_depth > 0 adds vibrato -- gives a sci-fi/digital texture.
    """
    t    = _t(dur_s)
    n    = len(t)
    # Log-spaced instantaneous frequency
    inst_f = np.logspace(math.log10(f_start), math.log10(f_end), n)
    # Optional FM modulation
    if fm_depth > 0:
        inst_f *= (1.0 + fm_depth * np.sin(2 * math.pi * fm_rate * t))
    # Integrate to get phase
    phase = 2 * math.pi * np.cumsum(inst_f) / SR
    sig   = np.sin(phase)

    peak = np.max(np.abs(sig)) or 1.0
    sig  = (sig / peak) * vol
    env  = adsr(n, attack_ms=5, decay_ms=30, sustain=0.85, release_ms=60)
    return (sig * env).astype(np.float32)


def sine_tone(freq: float, dur_s: float,
              vol: float = 0.45,
              warm: float = 0.20,
              atk_ms: float = 12,
              rel_ms: float = 70) -> np.ndarray:
    """
    Pure sine + subtle 2nd harmonic (warm overtone).
    warm=0 → pure sine, warm=0.20 → slightly full.
    """
    t   = _t(dur_s)
    sig = np.sin(2 * math.pi * freq * t)
    if warm > 0:
        sig += warm * np.sin(4 * math.pi * freq * t)
    peak = np.max(np.abs(sig)) or 1.0
    sig  = (sig / peak) * vol
    env  = adsr(len(t), attack_ms=atk_ms, decay_ms=40, sustain=0.80, release_ms=rel_ms)
    return (sig * env).astype(np.float32)


def reverb_tail(signal: np.ndarray,
                tail_ms: float = 250,
                decay: float = 6.0) -> np.ndarray:
    """
    Adds a simple exponential reverb tail after the signal ends.
    Convolves the last slice with a decaying noise IR for spatial depth.
    """
    n_tail = int(SR * tail_ms / 1000)
    t_ir   = np.linspace(0, tail_ms / 1000, n_tail)
    ir     = np.exp(-decay * t_ir) * np.random.randn(n_tail).astype(np.float32) * 0.08
    # Only reverb the last 50 ms of the source
    seed_samples = min(int(SR * 0.05), len(signal))
    seed = signal[-seed_samples:]
    tail = np.convolve(seed, ir, mode='full')[:n_tail]
    return np.concatenate([signal, tail])


# ══════════════════════════════════════════════════════════════════════════════
#  SEQUENCE BUILDER
# ══════════════════════════════════════════════════════════════════════════════

def seq(*parts, gap_ms: float = 40) -> np.ndarray:
    """Concatenate audio parts with a silence gap between them."""
    gap = np.zeros(int(SR * gap_ms / 1000), dtype=np.float32)
    out = []
    for i, p in enumerate(parts):
        out.append(p)
        if i < len(parts) - 1:
            out.append(gap)
    return np.concatenate(out).astype(np.float32)


def repeat_seq(audio: np.ndarray, times: int, gap_ms: float = 180) -> np.ndarray:
    """Repeat an audio sequence N times with silence between repetitions."""
    gap = np.zeros(int(SR * gap_ms / 1000), dtype=np.float32)
    parts = []
    for i in range(times):
        parts.append(audio)
        if i < times - 1:
            parts.append(gap)
    return np.concatenate(parts).astype(np.float32)


def normalise(signal: np.ndarray, target_db: float = -3.0) -> np.ndarray:
    """Peak-normalise to target dBFS.  Prevents clipping."""
    peak = np.max(np.abs(signal))
    if peak < 1e-9:
        return signal
    target_amp = 10 ** (target_db / 20.0)
    return np.clip(signal * (target_amp / peak), -1.0, 1.0).astype(np.float32)


def save(filename: str, audio: np.ndarray) -> Path:
    """Normalise then save as 16-bit PCM WAV."""
    ALERTS_DIR.mkdir(parents=True, exist_ok=True)
    audio = normalise(audio)
    path  = ALERTS_DIR / filename
    wavfile.write(path, SR, (audio * 32767).astype(np.int16))
    return path


# ══════════════════════════════════════════════════════════════════════════════
#  TONE LIBRARY  (46 events)
# ══════════════════════════════════════════════════════════════════════════════

def generate_all() -> dict:
    manifest = {}

    def build(event: str, filename: str, audio: np.ndarray):
        p = save(filename, audio)
        manifest[event] = filename
        print(f"  [OK] {event:35s} -> {filename}  ({p.stat().st_size // 1024} KB)")

    print("=" * 65)
    print("  bunyanx NGFW - Synthesizing Production Alert Tones v2")
    print("=" * 65)

    # ── INFORMATIONAL: gentle ascending chimes ─────────────────────────
    print("\n[L1] Informational")

    build("auth_login_success", "auth_login_success.wav",
          seq(chime(659, 0.18),          # E5
              chime(784, 0.20),          # G5
              chime(1047, 0.45, decay_rate=5.0),  # C6 — long ring
              gap_ms=25))

    build("system_started", "system_started.wav",
          seq(chime(523, 0.15),          # C5
              chime(659, 0.15),          # E5
              chime(784, 0.18),          # G5
              chime(1047, 0.55, vol=0.60, decay_rate=4.0),   # C6
              gap_ms=30))

    build("module_started", "module_started.wav",
          seq(chime(880, 0.12),
              chime(1047, 0.30, decay_rate=6.0),
              gap_ms=20))

    build("config_saved", "config_saved.wav",
          seq(chime(1047, 0.10),
              chime(1319, 0.28, decay_rate=6.0),
              gap_ms=18))

    build("config_reloaded", "config_reloaded.wav",
          seq(chime(523, 0.10),
              chime(659, 0.10),
              chime(784, 0.12),
              chime(1047, 0.35, decay_rate=5.0),
              gap_ms=20))

    build("intel_updated", "intel_updated.wav",
          seq(log_sweep(600, 900, 0.14, fm_depth=0.01),
              chime(880, 0.28, decay_rate=6.0),
              gap_ms=20))

    build("ai_score_generated", "ai_score_generated.wav",
          seq(log_sweep(700, 1100, 0.16, fm_depth=0.015, fm_rate=8),
              chime(1175, 0.35, decay_rate=5.5),
              gap_ms=22))

    # ── NOTICE: clean descending / neutral ────────────────────────────
    print("\n[L2] Notice")

    build("system_shutdown", "system_shutdown.wav",
          seq(chime(1047, 0.18),
              chime(784,  0.18),
              chime(659,  0.18),
              chime(523,  0.50, decay_rate=4.0),
              gap_ms=30))

    build("module_stopped", "module_stopped.wav",
          seq(chime(880, 0.14),
              chime(440, 0.30, decay_rate=5.0),
              gap_ms=25))

    build("module_health", "module_health.wav",
          chime(660, 0.25, decay_rate=7.0))

    build("vpn_restored", "vpn_restored.wav",
          seq(chime(440, 0.14),
              chime(660, 0.35, decay_rate=5.0),
              gap_ms=22))

    build("siem_incident_closed", "siem_incident_closed.wav",
          seq(chime(880, 0.12),
              chime(1047, 0.40, decay_rate=5.0),
              gap_ms=22))

    # ── WARNING: clear gentle double-pulses ────────────────────────────
    print("\n[L3] Warning")

    build("auth_login_failure", "auth_login_failure.wav",
          seq(triangle_tone(220, 0.15, vol=0.55),
              triangle_tone(196, 0.22, vol=0.50, rel_ms=120),
              gap_ms=80))

    build("pki_cert_expiring", "pki_cert_expiring.wav",
          repeat_seq(
              seq(sine_tone(440, 0.18, vol=0.50), gap_ms=0),
              times=2, gap_ms=200))

    build("response_alert", "response_alert.wav",
          seq(triangle_tone(330, 0.14, vol=0.52),
              triangle_tone(440, 0.18, vol=0.52, rel_ms=100),
              gap_ms=70))

    build("web_filter_block", "web_filter_block.wav",
          seq(sine_tone(440, 0.12, vol=0.48),
              sine_tone(330, 0.18, vol=0.44, rel_ms=100),
              gap_ms=60))

    # ── SECURITY ALERT: crisp cyber pulses ────────────────────────────
    print("\n[L4] Security Alert")

    build("threat_detected", "threat_detected.wav",
          seq(soft_pulse(880, 0.12, vol=0.65),
              soft_pulse(660, 0.12, vol=0.60),
              soft_pulse(880, 0.18, vol=0.65, rel_ms=80),
              gap_ms=55))

    build("threat_detected_alt1", "threat_detected_alt1.wav",
          seq(log_sweep(700, 1100, 0.15, vol=0.60, fm_depth=0.02),
              soft_pulse(1100, 0.18, vol=0.63, rel_ms=80),
              gap_ms=50))

    build("response_block", "response_block.wav",
          seq(soft_pulse(660, 0.09, vol=0.65, atk_ms=5),
              soft_pulse(880, 0.16, vol=0.68, atk_ms=5, rel_ms=70),
              gap_ms=40))

    build("response_quarantine", "response_quarantine.wav",
          seq(triangle_tone(440, 0.14, vol=0.58),
              triangle_tone(330, 0.18, vol=0.55, rel_ms=100),
              gap_ms=65))

    build("ids_port_scan", "ids_port_scan.wav",
          seq(soft_pulse(880,  0.08, vol=0.60, atk_ms=4, n_harmonics=6),
              soft_pulse(1100, 0.08, vol=0.60, atk_ms=4, n_harmonics=6),
              soft_pulse(880,  0.10, vol=0.60, atk_ms=4, n_harmonics=6),
              gap_ms=40))

    build("ids_port_scan_warning", "ids_port_scan_warning.wav",
          seq(soft_pulse(700, 0.09, vol=0.55, atk_ms=5),
              soft_pulse(900, 0.12, vol=0.55, atk_ms=5),
              gap_ms=50))

    build("anomaly_scored", "anomaly_scored.wav",
          seq(log_sweep(480, 750, 0.16, vol=0.55, fm_depth=0.018, fm_rate=7),
              triangle_tone(440, 0.20, vol=0.52, rel_ms=110),
              gap_ms=55))

    build("dns_suspicious", "dns_suspicious.wav",
          seq(triangle_tone(440, 0.12, vol=0.52),
              triangle_tone(550, 0.15, vol=0.52, rel_ms=90),
              gap_ms=55))

    build("dns_threat", "dns_threat.wav",
          seq(soft_pulse(440, 0.14, vol=0.58, n_harmonics=7),
              soft_pulse(550, 0.17, vol=0.58, n_harmonics=7, rel_ms=80),
              gap_ms=60))

    build("vpn_failure", "vpn_failure.wav",
          seq(soft_pulse(330, 0.16, vol=0.62),
              soft_pulse(220, 0.22, vol=0.58, rel_ms=120),
              gap_ms=85))

    build("correlation_triggered", "correlation_triggered.wav",
          seq(sine_tone(660,  0.10, vol=0.58),
              sine_tone(880,  0.10, vol=0.58),
              sine_tone(1100, 0.16, vol=0.62, rel_ms=80),
              gap_ms=40))

    build("siem_incident_created", "siem_incident_created.wav",
          seq(soft_pulse(880, 0.12, vol=0.63),
              soft_pulse(660, 0.15, vol=0.58, rel_ms=80),
              gap_ms=65))

    build("waf_block", "waf_block.wav",
          seq(soft_pulse(880, 0.07, vol=0.63, atk_ms=4),
              soft_pulse(660, 0.07, vol=0.63, atk_ms=4),
              soft_pulse(440, 0.12, vol=0.67, atk_ms=4, rel_ms=70),
              gap_ms=32))

    build("waf_alert", "waf_alert.wav",
          seq(soft_pulse(660, 0.12, vol=0.58),
              soft_pulse(880, 0.15, vol=0.58, rel_ms=75),
              gap_ms=55))

    build("email_threat", "email_threat.wav",
          seq(triangle_tone(330, 0.14, vol=0.52),
              triangle_tone(440, 0.17, vol=0.52, rel_ms=100),
              gap_ms=55))

    # ── CRITICAL: distinct professional alarm pulses ───────────────────
    print("\n[L5] Critical")

    build("malware_detected", "malware_detected.wav",
          repeat_seq(
              seq(soft_pulse(880, 0.13, vol=0.72, atk_ms=4),
                  soft_pulse(660, 0.13, vol=0.68, atk_ms=4),
                  soft_pulse(880, 0.17, vol=0.72, atk_ms=4, rel_ms=70),
                  gap_ms=55),
              times=2, gap_ms=150))

    build("malware_critical", "malware_critical.wav",
          repeat_seq(
              seq(log_sweep(850, 1300, 0.12, vol=0.78, fm_depth=0.025),
                  log_sweep(1300, 900, 0.14, vol=0.78, fm_depth=0.025),
                  gap_ms=45),
              times=2, gap_ms=140))

    build("auth_brute_force", "auth_brute_force.wav",
          repeat_seq(
              seq(soft_pulse(220, 0.09, vol=0.70, atk_ms=3, n_harmonics=7),
                  soft_pulse(330, 0.09, vol=0.70, atk_ms=3, n_harmonics=7),
                  soft_pulse(220, 0.09, vol=0.70, atk_ms=3, n_harmonics=7),
                  soft_pulse(330, 0.13, vol=0.70, atk_ms=3, n_harmonics=7),
                  gap_ms=40),
              times=2, gap_ms=140))

    build("auth_hacker_alarm", "auth_hacker_alarm.wav",
          repeat_seq(
              seq(log_sweep(800, 1400, 0.14, vol=0.73, fm_depth=0.02, fm_rate=9),
                  log_sweep(1400, 800, 0.14, vol=0.73, fm_depth=0.02, fm_rate=9),
                  gap_ms=40),
              times=2, gap_ms=130))

    build("dlp_incident", "dlp_incident.wav",
          repeat_seq(
              seq(soft_pulse(660, 0.16, vol=0.72, n_harmonics=8),
                  soft_pulse(440, 0.20, vol=0.70, n_harmonics=8, rel_ms=90),
                  gap_ms=60),
              times=2, gap_ms=150))

    build("pki_cert_invalid", "pki_cert_invalid.wav",
          repeat_seq(
              seq(soft_pulse(440, 0.16, vol=0.67),
                  soft_pulse(330, 0.20, vol=0.65, rel_ms=100),
                  gap_ms=65),
              times=2, gap_ms=160))

    build("ha_failover", "ha_failover.wav",
          reverb_tail(
              repeat_seq(
                  seq(soft_pulse(880, 0.17, vol=0.78, atk_ms=4, n_harmonics=8),
                      soft_pulse(440, 0.20, vol=0.76, atk_ms=4, n_harmonics=8, rel_ms=90),
                      gap_ms=60),
                  times=3, gap_ms=140),
              tail_ms=280, decay=5.5))

    build("system_memory_critical", "system_memory_critical.wav",
          repeat_seq(
              seq(soft_pulse(550, 0.13, vol=0.68),
                  soft_pulse(660, 0.16, vol=0.68, rel_ms=80),
                  gap_ms=55),
              times=2, gap_ms=150))

    build("system_cpu_critical", "system_cpu_critical.wav",
          repeat_seq(
              seq(soft_pulse(660, 0.13, vol=0.68),
                  soft_pulse(880, 0.16, vol=0.68, rel_ms=80),
                  gap_ms=55),
              times=2, gap_ms=150))

    build("siem_incident_escalated", "siem_incident_escalated.wav",
          repeat_seq(
              seq(soft_pulse(880, 0.11, vol=0.73, atk_ms=4),
                  soft_pulse(660, 0.11, vol=0.68, atk_ms=4),
                  soft_pulse(880, 0.16, vol=0.73, atk_ms=4, rel_ms=75),
                  gap_ms=52),
              times=2, gap_ms=145))

    # ── EMERGENCY: max urgency, reverb depth ──────────────────────────
    print("\n[L6] Emergency")

    # system_core_failure: repeating alternating siren with reverb tail
    _siren_pulse = seq(
        soft_pulse(960, 0.18, vol=0.85, atk_ms=3, n_harmonics=9),
        soft_pulse(480, 0.22, vol=0.83, atk_ms=3, n_harmonics=9, rel_ms=80),
        gap_ms=50)
    build("system_core_failure", "system_core_failure.wav",
          reverb_tail(
              repeat_seq(_siren_pulse, times=4, gap_ms=120),
              tail_ms=350, decay=4.5))

    # ── PRIORITY FALLBACKS ────────────────────────────────────────────
    print("\n[Fallbacks]")

    build("p3_generic", "p3_generic.wav",
          seq(triangle_tone(330, 0.14, vol=0.52),
              triangle_tone(440, 0.18, vol=0.52, rel_ms=100),
              gap_ms=65))

    build("p4_generic", "p4_generic.wav",
          seq(soft_pulse(660, 0.12, vol=0.62),
              soft_pulse(880, 0.17, vol=0.62, rel_ms=80),
              gap_ms=55))

    build("p5_generic", "p5_generic.wav",
          repeat_seq(
              seq(soft_pulse(880, 0.13, vol=0.72),
                  soft_pulse(660, 0.16, vol=0.70, rel_ms=80),
                  gap_ms=55),
              times=2, gap_ms=140))

    build("p6_generic", "p6_generic.wav",
          reverb_tail(
              repeat_seq(
                  seq(soft_pulse(960, 0.16, vol=0.82, atk_ms=3),
                      soft_pulse(480, 0.20, vol=0.80, atk_ms=3, rel_ms=80),
                      gap_ms=50),
                  times=3, gap_ms=130),
              tail_ms=300, decay=5.0))

    # ── Overwrite multi-sound array entries ───────────────────────────
    manifest["auth_brute_force"] = ["auth_brute_force.wav", "auth_hacker_alarm.wav"]
    manifest["threat_detected"]  = ["threat_detected.wav",  "threat_detected_alt1.wav"]
    manifest["malware_detected"] = ["malware_detected.wav", "malware_critical.wav"]
    manifest["ids_port_scan"]    = ["ids_port_scan.wav",    "ids_port_scan_warning.wav"]

    return manifest


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def main():
    manifest = generate_all()

    print(f"\n[MANIFEST] Writing {MANIFEST_PATH} ...")
    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
    print(f"  [OK] Manifest updated  ({len(manifest)} entries)\n")

    total_kb = sum(
        (ALERTS_DIR / v[0] if isinstance(v, list) else ALERTS_DIR / v).stat().st_size
        for v in manifest.values()
        if (ALERTS_DIR / (v[0] if isinstance(v, list) else v)).exists()
    ) // 1024

    print(f"[DONE] {len(manifest)} production tones ready  |  ~{total_kb} KB total")
    print(f"       Audio directory: {ALERTS_DIR}")


if __name__ == "__main__":
    np.random.seed(42)   # reproducible reverb noise
    main()
