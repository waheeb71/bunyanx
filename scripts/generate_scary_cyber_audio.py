#!/usr/bin/env python3
"""
bunyanx NGFW -- Dark Cyber Threat Sound Synthesizer (Scary Cyber Edition)
=============================================================================
Generates ominous, tactical, dark-cyber security alert audio files (44.1 kHz PCM WAV).
Saves all sound files into a separate dedicated folder:
  <project_root>/var/audio/cyber_scary_alerts/

To activate this dark cyber sound pack in NGFW, set the environment variable:
  NGFW_AUDIO_DIR = F:\\enterprise_ngfw\\var\\audio\\cyber_scary_alerts
"""

import json
import math
import numpy as np
import scipy.io.wavfile as wavfile
from pathlib import Path

THIS_FILE    = Path(__file__).resolve()
PROJECT_ROOT = THIS_FILE.parent.parent
# Dedicated directory for Dark Cyber sounds -- separate from default alerts!
ALERTS_DIR   = PROJECT_ROOT / "var" / "audio" / "cyber_scary_alerts"
MANIFEST_PATH = ALERTS_DIR / "manifest.json"

SR = 44100   # sample rate 44.1kHz


def _t(dur_s: float) -> np.ndarray:
    return np.linspace(0, dur_s, int(SR * dur_s), endpoint=False)


def env_adsr(n: int, attack_ms: float = 5, decay_ms: float = 100, sustain: float = 0.7, release_ms: float = 100) -> np.ndarray:
    env = np.ones(n, dtype=np.float32)
    a = min(int(SR * attack_ms / 1000), n)
    d = min(int(SR * decay_ms / 1000), max(0, n - a))
    r = min(int(SR * release_ms / 1000), n)

    if a > 0:
        env[:a] = np.sin(np.linspace(0, math.pi / 2, a))
    if d > 0 and a + d <= n:
        env[a:a+d] = sustain + (1.0 - sustain) * np.cos(np.linspace(0, math.pi / 2, d))
    s_end = max(a + d, n - r)
    env[a+d:s_end] = sustain
    if r > 0 and s_end < n:
        env[s_end:] = sustain * np.cos(np.linspace(0, math.pi / 2, n - s_end))
    return env


def normalize(sig: np.ndarray, peak_db: float = -2.0) -> np.ndarray:
    peak = np.max(np.abs(sig))
    if peak > 0:
        target = 10 ** (peak_db / 20.0)
        sig = (sig / peak) * target
    return (sig * 32767.0).astype(np.int16)


# ══════════════════════════════════════════════════════════════════════════════
#  DARK CYBER SOUND GENERATORS
# ══════════════════════════════════════════════════════════════════════════════

def make_dark_cyber_threat() -> np.ndarray:
    """Dark Tactical Cyber Threat Stinger: Heavy sub-bass drop + sharp glitch sweep."""
    dur = 1.2
    t = _t(dur)
    n = len(t)
    
    freq_drop = 140.0 * (0.32 ** (t / dur))
    sub = np.sin(2 * math.pi * np.cumsum(freq_drop) / SR) * 0.8
    
    saw1 = np.mod(t * 146.83, 1.0) * 2.0 - 1.0  # D3
    saw2 = np.mod(t * 174.61, 1.0) * 2.0 - 1.0  # F3
    saw3 = np.mod(t * 220.00, 1.0) * 2.0 - 1.0  # A3
    synth = (saw1 * 0.4 + saw2 * 0.35 + saw3 * 0.35)
    
    fm_mod = np.sin(2 * math.pi * 35.0 * t) * 120.0
    glitch = np.sin(2 * math.pi * (880.0 + fm_mod) * t) * 0.3 * np.exp(-12.0 * t)
    
    sig = (sub + synth * 0.5 + glitch) * env_adsr(n, attack_ms=10, decay_ms=150, sustain=0.6, release_ms=250)
    return normalize(sig)


def make_malware_ominous_siren() -> np.ndarray:
    """Ominous Pulsing Cyber Siren: FM modulated dual emergency alarm + sub-rumble."""
    dur = 1.8
    t = _t(dur)
    n = len(t)
    
    mod = np.sin(2 * math.pi * 5.5 * t)
    freq = 600.0 + mod * 200.0
    
    siren = np.sign(np.sin(2 * math.pi * np.cumsum(freq) / SR)) * 0.6
    sub_rumble = np.sin(2 * math.pi * 55.0 * t) * 0.5
    
    pulse_env = (np.sin(2 * math.pi * 3.0 * t) > 0).astype(float) * 0.8 + 0.2
    
    sig = (siren * pulse_env + sub_rumble) * env_adsr(n, attack_ms=15, decay_ms=100, sustain=0.8, release_ms=200)
    return normalize(sig)


def make_brute_force_hacker_alarm() -> np.ndarray:
    """Intruder Alert Siren: Stuttering high-contrast dual-tone siren."""
    dur = 1.4
    t = _t(dur)
    n = len(t)
    
    tone_step = (np.sin(2 * math.pi * 10.0 * t) > 0).astype(float)
    freq = 680.0 + tone_step * 240.0
    
    tone = np.sign(np.sin(2 * math.pi * np.cumsum(freq) / SR)) * 0.7
    sub = np.sin(2 * math.pi * 65.0 * t) * 0.4
    
    sig = (tone + sub) * env_adsr(n, attack_ms=8, decay_ms=80, sustain=0.85, release_ms=120)
    return normalize(sig)


def make_dlp_breach_warning() -> np.ndarray:
    """Data Breach Warning: Ominous glissando minor chord sweep."""
    dur = 1.3
    t = _t(dur)
    n = len(t)
    
    sweep_freq = 650.0 * (0.34 ** (t / dur))
    sweep = np.sin(2 * math.pi * np.cumsum(sweep_freq) / SR) * 0.7
    
    ring = np.sin(2 * math.pi * 1320.0 * t) * np.sin(2 * math.pi * 440.0 * t) * 0.3
    
    sig = (sweep + ring) * env_adsr(n, attack_ms=12, decay_ms=200, sustain=0.5, release_ms=300)
    return normalize(sig)


def make_port_scan_sonar_ping() -> np.ndarray:
    """Dark Sonar Ping: Deep cyber radar scan ping with fast stutter beeps."""
    dur = 1.1
    t = _t(dur)
    n = len(t)
    
    ping1 = np.sin(2 * math.pi * 1150.0 * t) * np.exp(-8.0 * t) * 0.7
    ping2 = np.sin(2 * math.pi * 1450.0 * t) * np.exp(-12.0 * t) * 0.5
    sub = np.sin(2 * math.pi * 90.0 * t) * np.exp(-4.0 * t) * 0.5
    
    sig = (ping1 + ping2 + sub) * env_adsr(n, attack_ms=2, decay_ms=100, sustain=0.4, release_ms=200)
    return normalize(sig)


def make_system_failure_horn() -> np.ndarray:
    """System Collapse Horn: Heavy distorted industrial cyber alarm."""
    dur = 1.6
    t = _t(dur)
    n = len(t)
    
    horn1 = np.sign(np.sin(2 * math.pi * 220.0 * t)) * 0.5
    horn2 = np.sign(np.sin(2 * math.pi * 233.08 * t)) * 0.5
    sub = np.sin(2 * math.pi * 50.0 * t) * 0.6
    
    gate = (np.sin(2 * math.pi * 4.0 * t) > -0.2).astype(float)
    
    sig = (horn1 + horn2 + sub) * gate * env_adsr(n, attack_ms=10, decay_ms=120, sustain=0.8, release_ms=180)
    return normalize(sig)


def main():
    ALERTS_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Generating Dark Cyber Threat Sound Effects into separate folder:\n  -> {ALERTS_DIR}")

    sounds = {
        "threat_detected.wav":          make_dark_cyber_threat(),
        "response_block.wav":           make_dark_cyber_threat(),
        "waf_block.wav":                make_dark_cyber_threat(),
        "sqli.wav":                     make_dark_cyber_threat(),
        "rce.wav":                      make_dark_cyber_threat(),
        "xss.wav":                      make_dark_cyber_threat(),
        "path_traversal.wav":           make_dark_cyber_threat(),
        "malware_detected.wav":         make_malware_ominous_siren(),
        "malware_critical.wav":         make_malware_ominous_siren(),
        "auth_brute_force.wav":         make_brute_force_hacker_alarm(),
        "auth_hacker_alarm.wav":        make_brute_force_hacker_alarm(),
        "dlp_incident.wav":             make_dlp_breach_warning(),
        "ids_port_scan.wav":            make_port_scan_sonar_ping(),
        "system_core_failure.wav":      make_system_failure_horn(),
        "ha_failover.wav":              make_system_failure_horn(),
        "p3_generic.wav":               make_dark_cyber_threat(),
        "p4_generic.wav":               make_dark_cyber_threat(),
        "p5_generic.wav":               make_dark_cyber_threat(),
        "p6_generic.wav":               make_malware_ominous_siren(),
    }

    manifest_data = {}
    for filename, data in sounds.items():
        out_path = ALERTS_DIR / filename
        wavfile.write(out_path, SR, data)
        print(f"  [+] Created: {out_path.name} ({len(data)} samples)")
        
        stem = Path(filename).stem
        manifest_data[stem] = filename
        dot_stem = stem.replace("_", ".")
        manifest_data[dot_stem] = filename

    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=2, ensure_ascii=False)

    print(f"  [+] Created dedicated {MANIFEST_PATH.name} with dark cyber threat mappings.")
    print("=" * 65)
    print("SUCCESS: Dark Cyber Threat Audio files generated in separate folder!")
    print(f"Directory: {ALERTS_DIR}")
    print("=" * 65)


if __name__ == "__main__":
    main()
