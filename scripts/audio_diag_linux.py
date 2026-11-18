#!/usr/bin/env python3
"""
bunyanx NGFW — Audio Playback Diagnostic (Linux)
=================================================
Run this directly on the Ubuntu server to find out WHY sound isn't playing.
Usage:  python3 scripts/audio_diag_linux.py
"""

import os
import sys
import shutil
import subprocess
import time
from pathlib import Path

SEP  = "=" * 60
PASS = "[OK] "
FAIL = "[ERR]"
WARN = "[WRN]"
INFO = "[INF]"

def run(cmd, timeout=5):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except FileNotFoundError:
        return -2, "", f"command not found: {cmd[0]}"
    except Exception as e:
        return -3, "", str(e)

print(SEP)
print("  bunyanx NGFW — Linux Audio Diagnostic")
print(SEP)

# ── 1. Find audio file ───────────────────────────────────────────────────
print("\n[1] Locating audio file...")
script_dir   = Path(__file__).resolve().parent
project_root = script_dir.parent
candidates   = [
    project_root / "var" / "audio" / "alerts" / "p3_generic.mp3",
    Path("/var/lib/ngfw/audio/alerts/p3_generic.mp3"),
    Path("/home/bunyanx/Desktop/BUNYANX/var/audio/alerts/p3_generic.mp3"),
]
audio_file = None
for c in candidates:
    if c.exists():
        audio_file = c
        print(f"  {PASS} Found: {c}")
        break
if not audio_file:
    print(f"  {FAIL} No audio file found in:")
    for c in candidates: print(f"       {c}")
    print("       Please run: sudo bash scripts/install_audio.sh")
    sys.exit(1)

# ── 2. Check audio players ───────────────────────────────────────────────
print("\n[2] Checking installed audio players...")
PLAYERS = ["mpg123", "mpg321", "ffplay", "paplay", "aplay", "cvlc", "mplayer"]
available = []
for p in PLAYERS:
    path = shutil.which(p)
    if path:
        available.append(p)
        print(f"  {PASS} {p:10s} → {path}")
    else:
        print(f"  {INFO} {p:10s} → not installed")
if not available:
    print(f"\n  {FAIL} No audio player found!")
    print("       Fix: sudo apt install mpg123")
    sys.exit(1)

# ── 3. Check audio devices ───────────────────────────────────────────────
print("\n[3] Checking audio devices...")

# ALSA
rc, out, err = run(["aplay", "-l"])
if rc == 0 and out:
    print(f"  {PASS} ALSA devices found:")
    for line in out.splitlines()[:5]:
        print(f"        {line}")
else:
    print(f"  {WARN} ALSA device list: {err or '(empty output)'}")

# PulseAudio
rc, out, err = run(["pactl", "info"])
if rc == 0:
    for line in out.splitlines():
        if "Server Name" in line or "Default Sink" in line or "Default Source" in line:
            print(f"  {PASS} PulseAudio: {line.strip()}")
else:
    print(f"  {WARN} PulseAudio not running or not accessible")

# PipeWire
rc, out, err = run(["pw-cli", "info", "0"])
if rc == 0:
    print(f"  {PASS} PipeWire is running")
else:
    print(f"  {INFO} PipeWire: not detected")

# Environment
xdg = os.environ.get("XDG_RUNTIME_DIR", "")
display = os.environ.get("DISPLAY", "")
wayland = os.environ.get("WAYLAND_DISPLAY", "")
pulse_server = os.environ.get("PULSE_SERVER", "")
print(f"\n  {INFO} User: {os.getenv('USER', os.getenv('LOGNAME', 'unknown'))}")
print(f"  {INFO} XDG_RUNTIME_DIR: {xdg or '(not set)'}")
print(f"  {INFO} DISPLAY:         {display or '(not set)'}")
print(f"  {INFO} WAYLAND_DISPLAY: {wayland or '(not set)'}")
print(f"  {INFO} PULSE_SERVER:    {pulse_server or '(not set)'}")

if not xdg:
    print(f"  {WARN} XDG_RUNTIME_DIR not set — PulseAudio may not work for this user/service")

# ── 4. Test playback with each player ───────────────────────────────────
print(f"\n[4] Testing playback with each available player...")
print(f"    File: {audio_file}")

player_results = {}
for player in available:
    if player == "mpg123":
        cmd = ["mpg123", "-q", "-g", "70", str(audio_file)]
    elif player == "mpg321":
        cmd = ["mpg321", "-q", "-g", "70", str(audio_file)]
    elif player == "ffplay":
        cmd = ["ffplay", "-nodisp", "-autoexit", "-loglevel", "quiet",
               "-t", "3", str(audio_file)]
    elif player == "paplay":
        cmd = ["paplay", str(audio_file)]
    elif player == "aplay":
        cmd = ["aplay", str(audio_file)]
    elif player == "cvlc":
        cmd = ["cvlc", "--intf", "dummy", "--play-and-exit", str(audio_file)]
    elif player == "mplayer":
        cmd = ["mplayer", "-really-quiet", "-ao", "alsa", str(audio_file)]
    else:
        continue

    print(f"\n  Testing {player}...")
    print(f"    CMD: {' '.join(cmd)}")

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        time.sleep(1.0)  # wait 1s then check

        if proc.poll() is None:
            print(f"    {PASS} {player} is RUNNING (process alive after 1s) ← probably working!")
            player_results[player] = "RUNNING"
            proc.wait(timeout=10)
        else:
            rc = proc.returncode
            stderr = proc.stderr.read().decode(errors="replace").strip()
            if rc == 0:
                print(f"    {PASS} {player} finished OK (rc=0)")
                player_results[player] = "OK"
            else:
                print(f"    {FAIL} {player} failed (rc={rc})")
                if stderr:
                    print(f"         Error: {stderr[:300]}")
                player_results[player] = f"FAILED rc={rc}"
    except Exception as e:
        print(f"    {FAIL} {player} exception: {e}")
        player_results[player] = f"EXCEPTION: {e}"

# ── 5. ALSA device test ──────────────────────────────────────────────────
if "mpg123" in available:
    print(f"\n[5] Testing explicit ALSA devices with mpg123...")
    for dev in ["default", "hw:0,0", "plughw:0,0", "hw:1,0", "plughw:1,0"]:
        cmd = ["mpg123", "-a", dev, "-q", "-g", "70", str(audio_file)]
        print(f"  Testing device '{dev}'...", end=" ", flush=True)
        rc, out, err = run(cmd, timeout=5)
        if rc == 0:
            print(f"{PASS} WORKS!")
        else:
            snippet = err[:100].replace("\n", " ")
            print(f"{FAIL} rc={rc} — {snippet}")

# ── 6. Summary ──────────────────────────────────────────────────────────
print(f"\n{SEP}")
print("  SUMMARY")
print(SEP)
working = [p for p, r in player_results.items() if r in ("OK", "RUNNING")]
if working:
    print(f"  {PASS} Working player(s): {', '.join(working)}")
    print()
    print("  If you STILL don't hear sound, the issue is the audio output device.")
    print("  On a headless server or SSH session without audio forwarding,")
    print("  sound cannot play through speakers remotely.")
    print()
    print("  Solutions:")
    print("   A) Run the firewall directly on the physical machine (not via SSH)")
    print("   B) Use SSH with audio forwarding: ssh -X user@server")
    print("   C) Connect a speaker to the server and run as desktop user (not root/service)")
else:
    print(f"  {FAIL} No working player found!")
    print()
    print("  Fix options:")
    print("   1. Install mpg123:    sudo apt install mpg123")
    print("   2. Install ffmpeg:    sudo apt install ffmpeg")
    print("   3. Start PulseAudio:  pulseaudio --start")
    print("   4. Check ALSA:        sudo alsa force-reload")
print(SEP)
