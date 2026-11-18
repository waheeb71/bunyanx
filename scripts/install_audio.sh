#!/usr/bin/env bash
# =============================================================================
# install_audio.sh — Deploy bunyanx NGFW Audio System on Linux
# =============================================================================
# 1. Installs required audio player (mpg123)
# 2. Copies var/audio/alerts/ to production path
#
# Usage:
#   sudo bash scripts/install_audio.sh
#   sudo bash scripts/install_audio.sh /custom/audio/alerts
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SOURCE_DIR="$PROJECT_ROOT/var/audio/alerts"

# Resolve destination
if [[ -n "${1:-}" ]]; then
    DEST_DIR="$1"
elif [[ -n "${NGFW_AUDIO_DIR:-}" ]]; then
    DEST_DIR="$NGFW_AUDIO_DIR"
elif [[ -n "${NGFW_VAR_DIR:-}" ]]; then
    DEST_DIR="$NGFW_VAR_DIR/audio/alerts"
else
    # Default: use project var/ (auto-detected by NativePlayer)
    DEST_DIR="$PROJECT_ROOT/var/audio/alerts"
fi

echo "============================================================"
echo "  bunyanx NGFW — Audio System Installer (Linux)"
echo "============================================================"
echo "  Source : $SOURCE_DIR"
echo "  Dest   : $DEST_DIR"
echo ""

# ── 1. Install mpg123 (MP3 player) ────────────────────────────────────
echo "[1/3] Checking audio player..."
if command -v mpg123 &>/dev/null; then
    echo "  [OK]  mpg123 already installed: $(mpg123 --version 2>&1 | head -1)"
elif command -v ffplay &>/dev/null; then
    echo "  [OK]  ffplay available (mpg123 preferred): $(ffplay -version 2>&1 | head -1)"
else
    echo "  Installing mpg123..."
    if command -v apt-get &>/dev/null; then
        apt-get install -y -q mpg123
    elif command -v dnf &>/dev/null; then
        dnf install -y mpg123
    elif command -v yum &>/dev/null; then
        yum install -y mpg123
    else
        echo "  [WARN] Could not install mpg123 automatically."
        echo "         Please run: sudo apt install mpg123"
    fi
    command -v mpg123 &>/dev/null && echo "  [OK]  mpg123 installed" || echo "  [WARN] mpg123 not found"
fi

# ── 2. Copy audio files ────────────────────────────────────────────────
echo ""
echo "[2/3] Deploying audio files..."

if [[ ! -d "$SOURCE_DIR" ]]; then
    echo "  [WARN] Source directory not found: $SOURCE_DIR"
    echo "         Audio files will be read from project var/ directory (auto-detect)"
else
    MP3_COUNT=$(find "$SOURCE_DIR" -name "*.mp3" 2>/dev/null | wc -l)

    if [[ "$MP3_COUNT" -eq 0 ]]; then
        echo "  [WARN] No MP3 files in $SOURCE_DIR"
    else
        mkdir -p "$DEST_DIR"
        cp -v "$SOURCE_DIR"/*.mp3        "$DEST_DIR/" 2>/dev/null || true
        cp -v "$SOURCE_DIR"/manifest.json "$DEST_DIR/" 2>/dev/null || true
        chmod 644 "$DEST_DIR"/*.mp3       2>/dev/null || true
        chmod 644 "$DEST_DIR"/manifest.json 2>/dev/null || true

        INSTALLED=$(find "$DEST_DIR" -name "*.mp3" 2>/dev/null | wc -l)
        echo "  [OK]  $INSTALLED MP3 files → $DEST_DIR"
    fi
fi

# ── 3. Test playback ───────────────────────────────────────────────────
echo ""
echo "[3/3] Testing audio playback..."

TEST_FILE=$(find "$DEST_DIR" -name "*.mp3" 2>/dev/null | head -1 || true)
if [[ -z "$TEST_FILE" ]]; then
    TEST_FILE=$(find "$SOURCE_DIR" -name "*.mp3" 2>/dev/null | head -1 || true)
fi

if [[ -n "$TEST_FILE" ]] && command -v mpg123 &>/dev/null; then
    echo "  Playing 2s of: $(basename "$TEST_FILE")"
    mpg123 -q -T 2 "$TEST_FILE" 2>/dev/null && echo "  [OK]  Audio playback works!" || echo "  [WARN] Playback test failed (may be headless server)"
elif [[ -n "$TEST_FILE" ]] && command -v ffplay &>/dev/null; then
    ffplay -nodisp -autoexit -loglevel quiet -t 2 "$TEST_FILE" 2>/dev/null && echo "  [OK]  Audio playback works!" || echo "  [WARN] Playback test failed (may be headless server)"
else
    echo "  [SKIP] No test file or player available"
fi

echo ""
echo "============================================================"
echo "  Installation complete!"
echo ""
echo "  NativePlayer path resolution order:"
echo "    1. NGFW_AUDIO_DIR env var  (currently: ${NGFW_AUDIO_DIR:-not set})"
echo "    2. NGFW_VAR_DIR/audio/alerts  (currently: ${NGFW_VAR_DIR:-not set})"
echo "    3. Auto-detect: $PROJECT_ROOT/var/audio/alerts"
echo "============================================================"
