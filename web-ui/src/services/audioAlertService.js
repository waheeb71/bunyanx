/**
 * bunyanx NGFW — Audio Alert Service
 * =====================================
 * Hybrid audio pipeline:
 *
 *   Priority 1–2 (Informational / Notice)
 *     → Server sends SSE with sound_profile.tones
 *     → Browser plays synthesized tones via Web Audio API (AudioEngine)
 *
 *   Priority 3+ (Warning, Security Alert, Critical, Emergency)
 *     → Server plays MP3 natively via NativePlayer
 *     → Browser receives SSE for visual notification only (no audio)
 *
 * SSE endpoint: GET /api/audio/events/stream
 */

import audioEngine from './AudioEngine.js';

// Priority thresholds (must match backend AudioPriority)
const PRIORITY_INFORMATIONAL = 1;
const PRIORITY_NOTICE        = 2;
const PRIORITY_WARNING       = 3;  // 3+ handled server-side

class AudioAlertService {
  constructor() {
    this._unlocked    = false;
    this._needsUnlock = true;
    this._muted       = false;
    this._volume      = 0.7;

    this._onNotificationCallbacks = [];
    this._onUnlockCallbacks       = [];
  }

  // ── Unlock (required on first user interaction) ───────────────────

  async unlock() {
    const ok = await audioEngine.unlock();
    if (ok) {
      this._unlocked   = true;
      this._needsUnlock = false;
      this._onUnlockCallbacks.forEach(cb => { try { cb(); } catch (_) {} });
    }
    return ok;
  }

  isUnlocked()  { return this._unlocked; }
  needsUnlock() { return this._needsUnlock; }

  onUnlock(callback) {
    if (this._unlocked) {
      try { callback(); } catch (_) {}
      return () => {};
    }
    this._onUnlockCallbacks.push(callback);
    return () => {
      this._onUnlockCallbacks = this._onUnlockCallbacks.filter(cb => cb !== callback);
    };
  }

  // ── UI Tones: triggered directly by frontend events ───────────────
  // These play in the browser instantly without going through SSE/EventBus.

  /**
   * Play a predefined UI tone by type.
   * @param {'login' | 'logout' | 'error' | 'pressure'} type
   */
  async playUiTone(type) {
    if (this._muted) return;

    // Auto-unlock silently on first UI interaction
    if (!this._unlocked) {
      const ok = await audioEngine.unlock();
      if (!ok) return;
      this._unlocked    = true;
      this._needsUnlock = false;
    }

    audioEngine.setVolume(this._volume);

    const UI_TONES = {
      // تسجيل دخول: ثلاث نغمات تصاعدية خفيفة — C5 → E5 → G5 → C6
      login: {
        tones: [
          { frequency_hz: 523, duration_ms: 90,  waveform: 'sine', volume: 0.35, attack_ms: 10, decay_ms: 30, sustain_level: 0.6, release_ms: 50 },
          { frequency_hz: 659, duration_ms: 90,  waveform: 'sine', volume: 0.38, attack_ms: 10, decay_ms: 30, sustain_level: 0.6, release_ms: 50 },
          { frequency_hz: 784, duration_ms: 90,  waveform: 'sine', volume: 0.40, attack_ms: 10, decay_ms: 30, sustain_level: 0.6, release_ms: 50 },
          { frequency_hz: 1047, duration_ms: 160, waveform: 'sine', volume: 0.45, attack_ms: 10, decay_ms: 40, sustain_level: 0.65, release_ms: 80 },
        ],
        repeat: 1, gap_ms: 0,
      },

      // تسجيل خروج: نغمتان تنازليتان هادئتان — G5 → E5 → C5
      logout: {
        tones: [
          { frequency_hz: 784, duration_ms: 100, waveform: 'sine', volume: 0.30, attack_ms: 15, decay_ms: 35, sustain_level: 0.55, release_ms: 70 },
          { frequency_hz: 659, duration_ms: 100, waveform: 'sine', volume: 0.28, attack_ms: 15, decay_ms: 35, sustain_level: 0.50, release_ms: 70 },
          { frequency_hz: 523, duration_ms: 180, waveform: 'sine', volume: 0.25, attack_ms: 15, decay_ms: 40, sustain_level: 0.45, release_ms: 100 },
        ],
        repeat: 1, gap_ms: 0,
      },

      // خطأ: نغمتان متعاكستان حادتان — A4 ↓ E4 (square wave)
      error: {
        tones: [
          { frequency_hz: 440, duration_ms: 130, waveform: 'square', volume: 0.38, attack_ms: 5, decay_ms: 20, sustain_level: 0.65, release_ms: 40 },
          { frequency_hz: 330, duration_ms: 220, waveform: 'square', volume: 0.32, attack_ms: 5, decay_ms: 20, sustain_level: 0.55, release_ms: 60 },
        ],
        repeat: 1, gap_ms: 0,
      },

      // نظام مضغوط: نبضة تنبيهية متكررة — 660 Hz سريعة × 3
      pressure: {
        tones: [
          { frequency_hz: 660, duration_ms: 120, waveform: 'square', volume: 0.50, attack_ms: 5,  decay_ms: 15, sustain_level: 0.75, release_ms: 25 },
        ],
        repeat: 3, gap_ms: 100,
      },
    };

    const profile = UI_TONES[type];
    if (!profile) return;
    try {
      await audioEngine.playSoundProfile(profile);
    } catch (_) {}
  }

  // ── Core: receive SSE notification ───────────────────────────────

  /**
   * Called by the SSE listener when a new AudioNotification arrives.
   *
   * - Priority 1–2: plays synthesized tones in the browser
   * - Priority 3+:  visual only (server already played the MP3)
   *
   * @param {Object} notification - AudioNotification payload from SSE
   */
  play(notification) {
    if (!notification || notification.suppressed) return;

    const priority = notification.priority ?? PRIORITY_WARNING;

    // Browser tones: only for Informational and Notice
    if (priority <= PRIORITY_NOTICE) {
      this._playBrowserTones(notification);
    }
    // Priority 3+: server already handled audio, just show visual

    // Notify all UI callbacks (visual toasts, logs, etc.)
    this._onNotificationCallbacks.forEach(cb => {
      try { cb(notification); } catch (_) {}
    });
  }

  /**
   * Synthesize tones from the sound_profile using Web Audio API.
   * @param {Object} notification
   */
  async _playBrowserTones(notification) {
    if (this._muted) return;

    const profile = notification.sound_profile;
    if (!profile || !Array.isArray(profile.tones) || !profile.tones.length) return;

    // Auto-unlock on first informational event (safe — user already loaded page)
    if (!this._unlocked) {
      const ok = await audioEngine.unlock();
      if (!ok) return;
      this._unlocked   = true;
      this._needsUnlock = false;
    }

    // Scale volume from settings
    audioEngine.setVolume(this._volume);

    try {
      await audioEngine.playSoundProfile(profile);
    } catch (_) {}
  }

  // ── SSE callbacks ─────────────────────────────────────────────────

  /**
   * Register a callback to receive every notification (visual + audio).
   * @param {(notification: Object) => void} callback
   * @returns {() => void} Unsubscribe function
   */
  onNotification(callback) {
    this._onNotificationCallbacks.push(callback);
    return () => {
      this._onNotificationCallbacks =
        this._onNotificationCallbacks.filter(cb => cb !== callback);
    };
  }

  // ── Emergency (server handles loop) ──────────────────────────────

  stopEmergencyAlert() {
    // Server-side NativePlayer handles repeat — no action needed here
  }

  // ── Volume / Mute ─────────────────────────────────────────────────

  setVolume(level) {
    this._volume = Math.max(0, Math.min(1, level));
    audioEngine.setVolume(this._volume);
  }
  getVolume() { return this._volume; }

  mute() {
    this._muted = true;
    audioEngine.mute();
  }
  unmute() {
    this._muted = false;
    audioEngine.unmute();
  }
  isMuted() { return this._muted; }

  // ── Test tone (browser) ───────────────────────────────────────────

  /**
   * Play a quick test tone in the browser (for unlock verification).
   * For full sound tests use POST /api/audio/test/{sound_id}.
   */
  async testTone(frequency = 880, waveform = 'sine', duration = 300) {
    if (!this._unlocked) await this.unlock();
    audioEngine.setVolume(this._volume);
    audioEngine.playTone({
      frequency_hz:  frequency,
      duration_ms:   duration,
      waveform,
      volume:        0.5,
      attack_ms:     20,
      decay_ms:      40,
      sustain_level: 0.7,
      release_ms:    60,
    });
  }

  // ── Diagnostics ──────────────────────────────────────────────────

  getStatus() {
    return {
      mode:         'hybrid (browser tones p1-2, server MP3 p3+)',
      unlocked:     this._unlocked,
      contextState: audioEngine.getStatus().contextState,
      volume:       this._volume,
      muted:        this._muted,
    };
  }

  destroy() {
    this._onNotificationCallbacks = [];
    this._onUnlockCallbacks       = [];
    audioEngine.destroy();
  }
}

// Singleton export
const audioAlertService = new AudioAlertService();
export default audioAlertService;
