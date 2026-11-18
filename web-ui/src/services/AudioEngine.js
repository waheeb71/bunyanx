/**
 * bunyanx NGFW — AudioEngine (Browser Tone Synthesizer)
 * =======================================================
 * Synthesizes tones in the browser using Web Audio API.
 * Used ONLY for Informational (priority 1) and Notice (priority 2) events.
 * Security alerts (priority 3+) are played server-side via NativePlayer.
 *
 * Tone format (from SoundProfile.tones):
 *   { frequency_hz, duration_ms, waveform, volume,
 *     attack_ms, decay_ms, sustain_level, release_ms }
 */

class AudioEngine {
  constructor() {
    this._ctx        = null;
    this._masterGain = null;
    this._unlocked   = false;
    this._muted      = false;
    this._volume     = 0.7;
    this._unlockCallbacks = [];
  }

  // ── Context ───────────────────────────────────────────────────────

  _init() {
    if (this._ctx) return;
    try {
      const Ctx = window.AudioContext || window.webkitAudioContext;
      if (!Ctx) return;
      this._ctx        = new Ctx();
      this._masterGain = this._ctx.createGain();
      this._masterGain.gain.value = this._muted ? 0 : this._volume;
      this._masterGain.connect(this._ctx.destination);
    } catch (_) {}
  }

  async unlock() {
    this._init();
    if (!this._ctx) return false;
    try {
      if (this._ctx.state === 'suspended') {
        await this._ctx.resume();
      }
      // Play a silent buffer to unlock on iOS/Safari
      const buf = this._ctx.createBuffer(1, 1, 22050);
      const src = this._ctx.createBufferSource();
      src.buffer = buf;
      src.connect(this._ctx.destination);
      src.start(0);
      this._unlocked = true;
      this._unlockCallbacks.forEach(cb => { try { cb(); } catch (_) {} });
      return true;
    } catch (_) {
      return false;
    }
  }

  async ensureRunning() {
    this._init();
    if (!this._ctx) return false;
    if (this._ctx.state === 'suspended') {
      await this._ctx.resume();
    }
    return this._ctx.state === 'running';
  }

  onUnlock(callback) {
    if (this._unlocked) {
      try { callback(); } catch (_) {}
    } else {
      this._unlockCallbacks.push(callback);
    }
    return () => {
      this._unlockCallbacks = this._unlockCallbacks.filter(cb => cb !== callback);
    };
  }

  get ctx()        { return this._ctx; }
  get masterGain() { return this._masterGain; }
  get isUnlocked() { return this._unlocked; }
  get needsUnlock() { return !this._unlocked; }

  // ── Volume / Mute ─────────────────────────────────────────────────

  setVolume(level) {
    this._volume = Math.max(0, Math.min(1, level));
    if (this._masterGain && !this._muted) {
      this._masterGain.gain.setTargetAtTime(this._volume, this._ctx.currentTime, 0.01);
    }
  }
  getVolume() { return this._volume; }

  mute() {
    this._muted = true;
    if (this._masterGain) this._masterGain.gain.setTargetAtTime(0, this._ctx.currentTime, 0.01);
  }
  unmute() {
    this._muted = false;
    if (this._masterGain) this._masterGain.gain.setTargetAtTime(this._volume, this._ctx.currentTime, 0.01);
  }
  isMuted() { return this._muted; }

  // ── Core: Play a single tone ──────────────────────────────────────

  /**
   * Play one synthesized tone.
   * @param {Object} tone  - { frequency_hz, duration_ms, waveform, volume, attack_ms, decay_ms, sustain_level, release_ms }
   * @param {number} startAt - AudioContext time to start (default: now)
   * @returns {number} AudioContext time when tone ends
   */
  playTone(tone, startAt = null) {
    this._init();
    if (!this._ctx || !this._masterGain) return (startAt || 0);

    const t0          = startAt !== null ? startAt : this._ctx.currentTime;
    const freq        = tone.frequency_hz  || 440;
    const dur         = (tone.duration_ms  || 200) / 1000;
    const wave        = tone.waveform      || 'sine';
    const vol         = (tone.volume       ?? 0.6) * this._volume;
    const attackT     = (tone.attack_ms    || 20)  / 1000;
    const decayT      = (tone.decay_ms     || 50)  / 1000;
    const sustainLvl  = (tone.sustain_level ?? 0.7) * vol;
    const releaseT    = (tone.release_ms   || 80)  / 1000;

    try {
      // Oscillator
      const osc  = this._ctx.createOscillator();
      osc.type   = ['sine', 'square', 'sawtooth', 'triangle'].includes(wave) ? wave : 'sine';
      osc.frequency.setValueAtTime(freq, t0);

      // Gain envelope (ADSR)
      const gain = this._ctx.createGain();
      gain.gain.setValueAtTime(0, t0);
      gain.gain.linearRampToValueAtTime(vol, t0 + attackT);             // Attack
      gain.gain.linearRampToValueAtTime(sustainLvl, t0 + attackT + decayT); // Decay → Sustain
      gain.gain.setValueAtTime(sustainLvl, t0 + dur - releaseT);        // Hold sustain
      gain.gain.linearRampToValueAtTime(0, t0 + dur);                   // Release

      osc.connect(gain);
      gain.connect(this._masterGain);

      osc.start(t0);
      osc.stop(t0 + dur + 0.01);  // slight buffer to avoid click

      return t0 + dur;
    } catch (_) {
      return t0 + dur;
    }
  }

  /**
   * Play a full SoundProfile (sequence of tones, repeated N times).
   * @param {Object} profile - { tones: [...], repeat: N, gap_ms: N }
   */
  async playSoundProfile(profile) {
    if (!profile || !profile.tones || !profile.tones.length) return;
    if (this._muted) return;

    const running = await this.ensureRunning();
    if (!running) return;

    const tones   = profile.tones;
    const repeat  = profile.repeat  || 1;
    const gapSecs = (profile.gap_ms || 0) / 1000;

    let cursor = this._ctx.currentTime + 0.02; // small pre-roll

    for (let r = 0; r < repeat; r++) {
      for (const tone of tones) {
        cursor = this.playTone(tone, cursor);
      }
      if (r < repeat - 1) {
        cursor += gapSecs;
      }
    }
  }

  // ── Diagnostics ──────────────────────────────────────────────────

  getStatus() {
    return {
      unlocked:     this._unlocked,
      contextState: this._ctx ? this._ctx.state : 'not-initialized',
      volume:       this._volume,
      muted:        this._muted,
    };
  }

  destroy() {
    try { this._ctx?.close(); } catch (_) {}
    this._ctx = null;
    this._masterGain = null;
    this._unlockCallbacks = [];
  }
}

// ── Singleton ────────────────────────────────────────────────────────
export const audioEngine = new AudioEngine();

if (typeof window !== 'undefined') {
  window.audioEngine = audioEngine;
}

export default audioEngine;
