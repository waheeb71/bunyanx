/**
 * bunyanx NGFW — Audio File Service (DISABLED — Server-Side Playback)
 * =====================================================================
 * ⚠️  This service is now a NO-OP stub.
 *
 * Audio file playback has been moved to the server (NativePlayer/PowerShell).
 * The firewall machine plays MP3 alerts directly on its speakers.
 *
 * This stub is kept to avoid breaking any imports. All methods return
 * immediately without doing anything.
 *
 * Audio files are now stored server-side at:
 *   var/audio/alerts/   ← backend production path (NativePlayer reads from here)
 */

class AudioFileService {
  constructor() {
    // Settings stubs (kept for compatibility with AudioSettings UI)
    this._enabled     = false;  // Always disabled in browser
    this._muted       = false;
    this._volume      = 1.0;
    this._minPriority = 3;

    // Fake manifest/buffer state for UI components that read it
    this._manifest       = {};
    this._buffers        = {};
    this._manifestLoaded = true;   // Report as loaded (no errors to show)
    this._manifestError  = null;
  }

  // ── No-op playback ───────────────────────────────────────────────

  /** No-op: audio is played server-side. */
  async play(eventId, priority = 1, loop = false) {
    return false;
  }

  /** No-op: audio is played server-side. */
  async playFile(filename, loop = false) {
    return false;
  }

  /** No-op. */
  stop() {}

  /** No-op: unlock is not needed server-side. */
  unlock() {}

  // ── Settings (kept for UI compatibility) ─────────────────────────

  setEnabled(val)      { /* no-op */ }
  setMuted(val)        { /* no-op */ }
  toggleMute()         { return false; }
  setVolume(v)         { /* no-op */ }
  setMinPriority(p)    { /* no-op */ }

  applySettings(s = {}) { /* no-op */ }

  async reloadManifest() { return; }

  // ── Introspection (returns safe defaults for UI) ──────────────────

  isEnabled()         { return false; }
  isMuted()           { return false; }
  getVolume()         { return this._volume; }
  getMinPriority()    { return this._minPriority; }
  isManifestLoaded()  { return true; }
  getManifestError()  { return null; }
  getManifest()       { return {}; }
  getFileStatuses()   { return []; }
  getGenericStatuses(){ return [3, 4, 5, 6].map(p => ({
    priority: p,
    filename: `p${p}_generic.mp3`,
    loaded: true,   // Report as "loaded" to avoid error indicators in UI
  })); }
  getSummary()        { return { total: 0, loaded: 0, missing: 0 }; }
}

// ── Singleton ─────────────────────────────────────────────────────────
const audioFileService = new AudioFileService();
export default audioFileService;
