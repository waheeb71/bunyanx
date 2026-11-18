/**
 * bunyanx NGFW — useAudioAlerts Hook
 * ========================================
 * React hook that:
 *  1. Connects to /api/audio/events/stream (SSE)
 *  2. Receives AudioNotification payloads
 *  3. Plays sounds via audioAlertService
 *  4. Exposes mute/volume controls
 *  5. Maintains a notification history (last 50 events)
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import audioAlertService from '../services/audioAlertService';
import audioFileService from '../services/audioFileService';

import { BASE_URL } from '../services/apiClient';

const API_BASE = BASE_URL;
const SSE_URL = `${API_BASE}/api/audio/events/stream`;
const HISTORY_MAX = 50;

export function useAudioAlerts() {
  const [connected, setConnected] = useState(false);
  const [muted, setMuted] = useState(false);
  const [volume, setVolumeState] = useState(0.7);
  const [profile, setProfile] = useState('default');
  const [notifications, setNotifications] = useState([]);
  const [activeEmergency, setActiveEmergency] = useState(false);
  const [lastEvent, setLastEvent] = useState(null);
  const [connectionError, setConnectionError] = useState(null);
  // ── Audio File state ──────────────────────────────────────────────────
  const [afEnabled, setAfEnabled] = useState(true);
  const [afMuted, setAfMuted] = useState(false);
  const [afVolume, setAfVolume] = useState(1.0);
  const [afMinPriority, setAfMinPriority] = useState(3);
  const [afManifest, setAfManifest] = useState({});
  const [afSummary, setAfSummary] = useState({ total: 0, loaded: 0, missing: 0 });

  const esRef = useRef(null);
  const retryTimerRef = useRef(null);
  const retryCount = useRef(0);
  const MAX_RETRY = 10;

  // ── Load persisted settings from localStorage ──────────────────

  useEffect(() => {
    const saved = localStorage.getItem('bunyanx_audio_settings');
    if (saved) {
      try {
        const s = JSON.parse(saved);
        if (typeof s.volume === 'number') { setVolumeState(s.volume); audioAlertService.setVolume(s.volume); }
        if (typeof s.muted === 'boolean') { setMuted(s.muted); if (s.muted) audioAlertService.mute(); }
        if (typeof s.profile === 'string') { setProfile(s.profile); }
        // ── Audio File settings restore ───────────────────────────────────
        const afSnap = {};
        if (typeof s.af_enabled === 'boolean') { setAfEnabled(s.af_enabled); afSnap.af_enabled = s.af_enabled; }
        if (typeof s.af_muted === 'boolean') { setAfMuted(s.af_muted); afSnap.af_muted = s.af_muted; }
        if (typeof s.af_volume === 'number') { setAfVolume(s.af_volume); afSnap.af_volume = s.af_volume; }
        if (typeof s.af_min_priority === 'number') { setAfMinPriority(s.af_min_priority); afSnap.af_min_priority = s.af_min_priority; }
        if (Object.keys(afSnap).length) audioFileService.applySettings(afSnap);
      } catch (_) { }
    }
  }, []);

  // ── Persist settings to localStorage on change ─────────────────

  const _persist = useCallback((updates) => {
    const existing = JSON.parse(localStorage.getItem('bunyanx_audio_settings') || '{}');
    localStorage.setItem('bunyanx_audio_settings', JSON.stringify({ ...existing, ...updates }));
  }, []);

  // ── SSE Connection ─────────────────────────────────────────────

  const connect = useCallback(() => {
    if (esRef.current) {
      esRef.current.close();
      esRef.current = null;
    }

    // Get auth token
    const token = localStorage.getItem('bunyanx_token');
    // SSE with auth: append token as query param (standard approach for SSE)
    const url = token ? `${SSE_URL}?token=${encodeURIComponent(token)}` : SSE_URL;

    const es = new EventSource(url, { withCredentials: true });
    esRef.current = es;

    es.onopen = () => {
      setConnected(true);
      setConnectionError(null);
      retryCount.current = 0;
      console.log('[AudioAlerts] SSE connected');
    };

    es.onmessage = (event) => {
      try {
        const notification = JSON.parse(event.data);
        handleNotification(notification);
      } catch (e) {
        console.warn('[AudioAlerts] Failed to parse SSE data:', e);
      }
    };

    es.addEventListener('connected', () => {
      setConnected(true);
    });

    es.onerror = () => {
      setConnected(false);
      es.close();
      esRef.current = null;

      if (retryCount.current < MAX_RETRY) {
        const delay = Math.min(1000 * 2 ** retryCount.current, 30000);
        retryCount.current++;
        setConnectionError(`Reconnecting in ${Math.round(delay / 1000)}s...`);
        retryTimerRef.current = setTimeout(connect, delay);
      } else {
        setConnectionError('SSE connection failed — refresh page to retry');
      }
    };
  }, []); // eslint-disable-line

  useEffect(() => {
    connect();
    // audioAlertService handles its own gesture listeners internally (persistent, not once).
    // We just need to pre-init the context here so it's ready.
    // Calling _ensureContext() indirectly by reading state:
    if (audioAlertService.needsUnlock()) {
      audioAlertService.onUnlock(() => {
        // Context became running — no action needed here, service handles queue
      });
    }

    return () => {
      esRef.current?.close();
      clearTimeout(retryTimerRef.current);
    };
  }, [connect]);

  // ── Notification Handler ────────────────────────────────────────

  const handleNotification = useCallback((notification) => {
    if (!notification?.notification_id) return;

    setLastEvent(notification);

    // Update emergency state
    if (notification.priority === 6 && !notification.suppressed) {
      setActiveEmergency(true);
    }

    // نغمة النظام المضغوط في المتصفح عند CPU أو Memory critical
    const pressureTopics = ['system.cpu_critical', 'system.memory_critical'];
    if (pressureTopics.includes(notification.event_type) && !notification.suppressed) {
      audioAlertService.playUiTone('pressure').catch(() => {});
    }

    // Add to history
    setNotifications((prev) => [notification, ...prev].slice(0, HISTORY_MAX));

    // Play sound
    audioAlertService.play(notification);
  }, []);

  // ── Controls ───────────────────────────────────────────────────

  const setVolume = useCallback((level) => {
    const v = Math.max(0, Math.min(1, level));
    setVolumeState(v);
    audioAlertService.setVolume(v);
    _persist({ volume: v });
  }, [_persist]);

  const toggleMute = useCallback(() => {
    const next = !muted;
    setMuted(next);
    if (next) audioAlertService.mute();
    else audioAlertService.unmute();
    _persist({ muted: next });
  }, [muted, _persist]);

  const muteFor = useCallback(async (minutes) => {
    setMuted(true);
    audioAlertService.mute();
    _persist({ muted: true });
    // Call backend to persist timed mute
    try {
      const token = localStorage.getItem('bunyanx_token');
      await fetch(`${API_BASE}/api/audio/mute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ duration_minutes: minutes }),
      });
    } catch (_) { }
    // Auto-unmute after duration
    setTimeout(() => {
      setMuted(false);
      audioAlertService.unmute();
      _persist({ muted: false });
    }, minutes * 60 * 1000);
  }, [_persist]);

  const changeProfile = useCallback(async (profileName) => {
    setProfile(profileName);
    _persist({ profile: profileName });
    try {
      const token = localStorage.getItem('bunyanx_token');
      await fetch(`${API_BASE}/api/audio/settings`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ profile: profileName }),
      });
    } catch (_) { }
  }, [_persist]);

  const acknowledgeEmergency = useCallback(() => {
    setActiveEmergency(false);
    audioAlertService.stopEmergencyAlert();
  }, []);

  const clearHistory = useCallback(() => {
    setNotifications([]);
  }, []);

  // ── Audio File Controls ─────────────────────────────────────────────

  const updateAf = useCallback((key, value, applyFn) => {
    applyFn(value);
    audioFileService.applySettings({ [key]: value });
    _persist({ [key]: value });
  }, [_persist]);

  const setAfEnabledCtrl = useCallback((v) => updateAf('af_enabled', v, setAfEnabled), [updateAf]);
  const setAfMutedCtrl = useCallback((v) => updateAf('af_muted', v, setAfMuted), [updateAf]);
  const setAfVolumeCtrl = useCallback((v) => updateAf('af_volume', v, setAfVolume), [updateAf]);
  const setAfMinPriorityCtrl = useCallback((v) => updateAf('af_min_priority', v, setAfMinPriority), [updateAf]);

  const toggleAfMute = useCallback(() => {
    const next = !afMuted;
    setAfMutedCtrl(next);
    return next;
  }, [afMuted, setAfMutedCtrl]);

  // Refresh manifest + file status
  const reloadManifest = useCallback(async () => {
    await audioFileService.reloadManifest();
    setAfManifest(audioFileService.getManifest());
    setAfSummary(audioFileService.getSummary());
  }, []);

  // Test a specific file
  const testAudioFile = useCallback((filename) => {
    audioFileService.unlock();
    audioFileService.playFile(filename);
  }, []);

  // Refresh summary periodically (to detect preloaded files)
  useEffect(() => {
    const refresh = () => {
      setAfManifest(audioFileService.getManifest());
      setAfSummary(audioFileService.getSummary());
    };
    refresh();
    const id = setInterval(refresh, 2000);
    return () => clearInterval(id);
  }, []);

  return {
    // Connection
    connected,
    connectionError,

    // Tone state
    muted,
    volume,
    profile,
    activeEmergency,
    lastEvent,
    notifications,

    // Tone controls
    setVolume,
    toggleMute,
    muteFor,
    changeProfile,
    acknowledgeEmergency,
    clearHistory,

    // ── Audio File state ─────────────────────────────────────────
    afEnabled,
    afMuted,
    afVolume,
    afMinPriority,
    afManifest,
    afSummary,

    // Audio File controls
    setAfEnabled: setAfEnabledCtrl,
    setAfMuted: setAfMutedCtrl,
    toggleAfMute,
    setAfVolume: setAfVolumeCtrl,
    setAfMinPriority: setAfMinPriorityCtrl,
    reloadManifest,
    testAudioFile,
    getFileStatuses: () => audioFileService.getFileStatuses(),
    getGenericStatuses: () => audioFileService.getGenericStatuses(),
  };
}

export default useAudioAlerts;
