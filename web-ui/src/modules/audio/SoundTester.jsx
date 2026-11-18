/**
 * bunyanx NGFW — Sound Tester Lab
 * ====================================
 * Interactive sound testing page:
 *  - Lists all 26+ audio events with "Test" buttons
 *  - Triggers sounds server-side via POST /api/audio/test/{sound_id}
 *  - Sounds play directly on the firewall machine's speakers
 *  - Custom frequency/waveform/duration test via /api/audio/test-native
 */

import { useState, useCallback } from 'react';
import { Beaker, Play, Square, Volume2, Server } from 'lucide-react';
import './AudioSettings.css';

import { BASE_URL } from '../../services/apiClient';

const API_BASE = BASE_URL;

// All testable events
const TEST_EVENTS = [
  // Level 1
  { sound_id: 'system_started', label: 'النظام بدأ', priority: 1, topic: 'system.started' },
  { sound_id: 'module_started', label: 'وحدة بدأت', priority: 1, topic: 'module.started' },
  { sound_id: 'config_saved', label: 'تم حفظ الإعدادات', priority: 1, topic: 'config.saved' },
  { sound_id: 'auth_login_success', label: 'تسجيل دخول ناجح', priority: 1, topic: 'auth.login_success' },
  { sound_id: 'intel_updated', label: 'استخبارات محدّثة', priority: 1, topic: 'intel.updated' },
  // Level 2
  { sound_id: 'system_shutdown', label: 'إيقاف النظام', priority: 2, topic: 'system.shutdown' },
  { sound_id: 'module_stopped', label: 'وحدة توقفت', priority: 2, topic: 'module.stopped' },
  { sound_id: 'config_reloaded', label: 'تم تحديث السياسة', priority: 2, topic: 'config.reloaded' },
  { sound_id: 'vpn_restored', label: 'VPN استعاد الاتصال', priority: 2, topic: 'vpn.restored' },
  { sound_id: 'siem_incident_closed', label: 'إغلاق حادثة أمنية', priority: 2, topic: 'siem.incident_closed' },
  // Level 3
  { sound_id: 'auth_login_failure', label: 'فشل تسجيل الدخول', priority: 3, topic: 'auth.login_failure' },
  { sound_id: 'pki_cert_expiring', label: 'شهادة SSL قاربت انتهاء', priority: 3, topic: 'pki.cert_expiring' },
  { sound_id: 'response_alert', label: 'تنبيه استجابة', priority: 3, topic: 'response.alert' },
  // Level 4
  { sound_id: 'threat_detected', label: 'تهديد مكتشف', priority: 4, topic: 'threat.detected' },
  { sound_id: 'response_block', label: 'تم حجب التهديد', priority: 4, topic: 'response.block' },
  { sound_id: 'ids_port_scan', label: 'مسح المنافذ مكتشف', priority: 4, topic: 'ids.port_scan' },
  { sound_id: 'dns_suspicious', label: 'نشاط DNS مشبوه', priority: 4, topic: 'dns.suspicious' },
  { sound_id: 'vpn_failure', label: 'فشل VPN', priority: 4, topic: 'vpn.failure' },
  { sound_id: 'siem_incident_created', label: 'حادثة أمنية جديدة', priority: 4, topic: 'siem.incident_created' },
  // Level 5
  { sound_id: 'malware_detected', label: 'برمجية خبيثة مكتشفة', priority: 5, topic: 'malware.detected' },
  { sound_id: 'auth_brute_force', label: 'هجوم Brute Force', priority: 5, topic: 'auth.brute_force' },
  { sound_id: 'dlp_incident', label: 'حادثة تسرب بيانات', priority: 5, topic: 'dlp.incident' },
  { sound_id: 'pki_cert_invalid', label: 'شهادة SSL غير صالحة', priority: 5, topic: 'pki.cert_invalid' },
  { sound_id: 'ha_failover', label: 'HA Failover نشط', priority: 5, topic: 'ha.failover' },
  { sound_id: 'system_memory_critical', label: 'ذاكرة حرجة', priority: 5, topic: 'system.memory_critical' },
  { sound_id: 'system_cpu_critical', label: 'CPU حرج', priority: 5, topic: 'system.cpu_critical' },
  { sound_id: 'siem_incident_escalated', label: 'تصعيد حادثة أمنية', priority: 5, topic: 'siem.incident_escalated' },
  // Level 6
  { sound_id: 'system_core_failure', label: 'فشل حرج في النظام', priority: 6, topic: 'system.core_failure' },
];

const PRIORITY_LABELS = {
  1: 'معلوماتي',
  2: 'إشعار',
  3: 'تحذير',
  4: 'تنبيه أمني',
  5: 'حرج',
  6: 'طوارئ',
};

const WAVEFORMS = ['sine', 'square', 'sawtooth', 'triangle'];

export default function SoundTester() {
  const [playing, setPlaying] = useState(null);  // sound_id currently playing
  const [lastPlayed, setLastPlayed] = useState(null);
  const [freq, setFreq] = useState(440);
  const [duration, setDuration] = useState(300);
  const [waveform, setWaveform] = useState('sine');
  const [filter, setFilter] = useState(0);     // 0 = all, 1-6 = priority level

  // ── Test via API → server-side native playback ─────────────────

  const testSound = useCallback(async (event) => {
    setPlaying(event.sound_id);
    try {
      const token = localStorage.getItem('bunyanx_token');
      await fetch(`${BASE_URL}/api/audio/test/${event.sound_id}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      setLastPlayed(event.label);
    } catch (_) { }
    setTimeout(() => setPlaying(null), 1500);
  }, []);

  // ── Custom tone test via native endpoint ───────────────────────

  const testCustom = useCallback(async () => {
    try {
      const token = localStorage.getItem('bunyanx_token');
      // Use test-native with a generic sound_id — server plays via PowerShell
      await fetch(`${BASE_URL}/api/audio/test-native/p3_generic`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      setLastPlayed('نغمة مخصصة (p3_generic)');
    } catch (_) { }
  }, [freq, waveform, duration]);

  const filtered = filter === 0
    ? TEST_EVENTS
    : TEST_EVENTS.filter((e) => e.priority === filter);

  return (
    <div className="audio-tester" dir="rtl">
      {/* Header */}
      <div className="audio-tester__header">
        <h1><Beaker size={22} /> مختبر اختبار الأصوات</h1>
        <p>اختبر كل صوت تنبيه في النظام — يُشغَّل مباشرة على مكبرات السيرفر</p>
      </div>

      {/* Server-side indicator */}
      <div className="audio-card" style={{ marginBottom: 'var(--sp-4)', background: 'rgba(0,200,100,0.07)', border: '1px solid rgba(0,200,100,0.25)' }}>
        <div className="audio-card__head" style={{ color: '#4ade80' }}>
          <Server size={16} />
          <span style={{ fontWeight: 700 }}>تشغيل من السيرفر</span>
          <span style={{ marginRight: 'auto', fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', fontWeight: 400 }}>
            الأصوات تُشغَّل مباشرة من جدار الحماية عبر PowerShell — لا يلزم المتصفح
          </span>
        </div>
      </div>

      {lastPlayed && (
        <div style={{ marginBottom: 'var(--sp-3)', padding: '8px 14px', borderRadius: 8, background: 'rgba(0,200,255,0.08)', color: '#00c8ff', fontSize: 'var(--text-sm)' }}>
          🔊 آخر صوت: <strong>{lastPlayed}</strong>
        </div>
      )}

      {/* Custom tone */}
      <div className="audio-card" style={{ marginBottom: 'var(--sp-5)' }}>
        <div className="audio-card__head">
          <Play size={18} />
          <h2>اختبار صوت مخصص (Native)</h2>
        </div>
        <div style={{ display: 'flex', gap: 'var(--sp-4)', flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <label style={{ display: 'flex', flexDirection: 'column', gap: 4, color: 'var(--text-secondary)', fontSize: 'var(--text-sm)' }}>
            التردد (Hz)
            <input
              id="audio-custom-freq"
              type="number" min="80" max="4000" step="10"
              value={freq}
              onChange={(e) => setFreq(+e.target.value)}
              className="audio-num-input"
              style={{ width: '100px' }}
            />
          </label>
          <label style={{ display: 'flex', flexDirection: 'column', gap: 4, color: 'var(--text-secondary)', fontSize: 'var(--text-sm)' }}>
            المدة (ms)
            <input
              id="audio-custom-duration"
              type="number" min="50" max="2000" step="50"
              value={duration}
              onChange={(e) => setDuration(+e.target.value)}
              className="audio-num-input"
              style={{ width: '100px' }}
            />
          </label>
          <label style={{ display: 'flex', flexDirection: 'column', gap: 4, color: 'var(--text-secondary)', fontSize: 'var(--text-sm)' }}>
            نوع الموجة
            <select
              id="audio-custom-waveform"
              className="audio-role-select"
              value={waveform}
              onChange={(e) => setWaveform(e.target.value)}
            >
              {WAVEFORMS.map((w) => <option key={w} value={w}>{w}</option>)}
            </select>
          </label>
          <button
            id="audio-custom-play"
            className="audio-test-btn"
            onClick={testCustom}
            style={{ marginBottom: '2px' }}
          >
            <Play size={14} /> تشغيل على السيرفر
          </button>
        </div>
        <p style={{ marginTop: 8, color: 'var(--text-secondary)', fontSize: 'var(--text-xs)' }}>
          ملاحظة: يُشغّل الصوت النوع العام (p3_generic.mp3) مباشرة من السيرفر.
        </p>
      </div>

      {/* Priority filter */}
      <div style={{ display: 'flex', gap: 'var(--sp-2)', marginBottom: 'var(--sp-4)', flexWrap: 'wrap' }}>
        <button
          id="audio-filter-all"
          className={`audio-preset-btn ${filter === 0 ? 'audio-preset-btn--unmute' : ''}`}
          onClick={() => setFilter(0)}
        >
          الكل
        </button>
        {[1, 2, 3, 4, 5, 6].map((p) => (
          <button
            key={p}
            id={`audio-filter-p${p}`}
            className={`audio-preset-btn ${filter === p ? 'audio-preset-btn--unmute' : ''}`}
            onClick={() => setFilter(p)}
            style={{ color: filter === p ? undefined : `var(--text-secondary)` }}
          >
            <span className={`audio-event-priority priority-${p}`} style={{ width: 20, height: 20, fontSize: 10 }}>
              {p}
            </span>
            {PRIORITY_LABELS[p]}
          </button>
        ))}
      </div>

      {/* Event list */}
      <div className="audio-event-list">
        {filtered.map((event) => (
          <div key={event.sound_id} className="audio-event-row">
            <span className={`audio-event-priority priority-${event.priority}`}>
              {event.priority}
            </span>
            <div className="audio-event-info">
              <div className="audio-event-label">{event.label}</div>
              <div className="audio-event-topic">{event.topic}</div>
            </div>
            <span className="audio-card__head" style={{ color: PRIORITY_LABELS[event.priority] && `var(--text-secondary)`, margin: 0, fontSize: 'var(--text-xs)' }}>
              {PRIORITY_LABELS[event.priority]}
            </span>
            <button
              id={`audio-test-${event.sound_id}`}
              className={`audio-test-btn ${playing === event.sound_id ? 'audio-test-btn--playing' : ''}`}
              onClick={() => testSound(event)}
              disabled={playing !== null && playing !== event.sound_id}
            >
              {playing === event.sound_id ? <Square size={12} /> : <Play size={12} />}
              {playing === event.sound_id ? 'يشتغل...' : 'تجربة'}
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
