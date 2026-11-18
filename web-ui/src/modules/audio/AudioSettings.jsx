/**
 * bunyanx NGFW — Audio Alert Settings Page
 * =============================================
 * Full settings management UI for the Audio Alert System.
 * Features:
 *  - Master volume slider with live preview
 *  - Global / timed mute controls
 *  - Sound profile selector (Default / Night / Silent)
 *  - Day/Night auto-switch scheduler
 *  - Role-based audio permission matrix
 *  - Connection status indicator
 */

import { useState, useEffect } from 'react';
import {
  Volume2, VolumeX, Volume1, Moon, Sun, Bell, BellOff,
  Clock, Shield, Settings2, Wifi, WifiOff, Save, RefreshCw,
  Mic, MicOff, Languages, PlayCircle, Server
} from 'lucide-react';
import useAudioAlerts from '../../hooks/useAudioAlerts';
import audioAlertService from '../../services/audioAlertService';
import './AudioSettings.css';

import { BASE_URL } from '../../services/apiClient';

const API_BASE = BASE_URL;

const PROFILES = [
  { id: 'default', name: 'الافتراضي', icon: '🔊', desc: 'أصوات كاملة لنوبات العمل العادية' },
  { id: 'night', name: 'الوضع الليلي', icon: '🌙', desc: 'أصوات أهدأ لنوبات الليل' },
  { id: 'silent', name: 'صامت', icon: '🔕', desc: 'إشعارات بصرية فقط (ما عدا الطوارئ)' },
];

const MUTE_PRESETS = [
  { label: '15 دقيقة', minutes: 15 },
  { label: 'ساعة', minutes: 60 },
  { label: '4 ساعات', minutes: 240 },
  { label: 'يوم', minutes: 1440 },
];

const ROLES = [
  { id: 'admin', name: 'المدير', max: 6 },
  { id: 'analyst', name: 'المحلل', max: 5 },
  { id: 'operator', name: 'المشغّل', max: 4 },
  { id: 'viewer', name: 'مشاهد فقط', max: 2 },
];

export default function AudioSettings() {
  const {
    connected, muted, volume, profile, activeEmergency,
    setVolume, toggleMute, muteFor, changeProfile, acknowledgeEmergency,
    // ── Audio File ──────────────────────────────────────────────────
    afEnabled, afMuted, afVolume, afMinPriority,
    afManifest, afSummary,
    setAfEnabled, toggleAfMute, setAfVolume,
    setAfMinPriority, reloadManifest, testAudioFile,
    getFileStatuses, getGenericStatuses,
  } = useAudioAlerts();

  const [backendSettings, setBackendSettings] = useState(null);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [dayStart, setDayStart] = useState(8);
  const [nightStart, setNightStart] = useState(22);
  const [autoSwitch, setAutoSwitch] = useState(false);
  const [nativePlayback, setNativePlayback] = useState(true);  // تشغيل الصوت من السيرفر
  const [roleMap, setRoleMap] = useState({
    admin: 6, analyst: 5, operator: 4, viewer: 2,
  });

  // Fetch backend settings on mount
  useEffect(() => {
    const token = localStorage.getItem('bunyanx_token');
    fetch(`${API_BASE}/api/audio/settings`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((r) => r.json())
      .then((data) => {
        setBackendSettings(data);
        setDayStart(data.day_start_hour ?? 8);
        setNightStart(data.night_start_hour ?? 22);
        setAutoSwitch(data.auto_switch_enabled ?? false);
        setNativePlayback(data.native_playback_enabled ?? true);
        setRoleMap(data.role_max_priority ?? { admin: 6, analyst: 5, operator: 4, viewer: 2 });
      })
      .catch(() => { });
  }, []);

  const saveSettings = async () => {
    setSaving(true);
    try {
      const token = localStorage.getItem('bunyanx_token');
      await fetch(`${API_BASE}/api/audio/settings`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({
          volume,
          muted,
          profile,
          auto_switch_enabled: autoSwitch,
          day_start_hour: dayStart,
          night_start_hour: nightStart,
          native_playback_enabled: nativePlayback,
          role_max_priority: roleMap,
        }),
      });
      setSaved(true);
      setTimeout(() => setSaved(false), 2500);
    } catch (_) { }
    setSaving(false);
  };

  const VolumeIcon = muted ? VolumeX : volume > 0.5 ? Volume2 : Volume1;

  return (
    <div className="audio-settings" dir="rtl">
      {/* ── Header ── */}
      <div className="audio-settings__header">
        <div className="audio-settings__title">
          <Settings2 size={22} className="audio-settings__title-icon" />
          <div>
            <h1>إعدادات نظام التنبيه الصوتي</h1>
            <p>إدارة الأصوات والتنبيهات للمنصة الأمنية</p>
          </div>
        </div>

        <div className="audio-settings__status">
          {connected ? (
            <span className="audio-badge audio-badge--online">
              <Wifi size={13} /> متصل مباشرة
            </span>
          ) : (
            <span className="audio-badge audio-badge--offline">
              <WifiOff size={13} /> غير متصل
            </span>
          )}
        </div>
      </div>

      {/* ── Emergency Alert Banner ── */}
      {activeEmergency && (
        <div className="audio-emergency-banner">
          <span className="audio-emergency-banner__icon">🚨</span>
          <div>
            <strong>تنبيه طارئ نشط</strong>
            <p>الصوت يتكرر حتى يتم الإقرار بالحادثة</p>
          </div>
          <button className="audio-emergency-banner__ack" onClick={acknowledgeEmergency}>
            إقرار
          </button>
        </div>
      )}

      <div className="audio-settings__grid">

        {/* ── Native Playback (Server-Side) ── */}
        <div className="audio-card" style={{ gridColumn: '1 / -1', background: nativePlayback ? 'rgba(0,200,100,0.07)' : 'rgba(255,100,100,0.07)', border: `1px solid ${nativePlayback ? 'rgba(0,200,100,0.3)' : 'rgba(255,100,100,0.3)'}` }}>
          <div className="audio-card__head">
            <Server size={18} style={{ color: nativePlayback ? '#4ade80' : '#f87171' }} />
            <h2 style={{ color: nativePlayback ? '#4ade80' : '#f87171' }}>
              تشغيل الصوت من السيرفر
            </h2>
            <label id="native-playback-toggle-label" className="audio-toggle" style={{ marginRight: 'auto' }}>
              <input
                id="native-playback-toggle"
                type="checkbox"
                checked={nativePlayback}
                onChange={(e) => setNativePlayback(e.target.checked)}
              />
              <span className="audio-toggle__slider" />
            </label>
          </div>
          <p className="audio-card__desc" style={{ marginTop: 8 }}>
            {nativePlayback
              ? '✅ الأصوات تُشغَّل مباشرة من جدار الحماية عبر PowerShell — لا يلزم المتصفح مفتوحاً'
              : '⚠️ التشغيل من السيرفر معطّل — الأصوات لن تُشغَّل'}
          </p>
        </div>

        {/* ── Volume Control ── */}
        <div className="audio-card">
          <div className="audio-card__head">
            <VolumeIcon size={18} />
            <h2>مستوى الصوت</h2>
          </div>

          <div className="audio-volume-row">
            <button
              id="audio-mute-toggle"
              className={`audio-mute-btn ${muted ? 'audio-mute-btn--muted' : ''}`}
              onClick={toggleMute}
              title={muted ? 'إلغاء الكتم' : 'كتم الصوت'}
            >
              {muted ? <VolumeX size={20} /> : <Volume2 size={20} />}
            </button>

            <div className="audio-slider-wrap">
              <input
                id="audio-volume-slider"
                type="range"
                className="audio-slider"
                min="0" max="1" step="0.01"
                value={muted ? 0 : volume}
                onChange={(e) => {
                  const v = parseFloat(e.target.value);
                  setVolume(v);
                  if (v > 0 && muted) toggleMute();
                }}
              />
              <div className="audio-slider-labels">
                <span>0%</span>
                <span>{Math.round(volume * 100)}%</span>
                <span>100%</span>
              </div>
            </div>

            <button
              id="audio-preview-btn"
              className="audio-preview-btn"
              onClick={async () => {
                try {
                  const token = localStorage.getItem('bunyanx_token');
                  await fetch(`${API_BASE}/api/audio/test-native/p3_generic`, {
                    method: 'POST',
                    headers: { Authorization: `Bearer ${token}` },
                  });
                } catch (_) { }
              }}
            >
              معاينة
            </button>
          </div>
        </div>

        {/* ── Timed Mute ── */}
        <div className="audio-card">
          <div className="audio-card__head">
            <BellOff size={18} />
            <h2>كتم مؤقت</h2>
          </div>
          <p className="audio-card__desc">
            كتم الصوت لفترة محددة مع استمرار الإشعارات البصرية
          </p>
          <div className="audio-mute-presets">
            {MUTE_PRESETS.map(({ label, minutes }) => (
              <button
                key={minutes}
                id={`audio-mute-${minutes}m`}
                className="audio-preset-btn"
                onClick={() => muteFor(minutes)}
              >
                <Clock size={13} />
                {label}
              </button>
            ))}
          </div>
          {muted && (
            <button
              id="audio-unmute-btn"
              className="audio-preset-btn audio-preset-btn--unmute"
              onClick={toggleMute}
            >
              <Bell size={13} />
              إلغاء الكتم الآن
            </button>
          )}
        </div>

        {/* ── Sound Profile ── */}
        <div className="audio-card audio-card--full">
          <div className="audio-card__head">
            <Moon size={18} />
            <h2>نمط الصوت</h2>
          </div>
          <div className="audio-profiles-grid">
            {PROFILES.map((p) => (
              <button
                key={p.id}
                id={`audio-profile-${p.id}`}
                className={`audio-profile-card ${profile === p.id ? 'audio-profile-card--active' : ''}`}
                onClick={() => changeProfile(p.id)}
              >
                <span className="audio-profile-card__icon">{p.icon}</span>
                <span className="audio-profile-card__name">{p.name}</span>
                <span className="audio-profile-card__desc">{p.desc}</span>
                {profile === p.id && (
                  <span className="audio-profile-card__badge">نشط</span>
                )}
              </button>
            ))}
          </div>
        </div>

        {/* ── Day/Night Auto-Switch ── */}
        <div className="audio-card">
          <div className="audio-card__head">
            <Sun size={18} />
            <h2>التبديل التلقائي نهار / ليل</h2>
          </div>
          <label className="audio-toggle-row">
            <span>تفعيل التبديل التلقائي</span>
            <input
              id="audio-autoswitch-toggle"
              type="checkbox"
              className="audio-checkbox"
              checked={autoSwitch}
              onChange={(e) => setAutoSwitch(e.target.checked)}
            />
          </label>
          {autoSwitch && (
            <div className="audio-time-inputs">
              <label>
                <Sun size={13} /> بداية النهار
                <input
                  id="audio-day-start"
                  type="number" min="0" max="23"
                  value={dayStart}
                  onChange={(e) => setDayStart(+e.target.value)}
                  className="audio-num-input"
                />
                <span>:00</span>
              </label>
              <label>
                <Moon size={13} /> بداية الليل
                <input
                  id="audio-night-start"
                  type="number" min="0" max="23"
                  value={nightStart}
                  onChange={(e) => setNightStart(+e.target.value)}
                  className="audio-num-input"
                />
                <span>:00</span>
              </label>
            </div>
          )}
        </div>

        {/* ── Role-Based Audio ── */}
        <div className="audio-card">
          <div className="audio-card__head">
            <Shield size={18} />
            <h2>صلاحيات الصوت حسب الدور</h2>
          </div>
          <p className="audio-card__desc">
            أقصى مستوى أولوية يمكن كل دور سماعه
          </p>
          <div className="audio-role-table">
            {ROLES.map((role) => (
              <div key={role.id} className="audio-role-row">
                <span className="audio-role-name">{role.name}</span>
                <select
                  id={`audio-role-${role.id}`}
                  className="audio-role-select"
                  value={roleMap[role.id] ?? role.max}
                  onChange={(e) =>
                    setRoleMap((prev) => ({ ...prev, [role.id]: +e.target.value }))
                  }
                >
                  <option value={1}>1 — معلوماتي</option>
                  <option value={2}>2 — إشعار</option>
                  <option value={3}>3 — تحذير</option>
                  <option value={4}>4 — تنبيه أمني</option>
                  <option value={5}>5 — حرج</option>
                  <option value={6}>6 — طوارئ</option>
                </select>
              </div>
            ))}
          </div>
        </div>

        {/* ── Audio File Card ─────────────────────────────────────────── */}
        <div className="audio-card" style={{ borderColor: 'rgba(0,200,255,0.2)' }}>
          <div className="audio-card__header">
            <span style={{ fontSize: 22 }}>📢</span>
            <div style={{ flex: 1 }}>
              <h2 className="audio-card__title">الملفات الصوتية المخصصة</h2>
              <p className="audio-card__subtitle">ضع ملفاتك في /public/audio/alerts/ ثم عدّل manifest.json</p>
            </div>
            {/* Summary badge */}
            <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
              <span style={{
                fontSize: 11, padding: '3px 10px', borderRadius: 999,
                background: 'rgba(0,230,118,0.12)', color: '#00e676',
                border: '1px solid rgba(0,230,118,0.25)'
              }}>
                ✓ {afSummary.loaded}
              </span>
              {afSummary.missing > 0 && (
                <span style={{
                  fontSize: 11, padding: '3px 10px', borderRadius: 999,
                  background: 'rgba(255,77,106,0.12)', color: '#ff4d6a',
                  border: '1px solid rgba(255,77,106,0.25)'
                }}>
                  ✕ {afSummary.missing}
                </span>
              )}
            </div>
          </div>

          {/* Master toggle + volume */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 14 }}>
            {/* Enable toggle */}
            <div style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              background: 'var(--bg-overlay)', borderRadius: 10, padding: '10px 14px',
              border: '1px solid var(--border)'
            }}>
              <div>
                <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)' }}>تفعيل</div>
                <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>{afEnabled ? 'نشط' : 'معطّل'}</div>
              </div>
              <button id="af-toggle-enabled" onClick={() => setAfEnabled(!afEnabled)}
                style={{
                  padding: '5px 14px', borderRadius: 7, border: 'none', cursor: 'pointer',
                  fontWeight: 700, fontSize: 12, transition: 'all 0.2s',
                  background: afEnabled ? 'var(--success)' : 'var(--bg-card)',
                  color: afEnabled ? '#000' : 'var(--text-muted)'
                }}>
                {afEnabled ? 'نشط' : 'تفعيل'}
              </button>
            </div>

            {/* Min priority */}
            <div style={{
              background: 'var(--bg-overlay)', borderRadius: 10, padding: '10px 14px',
              border: '1px solid var(--border)'
            }}>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 6 }}>يشغّل من الأولوية</div>
              <select id="af-min-priority" value={afMinPriority}
                onChange={e => setAfMinPriority(+e.target.value)}
                style={{
                  width: '100%', background: 'transparent', border: 'none',
                  color: 'var(--text-primary)', fontSize: 12, cursor: 'pointer'
                }}>
                <option value={1}>1 — كل الأحداث</option>
                <option value={2}>2 — إشعار+</option>
                <option value={3}>3 — تحذير+</option>
                <option value={4}>4 — أمني+</option>
                <option value={5}>5 — حرج+</option>
                <option value={6}>6 — طوارئ فقط</option>
              </select>
            </div>
          </div>

          {/* Volume slider */}
          <div style={{ marginBottom: 14 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
              <label style={{ fontSize: 12, color: 'var(--text-muted)' }}>مستوى صوت الملفات</label>
              <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--accent)', fontFamily: 'monospace' }}>
                {Math.round(afVolume * 100)}%
              </span>
            </div>
            <input id="af-volume" type="range" min={0} max={1} step={0.01} value={afVolume}
              onChange={e => setAfVolume(+e.target.value)}
              style={{ width: '100%', accentColor: 'var(--accent)' }} />
          </div>

          {/* Mute + Reload */}
          <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
            <button id="af-mute-btn" onClick={toggleAfMute}
              style={{
                flex: 1, padding: '9px', borderRadius: 9, cursor: 'pointer', fontWeight: 700, fontSize: 12,
                border: `1px solid ${afMuted ? 'rgba(0,230,118,0.35)' : 'rgba(255,77,106,0.35)'}`,
                background: afMuted ? 'rgba(0,230,118,0.08)' : 'rgba(255,77,106,0.08)',
                color: afMuted ? 'var(--success)' : 'var(--danger)'
              }}>
              {afMuted ? '🔊 إلغاء الكتم' : '🔇 كتم الملفات'}
            </button>
            <button id="af-reload-btn" onClick={reloadManifest}
              style={{
                flex: 1, padding: '9px', borderRadius: 9, cursor: 'pointer', fontWeight: 700, fontSize: 12,
                border: '1px solid rgba(0,200,255,0.3)',
                background: 'rgba(0,200,255,0.08)', color: 'var(--accent)'
              }}>
              🔄 إعادة تحميل manifest.json
            </button>
          </div>

          {/* File status table */}
          <div style={{
            background: 'var(--bg-overlay)', borderRadius: 10,
            border: '1px solid var(--border)', overflow: 'hidden'
          }}>
            <div style={{
              padding: '10px 14px', fontSize: 11, fontWeight: 700,
              color: 'var(--text-muted)', borderBottom: '1px solid var(--border)',
              display: 'flex', justifyContent: 'space-between'
            }}>
              <span>جدول الملفات</span>
              <span>{afSummary.loaded}/{afSummary.total} محمّل</span>
            </div>
            <div style={{ maxHeight: 240, overflowY: 'auto' }}>
              {getFileStatuses().map(({ eventId, filename, loaded }, index) => {
                const COLORS = {
                  auth_login_failure: '#ffab40', pki_cert_expiring: '#ffab40',
                  response_alert: '#ffab40', threat_detected: '#ff4d6a', response_block: '#ff4d6a',
                  response_quarantine: '#ff4d6a', ids_port_scan: '#ff4d6a', anomaly_scored: '#ff4d6a',
                  dns_suspicious: '#ff4d6a', vpn_failure: '#ff4d6a', correlation_triggered: '#ff4d6a',
                  siem_incident_created: '#ff4d6a', malware_detected: '#c084fc',
                  auth_brute_force: '#c084fc', dlp_incident: '#c084fc', pki_cert_invalid: '#c084fc',
                  ha_failover: '#c084fc', system_memory_critical: '#c084fc',
                  system_cpu_critical: '#c084fc', siem_incident_escalated: '#c084fc',
                  system_core_failure: '#ff0000'
                };
                const c = COLORS[eventId] || 'var(--text-muted)';
                return (
                  <div key={`${eventId}-${index}`}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 10, padding: '8px 14px',
                      borderBottom: '1px solid rgba(255,255,255,0.04)'
                    }}>
                    <span style={{ fontSize: 13 }}>{loaded ? '✅' : '❌'}</span>
                    <span style={{ flex: 1, fontSize: 11, color: c, fontFamily: 'monospace' }}>{eventId}</span>
                    <span style={{
                      fontSize: 11, color: 'var(--text-muted)', flex: 1,
                      overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'
                    }}>
                      {filename}
                    </span>
                    {loaded && (
                      <button id={`af-test-${eventId}-${index}`}
                        onClick={() => testAudioFile(filename)}
                        style={{
                          background: 'none', border: 'none', cursor: 'pointer',
                          color: 'var(--accent)', fontSize: 14, padding: '0 4px'
                        }}
                        title="تجربة">▶
                      </button>
                    )}
                  </div>
                );
              })}
              {getFileStatuses().length === 0 && (
                <div style={{ padding: '20px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>
                  ما تم تحميل manifest.json بعد — تأكد من وجود الملف في /public/audio/alerts/
                </div>
              )}
            </div>
          </div>

          {/* Generic fallbacks status */}
          <div style={{ marginTop: 12 }}>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8, fontWeight: 700 }}>
              ملفات Fallback العامة
            </div>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {getGenericStatuses().map(({ priority, filename, loaded }) => (
                <div key={priority}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 6, padding: '5px 12px',
                    borderRadius: 8, fontSize: 11, fontWeight: 700,
                    background: loaded ? 'rgba(0,230,118,0.08)' : 'rgba(255,77,106,0.08)',
                    border: `1px solid ${loaded ? 'rgba(0,230,118,0.25)' : 'rgba(255,77,106,0.25)'}`,
                    color: loaded ? '#00e676' : '#ff4d6a'
                  }}>
                  <span>{loaded ? '✓' : '✕'}</span>
                  <span>p{priority}_generic</span>
                  {loaded && (
                    <button onClick={() => testAudioFile(filename)}
                      style={{
                        background: 'none', border: 'none', cursor: 'pointer',
                        color: 'inherit', fontSize: 12, padding: '0 2px'
                      }}>▶
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>

      </div>

      {/* ── Save Button ── */}
      <div className="audio-settings__footer">
        <button
          id="audio-save-settings"
          className={`audio-save-btn ${saving ? 'audio-save-btn--saving' : ''} ${saved ? 'audio-save-btn--saved' : ''}`}
          onClick={saveSettings}
          disabled={saving}
        >
          {saving ? <RefreshCw size={16} className="spin" /> : <Save size={16} />}
          {saved ? 'تم الحفظ ✓' : saving ? 'جاري الحفظ...' : 'حفظ الإعدادات'}
        </button>
      </div>
    </div>
  );
}
