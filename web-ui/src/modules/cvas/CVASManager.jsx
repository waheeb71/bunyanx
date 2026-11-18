import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  Volume2, VolumeX, Play, RotateCcw, Trash2, CheckCircle2, AlertTriangle,
  Settings, Sliders, FileText, Cpu, Radio, Shield, Activity, RefreshCw, Eye,
  Wifi, WifiOff, Zap, Clock, ChevronRight
} from 'lucide-react';
import cvasApi from './api/cvasApi';
import './CVASManager.css';

// ── helpers ────────────────────────────────────────────────────────────────

const VERBOSITY_COLORS = {
  level1_critical: { bg: 'rgba(255,77,77,0.15)', color: '#ff4d4d', border: 'rgba(255,77,77,0.35)' },
  level1_full: { bg: 'rgba(255,77,77,0.15)', color: '#ff4d4d', border: 'rgba(255,77,77,0.35)' },
  level2_high: { bg: 'rgba(255,140,0,0.15)', color: '#ff8c00', border: 'rgba(255,140,0,0.35)' },
  level2_short: { bg: 'rgba(255,140,0,0.15)', color: '#ff8c00', border: 'rgba(255,140,0,0.35)' },
  level3_medium: { bg: 'rgba(255,193,7,0.12)', color: '#ffc107', border: 'rgba(255,193,7,0.3)' },
  level3_notice: { bg: 'rgba(255,193,7,0.12)', color: '#ffc107', border: 'rgba(255,193,7,0.3)' },
  level4_low_info: { bg: 'rgba(100,100,100,0.12)', color: '#888', border: 'rgba(100,100,100,0.3)' },
};

const verbosityStyle = (level) =>
  VERBOSITY_COLORS[level] || { bg: 'rgba(0,212,255,0.12)', color: '#00d4ff', border: 'rgba(0,212,255,0.3)' };

const VERBOSITY_LABELS_AR = {
  level1_critical: 'حرج',
  level1_full: 'حرج',
  level2_high: 'عالٍ',
  level2_short: 'عالٍ',
  level3_medium: 'متوسط',
  level3_notice: 'متوسط',
  level4_low_info: 'منخفض',
};

// Default form values — sync with cvas_config.yaml
const DEFAULT_FORM = {
  enabled: true,
  language: 'ar-SA',
  voice_gender: 'female',
  speed_wpm: 175,
  volume: 0.9,
  pitch: 1.0,
  speech_mode: 'natural',
  tts_engine: 'espeak',
  audio_effect: 'none',
  auto_language: false,
  rate_limit_per_min: 10,
  deduplication_window_s: 45,
  ip_cooldown_s: 60,
  window_seconds: 30,
  min_burst_count: 3,
  allow_critical_interrupt: true,
};

function formFromConfig(c) {
  if (!c) return DEFAULT_FORM;
  return {
    enabled: c.enabled ?? true,
    language: c.language || 'ar-SA',
    voice_gender: c.voice_gender || 'female',
    speed_wpm: c.speed_wpm || 175,
    volume: c.volume ?? 0.9,
    pitch: c.pitch ?? 1.0,
    speech_mode: c.speech_mode || 'natural',
    tts_engine: c.tts_engine || 'espeak',
    audio_effect: c.audio_effect || 'none',
    auto_language: c.auto_language ?? false,
    rate_limit_per_min: c.cooldown?.rate_limit_per_min || 10,
    deduplication_window_s: c.cooldown?.deduplication_window_s || 45,
    ip_cooldown_s: c.cooldown?.ip_cooldown_s || 60,
    window_seconds: c.aggregation?.window_seconds || 30,
    min_burst_count: c.aggregation?.min_burst_count || 3,
    allow_critical_interrupt: c.priority_override?.allow_critical_interrupt ?? true,
  };
}

// ── Component ──────────────────────────────────────────────────────────────

export default function CVASManager() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [status, setStatus] = useState(null);
  const [stats, setStats] = useState(null);
  const [voices, setVoices] = useState([]);
  const [events, setEvents] = useState([]);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [tonesEnabled, setTonesEnabled] = useState(true);
  const [message, setMessage] = useState({ text: '', type: 'info' });

  // FIX: settingsDirty prevents the polling loop from overwriting in-progress edits
  const [settingsForm, setSettingsForm] = useState(DEFAULT_FORM);
  const [settingsDirty, setSettingsDirty] = useState(false);
  const [saving, setSaving] = useState(false);

  const [customText, setCustomText] = useState('');
  const [testTopic, setTestTopic] = useState('malware.detected');
  const [previewResult, setPreviewResult] = useState(null);
  const [previewLoading, setPreviewLoading] = useState(false);

  const isEditingSettings = useRef(false);

  // ── data fetching ──────────────────────────────────────────────────────

  const fetchAllData = useCallback(async (force = false) => {
    // FIX: do not overwrite settings form while user is editing
    if (!force && isEditingSettings.current) return;

    try {
      const [statusRes, statsRes, voicesRes, eventsRes, historyRes, configRes, tonesRes] =
        await Promise.all([
          cvasApi.status(),
          cvasApi.statistics(),
          cvasApi.voices(),
          cvasApi.events(),
          cvasApi.history(100),
          cvasApi.config(),
          cvasApi.tonesStatus(),
        ]);

      setStatus(statusRes.data);
      setStats(statsRes.data);
      setVoices(voicesRes.data.voices || []);
      setEvents(eventsRes.data.events || []);
      setHistory(historyRes.data.history || []);
      setTonesEnabled(tonesRes.data.tones_enabled ?? true);

      // Only sync form if user has no unsaved changes
      if (!settingsDirty && configRes.data?.cvas) {
        setSettingsForm(formFromConfig(configRes.data.cvas));
      }
    } catch (err) {
      console.error('[CVAS] Failed to fetch data:', err);
    } finally {
      setLoading(false);
    }
  }, [settingsDirty]);

  useEffect(() => {
    fetchAllData(true);
    const iv = setInterval(() => fetchAllData(false), 5000);
    return () => clearInterval(iv);
  }, [fetchAllData]);

  // ── notifications ──────────────────────────────────────────────────────

  const showMsg = useCallback((text, type = 'info') => {
    setMessage({ text, type });
    setTimeout(() => setMessage({ text: '', type: 'info' }), 4500);
  }, []);

  // ── actions ────────────────────────────────────────────────────────────

  const handleToggleMute = async () => {
    try {
      if (status?.muted) {
        await cvasApi.unmute();
        showMsg('تم إلغاء كتم التنبيهات الصوتية.', 'success');
      } else {
        await cvasApi.mute();
        showMsg('تم كتم التنبيهات الصوتية.', 'warning');
      }
      await fetchAllData(true);
    } catch {
      showMsg('فشل تغيير حالة الكتم.', 'error');
    }
  };

  const handleToggleTones = async () => {
    try {
      if (tonesEnabled) {
        await cvasApi.disableTones();
        setTonesEnabled(false);
        showMsg('تم إيقاف نغمات التنبيه — الناطق يعمل وحده.', 'warning');
      } else {
        await cvasApi.enableTones();
        setTonesEnabled(true);
        showMsg('تم تفعيل نغمات التنبيه.', 'success');
      }
    } catch {
      showMsg('فشل تغيير حالة نغمات التنبيه.', 'error');
    }
  };

  const handleTestAlert = async () => {
    try {
      await cvasApi.test(testTopic);
      showMsg(`تم إرسال التنبيه الصوتي التجريبي (${testTopic}).`, 'success');
      await fetchAllData(true);
    } catch {
      showMsg('فشل إرسال التنبيه التجريبي.', 'error');
    }
  };

  const handleSpeakCustom = async () => {
    if (!customText.trim()) return;
    try {
      await cvasApi.speak({ text: customText.trim(), verbosity: 'level1_critical' });
      showMsg('تم إرسال النص الصوتي المخصص للتجميع.', 'success');
      setCustomText('');
      await fetchAllData(true);
    } catch {
      showMsg('فشل إرسال النص المخصص.', 'error');
    }
  };

  const handleSaveSettings = async () => {
    setSaving(true);
    try {
      await cvasApi.updateConfig(settingsForm);
      showMsg('تم حفظ وتطبيق إعدادات الخدمة الصوتية بنجاح.', 'success');
      setSettingsDirty(false);
      isEditingSettings.current = false;
      await fetchAllData(true);
    } catch {
      showMsg('فشل حفظ الإعدادات — تحقق من اتصال الخادم.', 'error');
    } finally {
      setSaving(false);
    }
  };

  const handleDiscardSettings = async () => {
    setSettingsDirty(false);
    isEditingSettings.current = false;
    await fetchAllData(true);
    showMsg('تم تجاهل التغييرات واستعادة الإعدادات الحالية.', 'info');
  };

  const patchForm = (patch) => {
    isEditingSettings.current = true;
    setSettingsDirty(true);
    setSettingsForm(prev => ({ ...prev, ...patch }));
  };

  const handleClearQueue = async () => {
    try {
      const res = await cvasApi.clearQueue();
      showMsg(`تم تفريغ طابور التنبيهات (${res.data.cleared_count} تنبيه).`, 'success');
      await fetchAllData(true);
    } catch {
      showMsg('فشل تفريغ الطابور.', 'error');
    }
  };

  const handleReload = async () => {
    try {
      await cvasApi.reload();
      showMsg('تم إعادة تحميل التكوين ومكتبة القوالب من القرص.', 'success');
      await fetchAllData(true);
    } catch {
      showMsg('فشل إعادة التحميل.', 'error');
    }
  };

  // FIX: verbosity_level was 'level1_full' — changed to 'level1_critical'
  const handlePreview = async (topic) => {
    setPreviewLoading(true);
    setPreviewResult(null);
    try {
      const res = await cvasApi.preview({
        topic,
        verbosity_level: 'level1_critical',
        language: settingsForm.language,
        payload: {
          src_ip: '185.220.101.5',
          dst_ip: '10.0.4.15',
          country: 'Germany',
          city: 'Frankfurt',
          threat_type: 'Ransomware',
          module: 'WAF Engine',
          action: 'Blocked',
          user: 'admin',
          count: 5,
          window_s: 30,
        },
      });
      setPreviewResult(res.data);
    } catch (err) {
      console.error('[CVAS] Preview error:', err);
      showMsg('فشل توليد معاينة القالب.', 'error');
    } finally {
      setPreviewLoading(false);
    }
  };

  // ── render helpers ─────────────────────────────────────────────────────

  const msgColors = {
    success: { bg: 'rgba(0,230,118,0.12)', border: 'rgba(0,230,118,0.35)', color: '#00e676' },
    error: { bg: 'rgba(255,77,77,0.12)', border: 'rgba(255,77,77,0.35)', color: '#ff4d4d' },
    warning: { bg: 'rgba(255,193,7,0.12)', border: 'rgba(255,193,7,0.35)', color: '#ffc107' },
    info: { bg: 'rgba(0,212,255,0.12)', border: 'rgba(0,212,255,0.35)', color: '#00d4ff' },
  };

  const workerAlive = status?.tts_worker_alive ?? false;
  const maxQueueSize = status?.queue?.max_size ?? 100;

  // ── JSX ────────────────────────────────────────────────────────────────

  return (
    <div className="cvas-container">

      {/* ── Header ──────────────────────────────────────────────────── */}
      <div className="cvas-header">
        <div className="cvas-title-section">
          <div className="cvas-title-icon">
            <Radio size={28} />
          </div>
          <div className="cvas-title-text">
            <h1>خدمة التنبيهات الصوتية الذكية (CVAS)</h1>
            <p>bunyanx Voice Alert Subsystem — نظام النطق الصوتي الفوري للمخاطر الأمنية</p>
          </div>
        </div>

        <div className="cvas-header-actions">
          {/* Live indicator */}
          <div className="cvas-live-dot" title={workerAlive ? 'Worker نشط' : 'Worker متوقف'}>
            <span className={`cvas-pulse ${workerAlive ? 'cvas-pulse-green' : 'cvas-pulse-red'}`} />
            <span style={{ fontSize: '0.78rem', color: workerAlive ? '#00e676' : '#ff4d4d' }}>
              {workerAlive ? 'مباشر' : 'متوقف'}
            </span>
          </div>

          <button
            className={`cvas-badge-btn ${status?.muted ? 'cvas-btn-warning' : 'cvas-btn-primary'}`}
            onClick={handleToggleMute}
            title={status?.muted ? 'النطق مكتوم' : 'النطق مفعّل'}
          >
            {status?.muted ? <VolumeX size={18} /> : <Volume2 size={18} />}
            {status?.muted ? 'مكتوم' : 'مفعّل'}
          </button>

          <button className="cvas-badge-btn cvas-btn-primary" onClick={handleTestAlert}>
            <Play size={16} /> تجربة
          </button>

          <button className="cvas-badge-btn cvas-btn-primary" onClick={handleReload}>
            <RefreshCw size={16} /> تحديث
          </button>
        </div>
      </div>

      {/* ── Toast message ────────────────────────────────────────────── */}
      {message.text && (
        <div className="cvas-toast" style={msgColors[message.type]}>
          {message.type === 'success' && <CheckCircle2 size={16} />}
          {message.type === 'error' && <AlertTriangle size={16} />}
          {message.type === 'warning' && <AlertTriangle size={16} />}
          {message.type === 'info' && <Zap size={16} />}
          {message.text}
        </div>
      )}

      {/* ── Unsaved settings banner ──────────────────────────────────── */}
      {settingsDirty && (
        <div className="cvas-unsaved-banner">
          <AlertTriangle size={16} />
          <span>لديك تغييرات غير محفوظة في الإعدادات</span>
          <button className="cvas-badge-btn cvas-btn-primary" onClick={handleSaveSettings} disabled={saving}>
            {saving ? '...' : 'حفظ الآن'}
          </button>
          <button className="cvas-badge-btn cvas-btn-warning" onClick={handleDiscardSettings}>
            تجاهل
          </button>
        </div>
      )}

      {/* ── Metrics ─────────────────────────────────────────────────── */}
      <div className="cvas-metrics-grid">
        <div className="cvas-metric-card">
          <span className="cvas-metric-label">حالة الخدمة</span>
          <span className="cvas-metric-val" style={{ color: status?.running ? '#00e676' : '#ff5252' }}>
            {loading ? '...' : status?.running ? 'تشغيل مباشر' : 'متوقف'}
          </span>
          <span className="cvas-metric-sub">
            محرك TTS: {status?.tts_engine || '—'} | GeoIP: {status?.geo_enricher_active ? 'نشط' : 'معطّل'}
          </span>
        </div>

        <div className="cvas-metric-card">
          <span className="cvas-metric-label">طابور الانتظار</span>
          <span className="cvas-metric-val">{stats?.queue_current ?? 0}</span>
          <span className="cvas-metric-sub">
            من أصل {maxQueueSize} — {stats?.dropped_full || 0} تنبيه مُسقَط (الطابور ممتلئ)
          </span>
        </div>

        <div className="cvas-metric-card">
          <span className="cvas-metric-label">إجمالي التنبيهات المنطوقة</span>
          <span className="cvas-metric-val" style={{ color: '#00d4ff' }}>{stats?.spoken ?? 0}</span>
          <span className="cvas-metric-sub">سجل السيرة: {stats?.total_history ?? 0} حادثة</span>
        </div>

        <div className="cvas-metric-card">
          <span className="cvas-metric-label">مكتوم بسبب حد المعدل</span>
          <span className="cvas-metric-val" style={{ color: '#ffc107' }}>{stats?.dropped_rate_limit ?? 0}</span>
          <span className="cvas-metric-sub">منع الإرهاق الصوتي للمشغل</span>
        </div>
      </div>

      {/* ── Navigation tabs ──────────────────────────────────────────── */}
      <div className="cvas-nav-tabs">
        {[
          { key: 'dashboard', icon: <Activity size={16} />, label: 'لوحة العمليات' },
          { key: 'history', icon: <Volume2 size={16} />, label: `السجل (${history.length})` },
          { key: 'events', icon: <Shield size={16} />, label: `التغطية (${events.length})` },
          { key: 'settings', icon: <Settings size={16} />, label: `الإعدادات${settingsDirty ? ' ●' : ''}` },
          { key: 'admin', icon: <Cpu size={16} />, label: 'التشخيص' },
        ].map(tab => (
          <button
            key={tab.key}
            className={`cvas-tab-btn ${activeTab === tab.key ? 'active' : ''}`}
            onClick={() => setActiveTab(tab.key)}
            style={settingsDirty && tab.key === 'settings' ? { color: '#ffc107' } : {}}
          >
            {tab.icon} {tab.label}
          </button>
        ))}
      </div>

      {/* ══════════════════════════════════════════════════════════════════
          Tab 1: Dashboard
      ══════════════════════════════════════════════════════════════════ */}
      {activeTab === 'dashboard' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 320px', gap: 20 }}>
          <div className="cvas-card">
            <h3 style={{ marginTop: 0, color: '#00d4ff', display: 'flex', alignItems: 'center', gap: 8 }}>
              <Radio size={20} /> البث المباشر واختبار التنبيه الصوتي
            </h3>

            <div className="cvas-test-panel">
              {/* Event selector */}
              <div className="cvas-form-group">
                <label className="cvas-form-label">اختر نوع الحدث الأمني للاختبار:</label>
                <div style={{ display: 'flex', gap: 10 }}>
                  <select
                    className="cvas-select"
                    value={testTopic}
                    onChange={e => setTestTopic(e.target.value)}
                    style={{ flex: 1 }}
                  >
                    {events.map(ev => (
                      <option key={ev.topic} value={ev.topic}>
                        {ev.title} — {ev.topic}
                      </option>
                    ))}
                  </select>
                  <button className="cvas-badge-btn cvas-btn-primary" onClick={handleTestAlert}>
                    <Play size={16} /> نطق الحدث
                  </button>
                </div>
              </div>

              {/* Custom text */}
              <div className="cvas-form-group" style={{ marginTop: 16 }}>
                <label className="cvas-form-label">نص تنبيه مخصص للنطق المباشر:</label>
                <div style={{ display: 'flex', gap: 10 }}>
                  <input
                    type="text"
                    className="cvas-input"
                    placeholder="مثال: تحذير أمني طارئ، تم رصد هجوم على الخادم الرئيسي..."
                    value={customText}
                    onChange={e => setCustomText(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && handleSpeakCustom()}
                    maxLength={500}
                    style={{ flex: 1 }}
                  />
                  <button
                    className="cvas-badge-btn cvas-btn-primary"
                    onClick={handleSpeakCustom}
                    disabled={!customText.trim()}
                  >
                    <Volume2 size={16} /> نطق
                  </button>
                </div>
                <span style={{ fontSize: '0.72rem', color: 'rgba(255,255,255,0.35)', textAlign: 'left', direction: 'ltr' }}>
                  {customText.length}/500
                </span>
              </div>
            </div>

            {/* Recent history mini-table */}
            <h4 style={{ color: 'rgba(255,255,255,0.7)', marginBottom: 10 }}>
              <Clock size={15} style={{ verticalAlign: 'middle', marginLeft: 6 }} />
              أحدث التنبيهات الصادرة:
            </h4>
            <div className="cvas-table-wrapper">
              <table className="cvas-table">
                <thead>
                  <tr>
                    <th>الوقت</th>
                    <th>الحدث</th>
                    <th>المستوى</th>
                    <th>النص المنطوق</th>
                    <th>المصدر</th>
                  </tr>
                </thead>
                <tbody>
                  {history.slice(0, 6).map((item, idx) => {
                    const vs = verbosityStyle(item.verbosity_level);
                    return (
                      <tr key={idx}>
                        <td style={{ direction: 'ltr', fontSize: '0.78rem', whiteSpace: 'nowrap' }}>
                          {item.datetime}
                        </td>
                        <td style={{ color: '#00d4ff', fontWeight: 700, fontSize: '0.8rem' }}>
                          {item.topic}
                        </td>
                        <td>
                          <span className="cvas-tag" style={{ background: vs.bg, color: vs.color, border: `1px solid ${vs.border}` }}>
                            {VERBOSITY_LABELS_AR[item.verbosity_level] || item.verbosity_level}
                          </span>
                        </td>
                        <td className="cvas-spoken-text">{item.spoken_text}</td>
                        <td style={{ fontSize: '0.78rem', color: 'rgba(255,255,255,0.6)', whiteSpace: 'nowrap' }}>
                          {item.country ? `${item.country}` : ''}{item.src_ip ? ` (${item.src_ip})` : 'نظام محلي'}
                        </td>
                      </tr>
                    );
                  })}
                  {history.length === 0 && (
                    <tr>
                      <td colSpan={5} style={{ textAlign: 'center', color: 'rgba(255,255,255,0.35)', padding: '28px 0' }}>
                        لا توجد تنبيهات منطوقة حتى الآن
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Voices panel */}
          <div className="cvas-card">
            <h3 style={{ marginTop: 0, fontSize: '1rem', color: '#fff' }}>الأصوات المتاحة</h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {voices.map(v => (
                <div key={v.id} className="cvas-voice-card">
                  <div style={{ fontWeight: 700, color: '#00d4ff', fontSize: '0.85rem' }}>{v.name}</div>
                  <div style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.45)', marginTop: 4 }}>
                    {v.languages?.join(', ')} &nbsp;|&nbsp; {v.gender === 'female' ? 'أنثوي' : 'ذكوري'}
                  </div>
                  <div style={{ fontSize: '0.72rem', color: 'rgba(255,255,255,0.3)', marginTop: 2 }}>
                    {v.engine}
                  </div>
                </div>
              ))}
              {voices.length === 0 && (
                <p style={{ color: 'rgba(255,255,255,0.35)', fontSize: '0.82rem' }}>
                  لا توجد أصوات محمّلة على الخادم حتى الآن.
                </p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ══════════════════════════════════════════════════════════════════
          Tab 2: History
      ══════════════════════════════════════════════════════════════════ */}
      {activeTab === 'history' && (
        <div className="cvas-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <h3 style={{ margin: 0 }}>سجل التنبيهات الصوتية المنطوقة</h3>
            <button
              className="cvas-badge-btn cvas-btn-danger"
              onClick={async () => { await cvasApi.clearHistory(); await fetchAllData(true); }}
            >
              <Trash2 size={16} /> مسح السجل
            </button>
          </div>

          <div className="cvas-table-wrapper">
            <table className="cvas-table">
              <thead>
                <tr>
                  <th>الوقت والتاريخ</th>
                  <th>نوع الحدث</th>
                  <th>مستوى الصوت</th>
                  <th>النص الكامل المنطوق</th>
                  <th>الموقع والمصدر</th>
                </tr>
              </thead>
              <tbody>
                {history.map((item, idx) => {
                  const vs = verbosityStyle(item.verbosity_level);
                  return (
                    <tr key={idx}>
                      <td style={{ direction: 'ltr', fontSize: '0.78rem', whiteSpace: 'nowrap' }}>
                        {item.datetime}
                      </td>
                      <td style={{ fontWeight: 700, color: '#00d4ff', fontSize: '0.82rem' }}>{item.topic}</td>
                      <td>
                        <span className="cvas-tag" style={{ background: vs.bg, color: vs.color, border: `1px solid ${vs.border}` }}>
                          {VERBOSITY_LABELS_AR[item.verbosity_level] || item.verbosity_level}
                        </span>
                      </td>
                      <td className="cvas-spoken-text">{item.spoken_text}</td>
                      <td style={{ fontSize: '0.78rem', color: 'rgba(255,255,255,0.6)' }}>
                        {item.country || ''}{item.src_ip ? ` (${item.src_ip})` : ''}
                        {!item.country && !item.src_ip ? 'نظام محلي' : ''}
                      </td>
                    </tr>
                  );
                })}
                {history.length === 0 && (
                  <tr>
                    <td colSpan={5} style={{ textAlign: 'center', color: 'rgba(255,255,255,0.35)', padding: '36px 0' }}>
                      السجل فارغ — لم يتم نطق أي تنبيهات بعد.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ══════════════════════════════════════════════════════════════════
          Tab 3: Event Coverage Matrix
      ══════════════════════════════════════════════════════════════════ */}
      {activeTab === 'events' && (
        <div className="cvas-card">
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 14, marginBottom: 8 }}>
            <h3 style={{ marginTop: 0 }}>مصفوفة تغطية الأحداث الأمنية</h3>
            <span style={{ fontSize: '0.8rem', color: 'rgba(255,255,255,0.45)' }}>
              {events.filter(e => e.handled).length} / {events.length} مغطى
            </span>
          </div>
          <p style={{ fontSize: '0.83rem', color: 'rgba(255,255,255,0.5)', marginBottom: 16 }}>
            جميع أحداث النظام المشترك بها مع نسبة دعم التنبيه الصوتي التلقائي لكل منها.
          </p>

          <div className="cvas-table-wrapper">
            <table className="cvas-table">
              <thead>
                <tr>
                  <th>رمز الحدث (Topic)</th>
                  <th>عنوان التنبيه</th>
                  <th>حالة التغطية</th>
                  <th>العربية</th>
                  <th>الإنجليزية</th>
                  <th>معاينة</th>
                </tr>
              </thead>
              <tbody>
                {events.map(ev => (
                  <tr key={ev.topic}>
                    <td style={{ fontWeight: 700, color: '#00d4ff', fontSize: '0.8rem', direction: 'ltr', textAlign: 'left' }}>
                      {ev.topic}
                    </td>
                    <td>{ev.title}</td>
                    <td>
                      {ev.handled ? (
                        <span className="cvas-tag" style={{ background: 'rgba(0,230,118,0.12)', color: '#00e676', border: '1px solid rgba(0,230,118,0.3)' }}>
                          ✓ مغطى
                        </span>
                      ) : (
                        <span className="cvas-tag" style={{ background: 'rgba(255,77,77,0.12)', color: '#ff5252', border: '1px solid rgba(255,77,77,0.3)' }}>
                          ✗ غير مغطى
                        </span>
                      )}
                    </td>
                    <td style={{ textAlign: 'center' }}>{ev.has_arabic ? '🇸🇦' : '—'}</td>
                    <td style={{ textAlign: 'center' }}>{ev.has_english ? '🇺🇸' : '—'}</td>
                    <td>
                      <button
                        className="cvas-badge-btn cvas-btn-primary"
                        style={{ padding: '4px 10px', fontSize: '0.75rem' }}
                        onClick={() => handlePreview(ev.topic)}
                        disabled={previewLoading}
                      >
                        <Eye size={13} /> معاينة
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {previewResult && (
            <div className="cvas-preview-box">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <h4 style={{ margin: 0, color: '#00d4ff' }}>
                  معاينة: {previewResult.topic}
                </h4>
                <button className="cvas-badge-btn cvas-btn-warning" style={{ padding: '3px 10px', fontSize: '0.75rem' }} onClick={() => setPreviewResult(null)}>
                  ✕ إغلاق
                </button>
              </div>
              <div style={{ marginBottom: 6, fontSize: '0.78rem', color: 'rgba(255,255,255,0.5)' }}>
                القالب المستخدم: <code style={{ color: '#ffc107' }}>{previewResult.template_used || '—'}</code>
                &nbsp;|&nbsp; اللغة: <code style={{ color: '#00d4ff' }}>{previewResult.language}</code>
              </div>
              {previewResult.spoken_text ? (
                <div className="cvas-preview-text">"{previewResult.spoken_text}"</div>
              ) : (
                <div style={{ color: '#ff5252', fontSize: '0.82rem' }}>
                  لم يتم توليد نص — تحقق من phrase_library.json
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ══════════════════════════════════════════════════════════════════
          Tab 4: Settings
      ══════════════════════════════════════════════════════════════════ */}
      {activeTab === 'settings' && (
        <div className="cvas-card">
          <h3 style={{ marginTop: 0 }}>إعدادات التنبيهات الصوتية وسرعة النطق</h3>

          {/* Alert Tones toggle */}
          <div className="cvas-tones-card" style={{
            background: tonesEnabled ? 'rgba(0,212,255,0.06)' : 'rgba(255,87,87,0.06)',
            borderColor: tonesEnabled ? 'rgba(0,212,255,0.22)' : 'rgba(255,87,87,0.3)',
          }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
                {tonesEnabled ? <Volume2 size={20} color="#00d4ff" /> : <VolumeX size={20} color="#ff5757" />}
                <span style={{ fontWeight: 700, fontSize: '0.97rem' }}>نغمات التنبيه (Alert Tones)</span>
              </div>
              <p style={{ margin: 0, fontSize: '0.8rem', color: 'rgba(255,255,255,0.5)', maxWidth: 440 }}>
                {tonesEnabled
                  ? 'نغمات التنبيه مفعّلة — تُعزف بجانب الناطق عند كل حدث أمني.'
                  : 'نغمات التنبيه متوقفة — الناطق الصوتي (TTS) يعمل وحده بدون أصوات نغمية.'}
              </p>
            </div>
            <button id="cvas-tones-toggle-btn" className="cvas-badge-btn" onClick={handleToggleTones}
              style={{
                flexShrink: 0, background: tonesEnabled
                  ? 'linear-gradient(135deg,#ff5757,#c0392b)'
                  : 'linear-gradient(135deg,#00d4ff,#0099cc)',
                color: '#fff', border: 'none', padding: '10px 22px', borderRadius: 10, fontWeight: 700,
              }}>
              {tonesEnabled ? <><VolumeX size={17} /> إيقاف النغمات</> : <><Volume2 size={17} /> تفعيل النغمات</>}
            </button>
          </div>

          {/* Settings grid */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '18px 24px', marginTop: 24 }}>

            {/* Language */}
            <div className="cvas-form-group">
              <label className="cvas-form-label">اللغة الافتراضية للنطق:</label>
              <select className="cvas-select" value={settingsForm.language}
                onChange={e => patchForm({ language: e.target.value })}>
                <option value="ar-SA">العربية (Saudi Arabia) — ar-SA</option>
                <option value="en-US">English (United States) — en-US</option>
              </select>
            </div>

            {/* Voice gender */}
            <div className="cvas-form-group">
              <label className="cvas-form-label">جنس الصوت:</label>
              <select className="cvas-select" value={settingsForm.voice_gender}
                onChange={e => patchForm({ voice_gender: e.target.value })}>
                <option value="female">أنثوي (Female Voice)</option>
                <option value="male">ذكوري (Male Voice)</option>
              </select>
            </div>

            {/* Speed */}
            <div className="cvas-form-group">
              <label className="cvas-form-label">
                سرعة النطق: <strong>{settingsForm.speed_wpm}</strong> كلمة/دقيقة
              </label>
              <input type="range" className="cvas-slider" min="90" max="300" step="5"
                value={settingsForm.speed_wpm}
                onChange={e => patchForm({ speed_wpm: parseInt(e.target.value) })} />
              <div className="cvas-slider-labels"><span>90</span><span>300</span></div>
            </div>

            {/* Volume */}
            <div className="cvas-form-group">
              <label className="cvas-form-label">
                مستوى الصوت: <strong>{Math.round(settingsForm.volume * 100)}%</strong>
              </label>
              <input type="range" className="cvas-slider" min="0.1" max="1.0" step="0.05"
                value={settingsForm.volume}
                onChange={e => patchForm({ volume: parseFloat(e.target.value) })} />
              <div className="cvas-slider-labels"><span>10%</span><span>100%</span></div>
            </div>

            {/* Pitch */}
            <div className="cvas-form-group">
              <label className="cvas-form-label">
                درجة طبقة الصوت (Pitch): <strong>{settingsForm.pitch.toFixed(1)}×</strong>
              </label>
              <input type="range" className="cvas-slider" min="0.5" max="2.0" step="0.1"
                value={settingsForm.pitch}
                onChange={e => patchForm({ pitch: parseFloat(e.target.value) })} />
              <div className="cvas-slider-labels"><span>0.5×</span><span>2.0×</span></div>
            </div>

            {/* Rate limit */}
            <div className="cvas-form-group">
              <label className="cvas-form-label">حد المعدل: <strong>{settingsForm.rate_limit_per_min}</strong> تنبيه/دقيقة</label>
              <input type="range" className="cvas-slider" min="1" max="60" step="1"
                value={settingsForm.rate_limit_per_min}
                onChange={e => patchForm({ rate_limit_per_min: parseInt(e.target.value) })} />
              <div className="cvas-slider-labels"><span>1</span><span>60</span></div>
            </div>

            {/* TTS Engine */}
            <div className="cvas-form-group">
              <label className="cvas-form-label">محرك النطق الصوتي (TTS Engine):</label>
              <select className="cvas-select" value={settingsForm.tts_engine}
                onChange={e => patchForm({ tts_engine: e.target.value })}>
                <option value="espeak">🤖 eSpeak — صوت إنذار آلي روبوتي</option>
                <option value="piper">🧠 Piper العصبي — صوت طبيعي دقيق</option>
                <option value="auto">⚡ تلقائي — Piper أولاً ثم eSpeak احتياطي</option>
              </select>
            </div>

            {/* Audio effect — FIX: added retro_computer */}
            <div className="cvas-form-group">
              <label className="cvas-form-label">مؤثر الصوت (DSP Filter):</label>
              <select className="cvas-select" value={settingsForm.audio_effect}
                onChange={e => patchForm({ audio_effect: e.target.value })}>
                <option value="none">طبيعي (Natural Voice)</option>
                <option value="robotic">🤖 روبوتي معدني (Sci-Fi Metallic)</option>
                <option value="cyber_ai">🛰️ ذكاء اصطناعي سيبراني (Cyber-AI)</option>
                <option value="radio_comm">📻 اتصالات تكتيكية (Tactical Radio)</option>
                <option value="retro_computer">💾 حاسب كلاسيكي (Retro Computer)</option>
              </select>
            </div>

            {/* Speech mode — FIX: removed invalid "verbose" option */}
            <div className="cvas-form-group">
              <label className="cvas-form-label">نمط النطق الصوتي:</label>
              <select className="cvas-select" value={settingsForm.speech_mode}
                onChange={e => patchForm({ speech_mode: e.target.value })}>
                <option value="natural">طبيعي (Natural) — جميع التنبيهات</option>
                <option value="concise">موجز (Concise) — ملخصات قصيرة</option>
                <option value="critical_only">حرج فقط (Critical Only) — التهديدات الطارئة فقط</option>
              </select>
            </div>

            {/* Deduplication window */}
            <div className="cvas-form-group">
              <label className="cvas-form-label">
                نافذة إلغاء التكرار: <strong>{settingsForm.deduplication_window_s}ث</strong>
              </label>
              <input type="range" className="cvas-slider" min="5" max="300" step="5"
                value={settingsForm.deduplication_window_s}
                onChange={e => patchForm({ deduplication_window_s: parseFloat(e.target.value) })} />
              <div className="cvas-slider-labels"><span>5ث</span><span>300ث</span></div>
            </div>

            {/* IP cooldown */}
            <div className="cvas-form-group">
              <label className="cvas-form-label">
                تبريد IP: <strong>{settingsForm.ip_cooldown_s}ث</strong> بين تنبيهات نفس المصدر
              </label>
              <input type="range" className="cvas-slider" min="5" max="300" step="5"
                value={settingsForm.ip_cooldown_s}
                onChange={e => patchForm({ ip_cooldown_s: parseFloat(e.target.value) })} />
              <div className="cvas-slider-labels"><span>5ث</span><span>300ث</span></div>
            </div>

            {/* Burst window */}
            <div className="cvas-form-group">
              <label className="cvas-form-label">
                نافذة تجميع الانفجار: <strong>{settingsForm.window_seconds}ث</strong>
              </label>
              <input type="range" className="cvas-slider" min="5" max="300" step="5"
                value={settingsForm.window_seconds}
                onChange={e => patchForm({ window_seconds: parseFloat(e.target.value) })} />
              <div className="cvas-slider-labels"><span>5ث</span><span>300ث</span></div>
            </div>

            {/* Min burst count */}
            <div className="cvas-form-group">
              <label className="cvas-form-label">
                الحد الأدنى لتجميع الانفجار: <strong>{settingsForm.min_burst_count} أحداث</strong>
              </label>
              <input type="range" className="cvas-slider" min="2" max="50" step="1"
                value={settingsForm.min_burst_count}
                onChange={e => patchForm({ min_burst_count: parseInt(e.target.value) })} />
              <div className="cvas-slider-labels"><span>2</span><span>50</span></div>
            </div>

            {/* Checkboxes row */}
            <div className="cvas-form-group" style={{ gridColumn: 'span 2' }}>
              <div style={{ display: 'flex', gap: 32, flexWrap: 'wrap' }}>
                <label className="cvas-checkbox-label">
                  <input type="checkbox" checked={settingsForm.allow_critical_interrupt}
                    onChange={e => patchForm({ allow_critical_interrupt: e.target.checked })}
                    style={{ accentColor: '#00d4ff', width: 17, height: 17 }} />
                  مقاطعة النطق الحالي فوراً عند وصول تنبيه حرج (Emergency Interrupt)
                </label>
                <label className="cvas-checkbox-label">
                  <input type="checkbox" checked={settingsForm.auto_language}
                    onChange={e => patchForm({ auto_language: e.target.checked })}
                    style={{ accentColor: '#00d4ff', width: 17, height: 17 }} />
                  اللغة التلقائية حسب جلسة المشغّل (Auto Language)
                </label>
              </div>
            </div>
          </div>

          {/* Save bar */}
          <div style={{ marginTop: 24, display: 'flex', gap: 12, alignItems: 'center' }}>
            <button
              className="cvas-badge-btn cvas-btn-primary"
              onClick={handleSaveSettings}
              disabled={saving}
              style={{ opacity: saving ? 0.6 : 1 }}
            >
              {saving ? 'جار الحفظ...' : 'حفظ وتطبيق التغييرات'}
            </button>
            {settingsDirty && (
              <button className="cvas-badge-btn cvas-btn-warning" onClick={handleDiscardSettings}>
                تجاهل التغييرات
              </button>
            )}
          </div>
        </div>
      )}

      {/* ══════════════════════════════════════════════════════════════════
          Tab 5: Admin / Diagnostics
      ══════════════════════════════════════════════════════════════════ */}
      {activeTab === 'admin' && (
        <div className="cvas-card">
          <h3 style={{ marginTop: 0 }}>تشخيص النظام ومحرك النطق</h3>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24 }}>

            {/* Worker status */}
            <div>
              <h4 style={{ color: 'rgba(255,255,255,0.7)', marginBottom: 14 }}>خيط العامل الصوتي (Worker Thread)</h4>
              <div className="cvas-diag-row">
                <span>حالة Worker Thread:</span>
                <strong style={{ color: workerAlive ? '#00e676' : '#ff5252' }}>
                  {workerAlive ? '✓ نشط ويعمل' : '✗ متوقف أو انهار'}
                </strong>
              </div>
              <div className="cvas-diag-row">
                <span>محرك TTS المستخدم:</span>
                <strong style={{ color: '#00d4ff' }}>{status?.tts_engine || '—'}</strong>
              </div>
              <div className="cvas-diag-row">
                <span>مؤثر الصوت الحالي:</span>
                <strong style={{ color: '#ffc107' }}>{status?.audio_effect || '—'}</strong>
              </div>
              <div className="cvas-diag-row">
                <span>pyttsx3 متاح:</span>
                <strong>{status?.pyttsx3_available ? '✓ نعم' : '✗ لا'}</strong>
              </div>
              <div className="cvas-diag-row">
                <span>GeoIP نشط:</span>
                <strong>{status?.geo_enricher_active ? '✓ نعم' : '✗ لا (MMDB مفقود)'}</strong>
              </div>
              <div className="cvas-diag-row">
                <span>Watchdog مفعّل:</span>
                <strong>{status?.watchdog_enabled ? '✓ نعم' : '✗ لا'}</strong>
              </div>

              <div style={{ marginTop: 16 }}>
                <button className="cvas-badge-btn cvas-btn-warning" onClick={handleClearQueue}>
                  <Trash2 size={16} /> تفريغ طابور الانتظار
                </button>
              </div>
            </div>

            {/* Stats */}
            <div>
              <h4 style={{ color: 'rgba(255,255,255,0.7)', marginBottom: 14 }}>إحصائيات الأداء</h4>
              <div className="cvas-diag-row">
                <span>الطابور الحالي:</span>
                <strong>{stats?.queue_current ?? 0} / {maxQueueSize}</strong>
              </div>
              <div className="cvas-diag-row">
                <span>التنبيهات المنطوقة:</span>
                <strong style={{ color: '#00d4ff' }}>{stats?.spoken ?? 0}</strong>
              </div>
              <div className="cvas-diag-row">
                <span>مُسقَط (حد المعدل):</span>
                <strong style={{ color: '#ffc107' }}>{stats?.dropped_rate_limit ?? 0}</strong>
              </div>
              <div className="cvas-diag-row">
                <span>مُسقَط (الطابور ممتلئ):</span>
                <strong style={{ color: '#ff5252' }}>{stats?.dropped_full ?? 0}</strong>
              </div>
              <div className="cvas-diag-row">
                <span>الوضع الحالي:</span>
                <strong style={{ color: '#00d4ff' }}>{status?.speech_mode || '—'}</strong>
              </div>
              <div className="cvas-diag-row">
                <span>اللغة الحالية:</span>
                <strong>{status?.language || '—'}</strong>
              </div>

              <div style={{ marginTop: 16 }}>
                <button
                  className="cvas-badge-btn cvas-btn-danger"
                  onClick={async () => { await cvasApi.reset(); await fetchAllData(true); }}
                >
                  <RotateCcw size={16} /> إعادة ضبط الإحصائيات
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
