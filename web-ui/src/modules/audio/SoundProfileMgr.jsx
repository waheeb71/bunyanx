/**
 * bunyanx NGFW — Sound Profile Manager
 * =========================================
 * Manage, view and customize sound profiles:
 *  - View all 3 built-in profiles (Default, Night, Silent)
 *  - Per-profile tone frequency/waveform/duration preview
 *  - Export profile as JSON
 *  - Import custom JSON profile overrides
 *  - Live stats: sounds count per priority level
 */

import { useState, useEffect, useRef } from 'react';
import {
  Sliders, Download, Upload, Play, ChevronDown, ChevronUp,
  Volume2, Moon, VolumeX, RefreshCw
} from 'lucide-react';
import audioAlertService from '../../services/audioAlertService';
import './AudioSettings.css';

import { BASE_URL } from '../../services/apiClient';

const API_BASE = BASE_URL;

const PROFILE_META = {
  default: { name: 'الافتراضي', icon: '🔊', color: 'var(--accent)', desc: 'نمط الصوت الكامل لنوبات العمل العادية' },
  night: { name: 'الوضع الليلي', icon: '🌙', color: '#818cf8', desc: 'أصوات أهدأ لنوبات الليل والمناوبات الهادئة' },
  silent: { name: 'صامت', icon: '🔕', color: 'var(--warning)', desc: 'إشعارات بصرية فقط — الصوت للطوارئ فقط' },
};

const PRIORITY_LABELS = {
  1: 'معلوماتي', 2: 'إشعار', 3: 'تحذير',
  4: 'تنبيه أمني', 5: 'حرج', 6: 'طوارئ',
};

const WAVEFORM_ICONS = {
  sine: '〰',
  square: '⊓',
  sawtooth: '⊿',
  triangle: '△',
};

export default function SoundProfileMgr() {
  const [activeProfile, setActiveProfile] = useState('default');
  const [mapping, setMapping] = useState([]);
  const [loading, setLoading] = useState(true);
  const [currentProfile, setCurrentProfile] = useState('default');
  const [expanded, setExpanded] = useState({});
  const [playing, setPlaying] = useState(null);
  const [importError, setImportError] = useState('');
  const [importSuccess, setImportSuccess] = useState('');
  const fileRef = useRef(null);

  // Fetch current settings + event map
  useEffect(() => {
    const token = localStorage.getItem('bunyanx_token');
    Promise.all([
      fetch(`${API_BASE}/api/audio/settings`, { headers: { Authorization: `Bearer ${token}` } }).then(r => r.json()),
      fetch(`${API_BASE}/api/audio/event-map`, { headers: { Authorization: `Bearer ${token}` } }).then(r => r.json()),
    ]).then(([settings, mapData]) => {
      setCurrentProfile(settings.profile || 'default');
      setActiveProfile(settings.profile || 'default');
      setMapping(mapData.mapping || []);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, []);

  // Switch active profile for viewing
  const viewProfile = (p) => setActiveProfile(p);

  // Activate profile on backend
  const activateProfile = async (p) => {
    const token = localStorage.getItem('bunyanx_token');
    await fetch(`${API_BASE}/api/audio/settings`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ profile: p }),
    });
    setCurrentProfile(p);
  };

  // Toggle row expand
  const toggleExpand = (id) =>
    setExpanded(prev => ({ ...prev, [id]: !prev[id] }));

  // Test a single sound via API
  const testSound = async (soundId) => {
    setPlaying(soundId);
    await audioAlertService.unlock();
    try {
      const token = localStorage.getItem('bunyanx_token');
      await fetch(`${API_BASE}/api/audio/test/${soundId}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
    } catch (_) { }
    setTimeout(() => setPlaying(null), 1500);
  };

  // Export profile as JSON
  const exportProfile = () => {
    const data = JSON.stringify(mapping, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `bunyanx_audio_profile_${activeProfile}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Import profile overrides from JSON
  const importProfile = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setImportError('');
    setImportSuccess('');

    const reader = new FileReader();
    reader.onload = async (evt) => {
      try {
        const overrides = JSON.parse(evt.target.result);
        if (!Array.isArray(overrides)) throw new Error('يجب أن يكون ملف JSON مصفوفة');

        const token = localStorage.getItem('bunyanx_token');
        let count = 0;
        for (const item of overrides) {
          if (!item.topic || !item.tones) continue;
          await fetch(`${API_BASE}/api/audio/event-map/${encodeURIComponent(item.topic)}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
            body: JSON.stringify({ sound_profile: item }),
          });
          count++;
        }
        setImportSuccess(`تم استيراد ${count} تخصيص بنجاح`);
      } catch (err) {
        setImportError(`خطأ في الاستيراد: ${err.message}`);
      }
    };
    reader.readAsText(file);
    e.target.value = '';
  };

  // Priority distribution stats
  const priorityCounts = mapping.reduce((acc, item) => {
    acc[item.priority] = (acc[item.priority] || 0) + 1;
    return acc;
  }, {});

  const profileItems = mapping;

  return (
    <div className="audio-profile-mgr" dir="rtl">
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 'var(--sp-6)' }}>
        <div>
          <h1 style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-3)', fontSize: 'var(--text-xl)', fontWeight: 700, color: 'var(--text-primary)', margin: '0 0 var(--sp-1) 0' }}>
            <Sliders size={22} style={{ color: 'var(--accent)' }} />
            إدارة أنماط الصوت
          </h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-sm)', margin: 0 }}>
            عرض وتخصيص أنماط الصوت لكل حالة تشغيلية
          </p>
        </div>
        <div style={{ display: 'flex', gap: 'var(--sp-2)' }}>
          <button
            id="audio-export-profile"
            className="audio-preview-btn"
            onClick={exportProfile}
            title="تصدير النمط الحالي كـ JSON"
          >
            <Download size={14} /> تصدير
          </button>
          <button
            id="audio-import-profile"
            className="audio-preview-btn"
            onClick={() => fileRef.current?.click()}
            title="استيراد تخصيصات من ملف JSON"
          >
            <Upload size={14} /> استيراد
          </button>
          <input
            ref={fileRef}
            type="file"
            accept=".json"
            style={{ display: 'none' }}
            onChange={importProfile}
          />
        </div>
      </div>

      {/* Import feedback */}
      {importError && <div style={{ marginBottom: 'var(--sp-4)', padding: 'var(--sp-3)', background: 'rgba(255,77,106,0.1)', border: '1px solid rgba(255,77,106,0.3)', borderRadius: 'var(--radius-md)', color: 'var(--danger)', fontSize: 'var(--text-sm)' }}>{importError}</div>}
      {importSuccess && <div style={{ marginBottom: 'var(--sp-4)', padding: 'var(--sp-3)', background: 'rgba(0,230,118,0.08)', border: '1px solid rgba(0,230,118,0.25)', borderRadius: 'var(--radius-md)', color: 'var(--success)', fontSize: 'var(--text-sm)' }}>{importSuccess}</div>}

      {/* Profile Selector Tabs */}
      <div style={{ display: 'flex', gap: 'var(--sp-3)', marginBottom: 'var(--sp-5)' }}>
        {Object.entries(PROFILE_META).map(([key, meta]) => (
          <button
            key={key}
            id={`audio-profile-tab-${key}`}
            onClick={() => viewProfile(key)}
            style={{
              flex: 1,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              gap: 'var(--sp-2)',
              padding: 'var(--sp-4)',
              borderRadius: 'var(--radius-lg)',
              border: `1px solid ${activeProfile === key ? meta.color : 'var(--border)'}`,
              background: activeProfile === key ? `rgba(0,200,255,0.07)` : 'var(--bg-raised)',
              cursor: 'pointer',
              transition: 'all 0.2s ease',
              position: 'relative',
            }}
          >
            <span style={{ fontSize: '1.8rem' }}>{meta.icon}</span>
            <span style={{ color: 'var(--text-primary)', fontWeight: 600, fontSize: 'var(--text-sm)' }}>{meta.name}</span>
            <span style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-xs)', textAlign: 'center' }}>{meta.desc}</span>
            {currentProfile === key && (
              <span style={{
                position: 'absolute', top: 8, left: 8,
                background: 'var(--success)', color: '#000',
                fontSize: 10, fontWeight: 700,
                padding: '2px 8px', borderRadius: 'var(--radius-full)',
              }}>نشط</span>
            )}
            {currentProfile !== key && (
              <button
                id={`audio-activate-${key}`}
                onClick={(e) => { e.stopPropagation(); activateProfile(key); }}
                style={{
                  marginTop: 'var(--sp-1)',
                  padding: '3px 12px',
                  fontSize: 11,
                  border: `1px solid ${meta.color}`,
                  borderRadius: 'var(--radius-full)',
                  background: 'transparent',
                  color: meta.color,
                  cursor: 'pointer',
                }}
              >
                تفعيل
              </button>
            )}
          </button>
        ))}
      </div>

      {/* Priority Stats */}
      <div className="audio-card" style={{ marginBottom: 'var(--sp-5)' }}>
        <div className="audio-card__head">
          <Volume2 size={16} />
          <h2>توزيع الأصوات حسب الأولوية</h2>
        </div>
        <div style={{ display: 'flex', gap: 'var(--sp-3)', flexWrap: 'wrap' }}>
          {[1, 2, 3, 4, 5, 6].map(p => (
            <div key={p} style={{
              display: 'flex', flexDirection: 'column', alignItems: 'center',
              padding: 'var(--sp-3) var(--sp-4)',
              background: 'var(--bg-overlay)',
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--border)',
              minWidth: 70,
            }}>
              <span className={`audio-event-priority priority-${p}`} style={{ width: 28, height: 28, fontSize: 12, display: 'flex', alignItems: 'center', justifyContent: 'center', borderRadius: '50%', marginBottom: 'var(--sp-2)' }}>{p}</span>
              <span style={{ fontSize: 'var(--text-xl)', fontWeight: 700, color: 'var(--text-primary)' }}>
                {priorityCounts[p] || 0}
              </span>
              <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
                {PRIORITY_LABELS[p]}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Sounds List */}
      {loading ? (
        <div style={{ textAlign: 'center', padding: 'var(--sp-12)', color: 'var(--text-secondary)' }}>
          <RefreshCw size={28} className="spin" />
        </div>
      ) : (
        <div className="audio-event-list">
          {profileItems.sort((a, b) => (a.priority || 0) - (b.priority || 0)).map((item) => (
            <div key={item.sound_id || item.topic}>
              {/* Row */}
              <div className="audio-event-row" style={{ cursor: 'pointer' }} onClick={() => toggleExpand(item.sound_id)}>
                <span className={`audio-event-priority priority-${item.priority}`}>
                  {item.priority}
                </span>
                <div className="audio-event-info">
                  <div className="audio-event-label">{item.label}</div>
                  <div className="audio-event-topic">{item.topic}</div>
                </div>
                <div style={{ display: 'flex', gap: 'var(--sp-2)', alignItems: 'center' }}>
                  <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                    {(item.tones || []).length} نغمة × {item.repeat || 1}
                  </span>
                  <button
                    id={`audio-profile-test-${item.sound_id}`}
                    className={`audio-test-btn ${playing === item.sound_id ? 'audio-test-btn--playing' : ''}`}
                    onClick={(e) => { e.stopPropagation(); testSound(item.sound_id); }}
                  >
                    <Play size={12} />
                  </button>
                  {expanded[item.sound_id]
                    ? <ChevronUp size={14} style={{ color: 'var(--text-muted)' }} />
                    : <ChevronDown size={14} style={{ color: 'var(--text-muted)' }} />
                  }
                </div>
              </div>

              {/* Expanded tone details */}
              {expanded[item.sound_id] && (
                <div style={{
                  background: 'var(--bg-overlay)',
                  border: '1px solid var(--border)',
                  borderTop: 'none',
                  borderRadius: '0 0 var(--radius-md) var(--radius-md)',
                  padding: 'var(--sp-4)',
                }}>
                  <div style={{ display: 'flex', gap: 'var(--sp-2)', flexWrap: 'wrap' }}>
                    {(item.tones || []).map((tone, i) => (
                      <div key={i} style={{
                        background: 'var(--bg-raised)',
                        border: '1px solid var(--border)',
                        borderRadius: 'var(--radius-sm)',
                        padding: 'var(--sp-2) var(--sp-3)',
                        fontSize: 'var(--text-xs)',
                        fontFamily: 'var(--font-mono)',
                        color: 'var(--text-secondary)',
                      }}>
                        <div style={{ color: 'var(--accent)', fontWeight: 700, marginBottom: 2 }}>
                          نغمة {i + 1} {WAVEFORM_ICONS[tone.waveform] || '~'}
                        </div>
                        <div>{tone.frequency_hz} Hz</div>
                        <div>{tone.duration_ms} ms</div>
                        <div>vol: {Math.round((tone.volume || 0) * 100)}%</div>
                      </div>
                    ))}
                  </div>
                  <div style={{ marginTop: 'var(--sp-3)', fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                    تكرار: ×{item.repeat || 1} &nbsp;|&nbsp; فاصل: {item.gap_ms || 0}ms
                    {item.silent && <span style={{ color: 'var(--warning)', marginRight: 8 }}>● صامت في هذا النمط</span>}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
