/**
 * bunyanx NGFW — Event → Sound Mapping Table
 * ================================================
 * Full interactive event mapping table:
 *  - Shows all event topics with current sound assignments
 *  - Priority badges, waveform info, repeat count
 *  - Inline "Override" capability (via API)
 *  - Sortable by priority / topic / module
 */

import { useState, useEffect } from 'react';
import { Map, RefreshCw, Play, Edit3, Trash2 } from 'lucide-react';
import audioAlertService from '../../services/audioAlertService';
import './AudioSettings.css';

import { BASE_URL } from '../../services/apiClient';

const API_BASE = BASE_URL;

const PRIORITY_LABELS = {
  1: 'معلوماتي', 2: 'إشعار', 3: 'تحذير',
  4: 'تنبيه أمني', 5: 'حرج', 6: 'طوارئ',
};

export default function EventSoundMap() {
  const [mapping, setMapping] = useState([]);
  const [loading, setLoading] = useState(true);
  const [sortBy, setSortBy] = useState('priority'); // priority | topic | module
  const [playing, setPlaying] = useState(null);

  const fetchMap = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('bunyanx_token');
      const res = await fetch(`${API_BASE}/api/audio/event-map`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      setMapping(data.mapping || []);
    } catch (_) { }
    setLoading(false);
  };

  useEffect(() => { fetchMap(); }, []);

  const testSound = async (item) => {
    setPlaying(item.topic);
    await audioAlertService.unlock();
    try {
      const token = localStorage.getItem('bunyanx_token');
      await fetch(`${API_BASE}/api/audio/test/${item.sound_id}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
    } catch (_) { }
    setTimeout(() => setPlaying(null), 1500);
  };

  const removeOverride = async (topic) => {
    try {
      const token = localStorage.getItem('bunyanx_token');
      await fetch(`${API_BASE}/api/audio/event-map/${encodeURIComponent(topic)}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      });
      await fetchMap();
    } catch (_) { }
  };

  const sorted = [...mapping].sort((a, b) => {
    if (sortBy === 'priority') return (a.priority || 0) - (b.priority || 0);
    if (sortBy === 'topic') return (a.topic || '').localeCompare(b.topic || '');
    return 0;
  });

  return (
    <div className="audio-event-map" dir="rtl">
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--sp-6)' }}>
        <div>
          <h1 style={{ display: 'flex', alignItems: 'center', gap: 'var(--sp-3)', fontSize: 'var(--text-xl)', fontWeight: 700, color: 'var(--text-primary)', margin: '0 0 var(--sp-1) 0' }}>
            <Map size={22} style={{ color: 'var(--accent)' }} />
            خريطة الأحداث الصوتية
          </h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-sm)', margin: 0 }}>
            ربط الأحداث الأمنية بأنماط الصوت المناسبة
          </p>
        </div>

        <div style={{ display: 'flex', gap: 'var(--sp-2)' }}>
          <select
            id="audio-map-sort"
            className="audio-role-select"
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value)}
          >
            <option value="priority">ترتيب حسب الأولوية</option>
            <option value="topic">ترتيب حسب الحدث</option>
          </select>
          <button
            id="audio-map-refresh"
            className="audio-preview-btn"
            onClick={fetchMap}
            disabled={loading}
          >
            <RefreshCw size={14} className={loading ? 'spin' : ''} />
            تحديث
          </button>
        </div>
      </div>

      {/* Table */}
      {loading ? (
        <div style={{ textAlign: 'center', padding: 'var(--sp-12)', color: 'var(--text-secondary)' }}>
          <RefreshCw size={32} className="spin" style={{ marginBottom: 'var(--sp-4)' }} />
          <p>جاري تحميل خريطة الأحداث...</p>
        </div>
      ) : (
        <div style={{ background: 'var(--bg-raised)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', overflow: 'hidden' }}>
          <table className="audio-map-table">
            <thead>
              <tr>
                <th>الأولوية</th>
                <th>الحدث</th>
                <th>الصوت المعين</th>
                <th>النغمات</th>
                <th>التكرار</th>
                <th>تجاوز</th>
                <th>الإجراءات</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((item) => (
                <tr key={item.topic || item.sound_id}>
                  <td>
                    <span className={`audio-event-priority priority-${item.priority}`} style={{ width: 24, height: 24, fontSize: 11, display: 'inline-flex', alignItems: 'center', justifyContent: 'center', borderRadius: '50%' }}>
                      {item.priority}
                    </span>
                    <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', marginRight: 6 }}>
                      {PRIORITY_LABELS[item.priority]}
                    </span>
                  </td>
                  <td>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--accent)' }}>
                      {item.topic}
                    </span>
                    <br />
                    <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                      {item.label}
                    </span>
                  </td>
                  <td>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
                      {item.sound_id}
                    </span>
                  </td>
                  <td style={{ textAlign: 'center' }}>
                    <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
                      {(item.tones || []).length}
                    </span>
                  </td>
                  <td style={{ textAlign: 'center' }}>
                    <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
                      ×{item.repeat || 1}
                    </span>
                  </td>
                  <td>
                    {item.has_override && (
                      <span style={{ fontSize: 'var(--text-xs)', background: 'rgba(255, 171, 64, 0.15)', color: 'var(--warning)', padding: '2px 8px', borderRadius: 'var(--radius-full)', fontWeight: 600 }}>
                        مخصص
                      </span>
                    )}
                  </td>
                  <td>
                    <div style={{ display: 'flex', gap: 'var(--sp-2)' }}>
                      <button
                        id={`audio-map-test-${item.sound_id}`}
                        className={`audio-test-btn ${playing === item.topic ? 'audio-test-btn--playing' : ''}`}
                        onClick={() => testSound(item)}
                        title="تجربة الصوت"
                      >
                        <Play size={12} />
                      </button>
                      {item.has_override && (
                        <button
                          id={`audio-map-remove-${item.sound_id}`}
                          className="audio-test-btn"
                          onClick={() => removeOverride(item.topic)}
                          title="إزالة التخصيص"
                          style={{ color: 'var(--danger)', borderColor: 'rgba(255, 77, 106, 0.35)' }}
                        >
                          <Trash2 size={12} />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div style={{ marginTop: 'var(--sp-3)', color: 'var(--text-muted)', fontSize: 'var(--text-xs)' }}>
        {sorted.length} حدث صوتي مُعيَّن
      </div>
    </div>
  );
}
