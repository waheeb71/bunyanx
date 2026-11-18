import React, { useState, useMemo } from 'react';
import { Trash2, Code, RefreshCw, Search, Filter } from 'lucide-react';

const SEV_META = {
  HIGH:   { label: 'عالية',    color: '#ff5f5f', bg: 'rgba(255,95,95,.12)',   border: 'rgba(255,95,95,.22)'   },
  MEDIUM: { label: 'متوسطة',  color: '#fbbf24', bg: 'rgba(251,191,36,.12)',  border: 'rgba(251,191,36,.22)'  },
  LOW:    { label: 'منخفضة',  color: '#28c76f', bg: 'rgba(40,199,111,.12)',  border: 'rgba(40,199,111,.22)'  },
};

const TARGET_META = {
  url:    { label: 'مسار URL',              color: '#818cf8' },
  header: { label: 'ترويسة HTTP',           color: '#60a5fa' },
  body:   { label: 'جسم الطلب (Body)',      color: '#f97316' },
};

export function TargetBadge({ target }) {
  const m = TARGET_META[target] || { label: target, color: '#888' };
  return (
    <span className="http-target-badge" style={{ color: m.color, background: `${m.color}10`, borderColor: `${m.color}22` }}>
      {m.label}
    </span>
  );
}

export function SevBadge({ severity }) {
  const m = SEV_META[severity] || SEV_META.MEDIUM;
  return (
    <span className="http-sev-badge" style={{ color: m.color, background: m.bg, borderColor: m.border }}>
      {m.label}
    </span>
  );
}

export function PatternsTable({
  patterns,
  isLoading,
  updatePattern,
  deletePattern
}) {
  const [search, setSearch] = useState('');
  const [targetFilter, setTargetFilter] = useState('ALL');
  const [sevFilter, setSevFilter] = useState('ALL');

  const filtered = useMemo(() => {
    return (patterns || []).filter(p => {
      if (targetFilter !== 'ALL' && p.target !== targetFilter) return false;
      if (sevFilter !== 'ALL' && p.severity !== sevFilter) return false;
      if (search.trim()) {
        const q = search.toLowerCase();
        const matchPattern = p.pattern?.toLowerCase().includes(q);
        const matchDesc = p.description?.toLowerCase().includes(q);
        const matchTarget = p.target?.toLowerCase().includes(q);
        if (!matchPattern && !matchDesc && !matchTarget) return false;
      }
      return true;
    });
  }, [patterns, search, targetFilter, sevFilter]);

  return (
    <div className="http-panel">
      <div className="http-panel-header" style={{ flexWrap: 'wrap', gap: 12 }}>
        <div className="http-panel-title">
          <Code size={14} /> قاعدة أنماط المطابقة
          <span className="http-count-pill" style={{ marginRight: 6 }}>
            {filtered.length} / {patterns?.length || 0} نمط
          </span>
        </div>

        {/* Filter Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <div className="http-search-box">
            <Search size={13} style={{ color: 'rgba(255,255,255,0.3)' }} />
            <input
              className="http-search-input"
              type="text"
              placeholder="البحث بالنمط أو الوصف..."
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
          </div>

          <select className="http-filter-select" value={targetFilter} onChange={e => setTargetFilter(e.target.value)}>
            <option value="ALL">جميع الأهداف</option>
            <option value="url">مسار URL</option>
            <option value="header">ترويسة HTTP</option>
            <option value="body">جسم الطلب</option>
          </select>

          <select className="http-filter-select" value={sevFilter} onChange={e => setSevFilter(e.target.value)}>
            <option value="ALL">جميع المستويات</option>
            <option value="HIGH">عالية</option>
            <option value="MEDIUM">متوسطة</option>
            <option value="LOW">منخفضة</option>
          </select>
        </div>
      </div>

      <div className="http-table-wrap">
        <table className="http-table">
          <thead>
            <tr>
              <th>الهدف</th>
              <th>نمط Regex</th>
              <th>الوصف</th>
              <th>الخطورة</th>
              <th>الحالة</th>
              <th style={{ width: 44 }}></th>
            </tr>
          </thead>
          <tbody>
            {isLoading && (
              <tr><td colSpan={6}>
                <div className="http-loading"><RefreshCw size={14} className="http-spin" /> جاري التحميل...</div>
              </td></tr>
            )}
            {!isLoading && (!patterns || !patterns.length) && (
              <tr><td colSpan={6}>
                <div className="http-empty"><Code size={26} style={{opacity:.08}}/><span>لا توجد أنماط مجدولة.</span></div>
              </td></tr>
            )}
            {!isLoading && patterns && patterns.length > 0 && filtered.length === 0 && (
              <tr><td colSpan={6}>
                <div className="http-empty"><Filter size={24} style={{opacity:.15}}/><span>لا توجد نتائج تطابق خيارات التصفية الحالية.</span></div>
              </td></tr>
            )}
            {filtered.map(p => (
              <tr key={p.id} className="http-row">
                <td><TargetBadge target={p.target} /></td>
                <td>
                  <span className="http-mono http-regex" dir="ltr">{p.pattern}</span>
                </td>
                <td style={{ fontSize: '0.78rem', color: 'rgba(255,255,255,0.45)' }}>
                  {p.description || '-'}
                </td>
                <td><SevBadge severity={p.severity} /></td>
                <td>
                  <button
                    className={`http-toggle-btn ${p.enabled ? 'http-toggle-btn--on' : 'http-toggle-btn--off'}`}
                    onClick={() => updatePattern({ id: p.id, data: { ...p, enabled: !p.enabled } })}
                    title={p.enabled ? 'تعطيل النمط' : 'تفعيل النمط'}
                    style={{ border: 'none', cursor: 'pointer', borderRadius: 4, padding: '3px 8px', fontSize: '0.78rem', fontWeight: 600 }}
                  >
                    {p.enabled ? 'نشط 🟢' : 'معطل 🔴'}
                  </button>
                </td>
                <td>
                  <button
                    className="http-del-btn"
                    title="حذف النمط"
                    onClick={() => window.confirm('حذف هذا النمط؟') && deletePattern(p.id)}
                  >
                    <Trash2 size={12} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

