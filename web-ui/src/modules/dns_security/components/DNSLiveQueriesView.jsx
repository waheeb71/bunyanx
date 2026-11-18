import React, { useState, useMemo } from 'react';
import { Radio, Search, Trash2, ShieldAlert, CheckCircle2, ArrowUpRight } from 'lucide-react';
import { SectionCard, EmptyState } from '../../../components/Shared';

export function DNSLiveQueriesView({ queries = [], clearQueries }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [actionFilter, setActionFilter] = useState('ALL');
  const [categoryFilter, setCategoryFilter] = useState('ALL');

  const filteredQueries = useMemo(() => {
    return queries.filter(q => {
      // Action filter
      if (actionFilter === 'BLOCK' && q.action !== 'BLOCK' && q.action !== 'DROP') return false;
      if (actionFilter === 'REDIRECT' && q.action !== 'REDIRECT' && q.action !== 'SINKHOLE') return false;
      if (actionFilter === 'ALLOW' && q.action !== 'ALLOW') return false;

      // Category filter
      if (categoryFilter !== 'ALL' && q.category !== categoryFilter) return false;

      // Search term
      if (searchTerm.trim()) {
        const term = searchTerm.toLowerCase();
        const matchDomain = q.domain?.toLowerCase().includes(term);
        const matchIp = q.client_ip?.toLowerCase().includes(term);
        const matchReason = q.reason?.toLowerCase().includes(term);
        const matchCategory = q.category?.toLowerCase().includes(term);
        if (!matchDomain && !matchIp && !matchReason && !matchCategory) return false;
      }

      return true;
    });
  }, [queries, actionFilter, categoryFilter, searchTerm]);

  const categories = useMemo(() => {
    const set = new Set();
    queries.forEach(q => {
      if (q.category) set.add(q.category);
    });
    return Array.from(set);
  }, [queries]);

  const handleClear = () => {
    if (window.confirm('هل أنت متأكد من مسح جميع سجلات استعلامات DNS الحية؟')) {
      clearQueries?.mutate();
    }
  };

  const getActionTag = (action) => {
    switch (action) {
      case 'BLOCK':
      case 'DROP':
        return <span className="dns-badge badge-block" style={{ color: 'var(--danger)', background: 'rgba(255, 77, 106, 0.15)', padding: '2px 8px', borderRadius: 4, fontSize: '0.75rem', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: 4 }}><ShieldAlert size={12} /> محجوب</span>;
      case 'REDIRECT':
      case 'SINKHOLE':
        return <span className="dns-badge badge-redirect" style={{ color: 'var(--warning)', background: 'rgba(255, 171, 64, 0.15)', padding: '2px 8px', borderRadius: 4, fontSize: '0.75rem', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: 4 }}><ArrowUpRight size={12} /> معزول (Sinkhole)</span>;
      case 'ALLOW':
      default:
        return <span className="dns-badge badge-allow" style={{ color: 'var(--success)', background: 'rgba(0, 230, 118, 0.15)', padding: '2px 8px', borderRadius: 4, fontSize: '0.75rem', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: 4 }}><CheckCircle2 size={12} /> مسموح</span>;
    }
  };

  return (
    <div className="dns-live-queries-container">
      {/* ── Filter Toolbar ──────────────────── */}
      <div className="dns-toolbar" style={{
        display: 'flex',
        flexWrap: 'wrap',
        gap: 12,
        alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: 16,
        padding: '12px 16px',
        background: 'var(--bg-card)',
        borderRadius: 'var(--radius-md)',
        border: '1px solid var(--border)'
      }}>
        {/* Search */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 1, minWidth: 260 }}>
          <div style={{ position: 'relative', width: '100%' }}>
            <Search size={15} style={{ position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
            <input
              type="text"
              className="dns-input"
              placeholder="ابحث بالنطاق، عنوان IP، أو السبب..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{ width: '100%', paddingRight: 32, height: 36, fontSize: '0.85rem' }}
            />
          </div>
        </div>

        {/* Action Filter Pills */}
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          {[
            { id: 'ALL', label: 'الكل' },
            { id: 'BLOCK', label: 'المحجوب فقط' },
            { id: 'REDIRECT', label: 'الموجه/المعزول' },
            { id: 'ALLOW', label: 'المسموح' },
          ].map(f => (
            <button
              key={f.id}
              onClick={() => setActionFilter(f.id)}
              className={`dns-pill-btn ${actionFilter === f.id ? 'active' : ''}`}
              style={{
                padding: '6px 12px',
                fontSize: '0.8rem',
                borderRadius: 'var(--radius-sm)',
                border: '1px solid var(--border)',
                background: actionFilter === f.id ? 'var(--accent)' : 'var(--bg-surface)',
                color: actionFilter === f.id ? '#fff' : 'var(--text-secondary)',
                cursor: 'pointer',
                transition: 'all 0.2s',
              }}
            >
              {f.label}
            </button>
          ))}
        </div>

        {/* Category Dropdown */}
        {categories.length > 0 && (
          <select
            className="dns-select"
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            style={{ padding: '6px 12px', height: 36, fontSize: '0.8rem', minWidth: 160 }}
          >
            <option value="ALL">جميع التصنيفات</option>
            {categories.map(cat => (
              <option key={cat} value={cat}>{cat}</option>
            ))}
          </select>
        )}

        {/* Actions */}
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            className="dns-btn-danger"
            onClick={handleClear}
            title="مسح جميع سجلات الاستعلامات"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              padding: '6px 12px',
              fontSize: '0.8rem',
              background: 'rgba(255, 77, 106, 0.15)',
              color: 'var(--danger)',
              border: '1px solid rgba(255, 77, 106, 0.3)',
              borderRadius: 'var(--radius-sm)',
              cursor: 'pointer'
            }}
          >
            <Trash2 size={14} />
            مسح السجل
          </button>
        </div>
      </div>

      {/* ── Table Card ──────────────────────── */}
      <SectionCard
        title={`سجل استعلامات DNS الحية (${filteredQueries.length})`}
        icon={Radio}
      >
        {filteredQueries.length === 0 ? (
          <EmptyState message="لا توجد استعلامات DNS مسجلة تطابق خيارات التصفية الحالية" />
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th style={{ width: 50 }}>#</th>
                  <th>الوقت</th>
                  <th>عنوان العميل (Client IP)</th>
                  <th>النطاق المطلوب (Domain)</th>
                  <th>النوع</th>
                  <th>الإجراء</th>
                  <th>التصنيف والسبب</th>
                  <th>الاستجابة / التحويل</th>
                </tr>
              </thead>
              <tbody>
                {filteredQueries.map((q, i) => (
                  <tr key={q.id || i} style={{
                    background: (q.action === 'BLOCK' || q.action === 'DROP') ? 'rgba(255, 77, 106, 0.04)' :
                                (q.action === 'REDIRECT' || q.action === 'SINKHOLE') ? 'rgba(255, 171, 64, 0.04)' : 'transparent'
                  }}>
                    <td style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>{i + 1}</td>
                    <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                      {q.timestamp ? new Date(q.timestamp).toLocaleTimeString('ar-SA') : 'الآن'}
                    </td>
                    <td>
                      <span className="mono" style={{ direction: 'ltr', display: 'inline-block', fontWeight: 600, color: 'var(--text-primary)' }}>
                        {q.client_ip}
                      </span>
                    </td>
                    <td>
                      <span className="mono" style={{ direction: 'ltr', display: 'inline-block', fontWeight: 600, color: (q.action === 'BLOCK' || q.action === 'DROP') ? 'var(--danger)' : 'var(--accent)' }}>
                        {q.domain}
                      </span>
                    </td>
                    <td>
                      <span style={{
                        fontSize: '0.75rem',
                        padding: '2px 6px',
                        borderRadius: 4,
                        background: 'var(--bg-hover)',
                        fontFamily: 'var(--font-mono)'
                      }}>
                        {q.query_type || 'A'}
                      </span>
                    </td>
                    <td>
                      {getActionTag(q.action)}
                    </td>
                    <td>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                        <span style={{ fontSize: '0.75rem', fontWeight: 700, color: (q.action === 'BLOCK' || q.action === 'DROP') ? 'var(--danger)' : 'var(--text-secondary)' }}>
                          {q.category || 'DNS'}
                        </span>
                        {q.reason && (
                          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                            {q.reason}
                          </span>
                        )}
                      </div>
                    </td>
                    <td>
                      {q.response_ip ? (
                        <span className="mono" style={{ direction: 'ltr', display: 'inline-block', fontSize: '0.8rem', color: 'var(--warning)' }}>
                          {q.response_ip}
                        </span>
                      ) : (
                        <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </SectionCard>
    </div>
  );
}

export default DNSLiveQueriesView;
