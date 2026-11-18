import { useState, useMemo } from 'react';
import { Activity, Search, Filter, ArrowUpRight, ArrowDownLeft, Clock } from 'lucide-react';
import { SectionCard, EmptyState } from '../../../components/Shared';

function formatBytes(bytes) {
  if (!bytes || isNaN(bytes)) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

export default function SessionsPanel({ stats, sessions }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('ALL');

  const filteredSessions = useMemo(() => {
    if (!sessions) return [];
    return sessions.filter(session => {
      // Protocol filter
      if (protocolFilter !== 'ALL') {
        const proto = (session.protocol || '').toUpperCase();
        if (protocolFilter === 'HTTP' && !proto.startsWith('HTTP') && proto !== 'HTTP') return false;
        if (protocolFilter === 'HTTPS' && !proto.includes('HTTPS')) return false;
      }

      // Search term
      if (!searchTerm.trim()) return true;
      const term = searchTerm.toLowerCase().trim();
      return (
        String(session.connection_id || '').toLowerCase().includes(term) ||
        String(session.client_ip || '').toLowerCase().includes(term) ||
        String(session.target_host || '').toLowerCase().includes(term) ||
        String(session.client_port || '').includes(term) ||
        String(session.target_port || '').includes(term) ||
        String(session.protocol || '').toLowerCase().includes(term)
      );
    });
  }, [sessions, searchTerm, protocolFilter]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
      {/* Session Telemetry KPI Summary */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 'var(--sp-3)' }}>
        <div className="prx-summary-card">
          <div className="prx-summary-label">الاتصالات النشطة الحالية</div>
          <div className="prx-summary-value mono" style={{ color: 'var(--accent)' }}>
            {stats?.active_connections ?? 0}
          </div>
        </div>
        <div className="prx-summary-card">
          <div className="prx-summary-label">إجمالي الاتصالات المعالجة</div>
          <div className="prx-summary-value mono">
            {(stats?.total_connections ?? 0).toLocaleString()}
          </div>
        </div>
        <div className="prx-summary-card">
          <div className="prx-summary-label">
            <ArrowUpRight size={14} style={{ display: 'inline', verticalAlign: 'middle', marginLeft: 4 }} />
            البيانات المرسلة (Sent)
          </div>
          <div className="prx-summary-value mono" style={{ color: 'var(--success)' }}>
            {formatBytes(stats?.bytes_sent ?? 0)}
          </div>
        </div>
        <div className="prx-summary-card">
          <div className="prx-summary-label">
            <ArrowDownLeft size={14} style={{ display: 'inline', verticalAlign: 'middle', marginLeft: 4 }} />
            البيانات المستلمة (Received)
          </div>
          <div className="prx-summary-value mono" style={{ color: 'var(--warning)' }}>
            {formatBytes(stats?.bytes_received ?? 0)}
          </div>
        </div>
      </div>

      <SectionCard title="قائمة الجلسات الحية (Active Telemetry Sessions)" icon={Activity}>
        {/* Search & Filter Toolbar */}
        <div className="prx-filter-bar" style={{ marginBottom: 'var(--sp-3)' }}>
          <div className="prx-search-box">
            <Search size={16} color="var(--text-muted)" />
            <input
              type="text"
              placeholder="البحث بالـ IP المصدر، الوجهة، أو معرف الجلسة..."
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
              className="prx-search-input"
            />
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>البروتوكول:</span>
            <div className="prx-filter-pills">
              <button
                className={`prx-filter-pill ${protocolFilter === 'ALL' ? 'active' : ''}`}
                onClick={() => setProtocolFilter('ALL')}
              >
                الكل
              </button>
              <button
                className={`prx-filter-pill ${protocolFilter === 'HTTP' ? 'active' : ''}`}
                onClick={() => setProtocolFilter('HTTP')}
              >
                HTTP
              </button>
              <button
                className={`prx-filter-pill ${protocolFilter === 'HTTPS' ? 'active' : ''}`}
                onClick={() => setProtocolFilter('HTTPS')}
              >
                HTTPS
              </button>
            </div>
          </div>
        </div>

        {!sessions || sessions.length === 0 ? (
          <EmptyState message="لا توجد جلسات نشطة حالياً عبر الوكيل الشبكي" icon={Activity} />
        ) : filteredSessions.length === 0 ? (
          <EmptyState message="لا توجد جلسات حية تطابق معايير تصفية البحث" icon={Filter} />
        ) : (
          <div className="prx-table-wrapper">
            <table className="prx-table">
              <thead>
                <tr>
                  <th>معرف الجلسة</th>
                  <th>المصدر (Client)</th>
                  <th>الوجهة (Destination)</th>
                  <th>البروتوكول</th>
                  <th>المرسل</th>
                  <th>المستقبل</th>
                  <th>المدة الزمنية</th>
                </tr>
              </thead>
              <tbody>
                {filteredSessions.map((session, idx) => {
                  const connId = session.connection_id || `session-${idx}`;
                  const proto = session.protocol || 'HTTP';
                  const protoClass = proto.toLowerCase().includes('https') ? 'https' : 'http';
                  const duration = session.duration || 0;

                  return (
                    <tr key={connId}>
                      <td className="mono" style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                        {connId.length > 28 ? connId.substring(0, 28) + '...' : connId}
                      </td>
                      <td className="mono">{session.client_ip || '—'}:{session.client_port || '—'}</td>
                      <td className="mono" style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                        {session.target_host || '—'}:{session.target_port || '—'}
                      </td>
                      <td>
                        <span className={`prx-badge ${protoClass}`}>
                          {proto}
                        </span>
                      </td>
                      <td className="mono">{formatBytes(session.bytes_sent)}</td>
                      <td className="mono">{formatBytes(session.bytes_received)}</td>
                      <td className="mono" style={{ color: 'var(--text-muted)' }}>
                        <Clock size={13} style={{ display: 'inline', verticalAlign: 'middle', marginLeft: 4 }} />
                        {duration < 60
                          ? `${Math.round(duration)}s`
                          : `${Math.floor(duration / 60)}m ${Math.round(duration % 60)}s`}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </SectionCard>
    </div>
  );
}
