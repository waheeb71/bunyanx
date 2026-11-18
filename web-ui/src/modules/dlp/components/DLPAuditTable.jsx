import React from 'react';
import { Clock, ShieldAlert, AlertTriangle, Info, CheckCircle, Search, FileText } from 'lucide-react';
import { useDLPStore } from '../store/dlpStore';
import { useDLP } from '../hooks/useDLP';

const SEVERITY_STYLES = {
  critical: { color: '#ff4d6a', bg: 'rgba(255, 77, 106, 0.12)', border: 'rgba(255, 77, 106, 0.3)', label: 'حرج جداً' },
  high: { color: '#ffab40', bg: 'rgba(255, 171, 64, 0.12)', border: 'rgba(255, 171, 64, 0.3)', label: 'عالي' },
  medium: { color: '#00c8ff', bg: 'rgba(0, 200, 255, 0.12)', border: 'rgba(0, 200, 255, 0.3)', label: 'متوسط' },
  info: { color: '#818cf8', bg: 'rgba(129, 140, 248, 0.12)', border: 'rgba(129, 140, 248, 0.3)', label: 'معلوماتي' },
};

export default function DLPAuditTable() {
  const { auditSeverityFilter, setAuditSeverityFilter, auditSearch, setAuditSearch } = useDLPStore();
  const { auditLogs = [], isLoadingAudit, isErrorAudit } = useDLP();

  if (isLoadingAudit) {
    return (
      <div className="card" style={{ padding: 48, textAlign: 'center', color: 'var(--text-secondary)' }}>
        جاري تحميل سجلات التحقيق الأمني والتنبيهات...
      </div>
    );
  }

  if (isErrorAudit) {
    return (
      <div className="card" style={{ padding: 36, color: '#ff4d6a', textAlign: 'center' }}>
        حدث خطأ أثناء جلب سجلات التحقيق الأمني من الخادم.
      </div>
    );
  }

  const filteredLogs = auditLogs.filter((log) => {
    const matchesSev =
      auditSeverityFilter === 'ALL' || log.severity?.toUpperCase() === auditSeverityFilter;
    const searchLower = auditSearch.toLowerCase();
    const matchesSearch =
      !auditSearch ||
      log.event_type?.toLowerCase().includes(searchLower) ||
      log.src_ip?.toLowerCase().includes(searchLower) ||
      log.dst_ip?.toLowerCase().includes(searchLower) ||
      log.description?.toLowerCase().includes(searchLower);
    return matchesSev && matchesSearch;
  });

  return (
    <div
      className="card"
      style={{
        background: 'rgba(10, 14, 26, 0.75)',
        backdropFilter: 'blur(16px)',
        border: '1px solid rgba(0, 200, 255, 0.15)',
        borderRadius: 'var(--radius-lg)',
        padding: '22px',
      }}
    >
      {/* ── Header & Controls ─────────────────────────────────── */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: 20,
          flexWrap: 'wrap',
          gap: 14,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div
            style={{
              width: 36,
              height: 36,
              borderRadius: 10,
              background: 'rgba(0, 200, 255, 0.12)',
              color: '#00c8ff',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <Clock size={18} />
          </div>
          <div>
            <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 800, color: 'var(--text-primary)' }}>
              سجلات التحقيق الأمني والتنبيهات (DLP Forensic Audit Logs)
            </h3>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
              رصد كافة محاولات تجاوز وتصدير البيانات الحساسة عبر الشبكة
            </span>
          </div>
        </div>

        {/* Filter Controls */}
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
          <div style={{ position: 'relative', width: 220 }}>
            <Search
              size={14}
              style={{
                position: 'absolute',
                right: 10,
                top: '50%',
                transform: 'translateY(-50%)',
                color: 'var(--text-muted)',
              }}
            />
            <input
              className="input"
              style={{ width: '100%', paddingRight: 32, fontSize: '0.8rem' }}
              placeholder="البحث في السجلات..."
              value={auditSearch}
              onChange={(e) => setAuditSearch(e.target.value)}
            />
          </div>

          <select
            className="input"
            style={{ fontSize: '0.8rem', fontWeight: 600, width: '160px' }}
            value={auditSeverityFilter}
            onChange={(e) => setAuditSeverityFilter(e.target.value)}
          >
            <option value="ALL">جميع المستويات</option>
            <option value="CRITICAL">حرج جداً (CRITICAL)</option>
            <option value="HIGH">عالي (HIGH)</option>
            <option value="MEDIUM">متوسط (MEDIUM)</option>
            <option value="INFO">معلوماتي (INFO)</option>
          </select>
        </div>
      </div>

      {/* ── Table Area ────────────────────────────────────────── */}
      {filteredLogs.length === 0 ? (
        <div style={{ padding: '48px 0', textAlign: 'center', color: 'var(--text-secondary)', fontSize: '0.88rem' }}>
          لا توجد سجلات تطابق معايير البحث الحالية.
        </div>
      ) : (
        <table className="table" style={{ width: '100%' }}>
          <thead>
            <tr>
              <th>التوقيت</th>
              <th>نوع الحدث</th>
              <th>المصدر (Src IP)</th>
              <th>الوجهة (Dst IP)</th>
              <th>مستوى الخطورة</th>
              <th>التفاصيل والوصف</th>
            </tr>
          </thead>
          <tbody>
            {filteredLogs.map((log, idx) => {
              const sevKey = log.severity?.toLowerCase() || 'info';
              const sevStyle = SEVERITY_STYLES[sevKey] || SEVERITY_STYLES.info;
              return (
                <tr key={log.id || idx}>
                  <td style={{ fontSize: '0.75rem', fontFamily: 'JetBrains Mono, monospace', color: 'var(--text-secondary)' }}>
                    {log.timestamp ? new Date(log.timestamp).toLocaleString('ar-SA') : 'منذ قليل'}
                  </td>
                  <td style={{ fontWeight: 700, color: 'var(--text-primary)' }}>
                    {log.event_type || 'مطابقة بصمة DLP'}
                  </td>
                  <td>
                    <code
                      style={{
                        fontFamily: 'JetBrains Mono, monospace',
                        fontSize: '0.78rem',
                        color: '#00c8ff',
                        background: 'rgba(0, 200, 255, 0.08)',
                        padding: '2px 8px',
                        borderRadius: '4px',
                        direction: 'ltr',
                        display: 'inline-block',
                      }}
                    >
                      {log.src_ip || '10.0.0.1'}
                    </code>
                  </td>
                  <td>
                    <code
                      style={{
                        fontFamily: 'JetBrains Mono, monospace',
                        fontSize: '0.78rem',
                        color: 'var(--text-primary)',
                        background: 'rgba(255, 255, 255, 0.05)',
                        padding: '2px 8px',
                        borderRadius: '4px',
                        direction: 'ltr',
                        display: 'inline-block',
                      }}
                    >
                      {log.dst_ip || '0.0.0.0'}
                    </code>
                  </td>
                  <td>
                    <span
                      style={{
                        fontSize: '0.68rem',
                        fontWeight: 800,
                        padding: '3px 9px',
                        borderRadius: '12px',
                        color: sevStyle.color,
                        background: sevStyle.bg,
                        border: `1px solid ${sevStyle.border}`,
                      }}
                    >
                      {sevStyle.label}
                    </span>
                  </td>
                  <td style={{ color: 'var(--text-secondary)', fontSize: '0.78rem', maxWidth: '300px' }}>
                    {log.description || 'تم رصد محاولة تسريب بيانات ومطابقة قاعدة الحماية'}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}
