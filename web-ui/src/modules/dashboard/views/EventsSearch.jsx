import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import { Search, Filter, AlertTriangle, Shield, CheckCircle, Clock } from 'lucide-react';
import { logManagerApi } from '../../../services/api';
import EventDetailDrawer from '../components/EventDetailDrawer';
import useDashboardStore from '../stores/useDashboardStore';

const VERDICT_LABELS = {
  BLOCK: 'محجوب', DROP: 'مُسقط',
  ALLOW: 'مسموح', PASS: 'ناجح',
  WARN:  'تحذير',
};

export default function EventsSearch() {
  const eventsFilter = useDashboardStore((s) => s.eventsFilter);
  const setEventsFilter = useDashboardStore((s) => s.setEventsFilter);
  const selectedEvent = useDashboardStore((s) => s.selectedEvent);
  const setSelectedEvent = useDashboardStore((s) => s.setSelectedEvent);

  const [filters, setFilters] = useState(eventsFilter);
  const [queryParams, setQueryParams] = useState(eventsFilter);

  const { data: result, isLoading } = useQuery({
    queryKey: ['siem_events', queryParams],
    queryFn:  () => logManagerApi.searchEvents({ ...queryParams, limit: 100 }).then(r => r.data),
    refetchInterval: 15000,
  });

  const handleSearch = (e) => {
    e.preventDefault();
    setQueryParams(filters);
    setEventsFilter(filters);
  };

  const getVerdictBadge = (verdict) => {
    const v = String(verdict).toUpperCase();
    const label = VERDICT_LABELS[v] || v;
    if (v.includes('BLOCK') || v.includes('DROP'))
      return <span className="status-badge error"><Shield size={12}/> {label}</span>;
    if (v.includes('ALLOW') || v.includes('PASS'))
      return <span className="status-badge success"><CheckCircle size={12}/> {label}</span>;
    return <span className="status-badge warning"><AlertTriangle size={12}/> {label}</span>;
  };

  const getModuleName = (ev) => {
    const raw = String(ev.module || ev.category || ev.service || ev.event_type || ev.source || ev.type || '').toUpperCase();
    if (raw.includes('WAF') || raw.includes('WEB')) return 'WAF (حماية الويب)';
    if (raw.includes('IDS') || raw.includes('IPS') || raw.includes('INTRUSION')) return 'IDS/IPS (كشف التسلل)';
    if (raw.includes('DLP') || raw.includes('DATA')) return 'DLP (تسريب البيانات)';
    if (raw.includes('FW') || raw.includes('FIREWALL')) return 'جدار الحماية (Firewall)';
    if (raw.includes('SSL') || raw.includes('INSPECTION')) return 'فحص SSL/TLS';
    if (raw.includes('MALWARE') || raw.includes('AV')) return 'مكافحة البرمجيات الخبيثة';
    if (raw.includes('UBA') || raw.includes('BEHAVIOR')) return 'تحليل السلوك (UBA)';
    if (raw.includes('DNS')) return 'حماية DNS';
    if (raw.includes('PROXY')) return 'الوكيل (Proxy)';
    if (raw.includes('FLOW') || raw.includes('TRAFFIC')) return 'حركة الشبكة (Network Flow)';
    return raw || 'حماية الشبكة (NGFW Guard)';
  };

  const getRuleText = (ev) => {
    if (ev.rule) return ev.rule;
    if (ev.reason) return ev.reason;
    if (ev.signature) return ev.signature;
    if (ev.rule_id) return `قاعدة #${ev.rule_id}`;
    if (ev.description) return ev.description;
    if (Array.isArray(ev.triggers) && ev.triggers.length > 0) return ev.triggers[0];
    if (ev.details && typeof ev.details === 'string') return ev.details;
    if (ev.verdict) return `قاعدة فحص ${ev.verdict}`;
    return 'قاعدة الأمان المعتمدة (Default Security Rule)';
  };

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="flex-col h-full gap-4">

      {/* شريط الفلترة */}
      <div className="dash-panel glass-panel" style={{ padding: '12px 16px', flexShrink: 0, marginBottom: 16 }}>
        <form onSubmit={handleSearch} style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'rgba(255,255,255,0.4)', fontSize: '0.85rem' }}>
            <Filter size={16} />
            <span>فلترة الأحداث:</span>
          </div>
          <input
            type="text"
            placeholder="ابحث بعنوان IP المصدر..."
            value={filters.src_ip}
            onChange={e => setFilters({ ...filters, src_ip: e.target.value })}
            dir="ltr"
            style={{
              flex: 1,
              minWidth: 200,
              background: 'rgba(0, 0, 0, 0.25)',
              border: '1px solid rgba(255, 255, 255, 0.08)',
              borderRadius: 6,
              padding: '8px 12px',
              color: '#f0f0f5',
              fontSize: '0.82rem',
              outline: 'none',
              transition: 'border-color 0.2s',
              fontFamily: 'Cairo, sans-serif'
            }}
          />
          <select
            value={filters.verdict}
            onChange={e => setFilters({ ...filters, verdict: e.target.value })}
            style={{
              background: 'rgba(0, 0, 0, 0.25)',
              border: '1px solid rgba(255, 255, 255, 0.08)',
              borderRadius: 6,
              padding: '7px 12px',
              color: '#f0f0f5',
              fontSize: '0.82rem',
              outline: 'none',
              cursor: 'pointer',
              fontFamily: 'Cairo, sans-serif'
            }}
          >
            <option value="" style={{ background: '#13141e' }}>كل القرارات</option>
            <option value="BLOCK" style={{ background: '#13141e' }}>محجوب</option>
            <option value="ALLOW" style={{ background: '#13141e' }}>مسموح</option>
            <option value="WARN" style={{ background: '#13141e' }}>تحذير</option>
          </select>
          <button
            type="submit"
            style={{
              background: 'rgba(59, 130, 246, 0.12)',
              border: '1px solid rgba(59, 130, 246, 0.28)',
              color: '#3b82f6',
              borderRadius: 6,
              padding: '8px 20px',
              fontSize: '0.82rem',
              fontWeight: 700,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              fontFamily: 'Cairo, sans-serif',
              transition: 'all 0.2s'
            }}
          >
            <Search size={14} />
            بحث
          </button>
        </form>
      </div>

      {/* جدول الأحداث */}
      <div className="dash-panel glass-panel flex-1 flex-col" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="panel-header" style={{ padding: '1rem', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
          <div className="panel-title">
            أحداث الأمان المهيكلة ({result?.count || 0})
          </div>
        </div>

        <div className="custom-scrollbar flex-1" style={{ overflow: 'auto' }}>
          <table className="siem-data-grid">
            <thead>
              <tr>
                <th><Clock size={14}/> الطابع الزمني</th>
                <th>IP المصدر</th>
                <th>IP الوجهة</th>
                <th>الوحدة</th>
                <th>القاعدة / المشغّل</th>
                <th>القرار</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr><td colSpan="6" className="text-center text-muted" style={{ padding: '2rem' }}>
                  جاري تحميل الأحداث...
                </td></tr>
              ) : result?.data?.length > 0 ? (
                result.data.map((ev, i) => (
                  <tr
                    key={ev.id || i}
                    onClick={() => setSelectedEvent(ev)}
                    style={{ cursor: 'pointer' }}
                    className="hover-row"
                  >
                    <td className="text-muted text-sm">
                      {ev.timestamp ? new Date(ev.timestamp).toLocaleString('ar-SA') : 'غير محدد'}
                    </td>
                    <td className="font-mono text-cyan">{ev.src_ip || ev.source_ip || '*'}</td>
                    <td className="font-mono text-muted">{ev.dst_ip || ev.destination_ip || '*'}</td>
                    <td style={{ fontWeight: 600, color: '#38bdf8' }}>{getModuleName(ev)}</td>
                    <td className="text-sm truncate" style={{ maxWidth: '240px', color: '#e2e8f0' }} title={getRuleText(ev)}>
                      {getRuleText(ev)}
                    </td>
                    <td>{getVerdictBadge(ev.action || ev.verdict || 'تنبيه')}</td>
                  </tr>
                ))
              ) : (
                <tr><td colSpan="6" className="text-center text-muted" style={{ padding: '2rem' }}>
                  لا توجد أحداث تطابق معايير البحث.
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <AnimatePresence>
        {selectedEvent && (
          <EventDetailDrawer
            event={selectedEvent}
            onClose={() => setSelectedEvent(null)}
          />
        )}
      </AnimatePresence>

    </motion.div>
  );
}
