import React, { useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Radio, AlertTriangle, Target, Ban, Activity, RefreshCw } from 'lucide-react';
import { SectionCard, FilterBar, LiveDot, EmptyState } from '../../../components/Shared';
import { CxAreaChart } from '../../../components/ChartKit';
import FeedbackSelector from './FeedbackSelector';

const TIME_OPTS = [
  { label: 'ساعة', value: 1 },
  { label: '٢٤ ساعة', value: 24 },
  { label: '٧ أيام', value: 168 },
  { label: '٣٠ يوم', value: 720 },
];

export function AlertsView({ alerts, alertsLoading, refetchAlerts, cfg, hours, setHours, blockMutation, feedbackMutation, notify }) {
  const [search, setSearch] = useState('');

  const filtered = useMemo(() =>
    alerts.filter(a =>
      (a.src_ip && a.src_ip.includes(search)) ||
      (a.dst_ip && a.dst_ip.includes(search)) ||
      (a.category && a.category.toLowerCase().includes(search.toLowerCase())) ||
      String(a.sig_id || '').includes(search)
    ), [alerts, search]);

  const chartData = useMemo(() => {
    const groups = {};
    alerts.forEach(a => {
      const t = a.time?.split(':').slice(0, 2).join(':') || '00:00';
      groups[t] = (groups[t] || 0) + 1;
    });
    return Object.entries(groups)
      .map(([time, count]) => ({ time, count }))
      .sort((a, b) => a.time.localeCompare(b.time));
  }, [alerts]);

  const handleBlock = (ip, category) => {
    blockMutation.mutate({ ip, reason: `IPS: ${category}` });
  };

const SEVERITY_META = {
  critical: { label: 'حرج', cls: 'badge-danger' },
  high:     { label: 'عالي', cls: 'badge-danger' },
  warning:  { label: 'تحذير', cls: 'badge-warning' },
  info:     { label: 'معلومات', cls: 'badge-accent' },
};

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>

      {/* Timeline Chart — using ChartKit */}
      <SectionCard
        title={
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Radio size={14} className={alertsLoading ? 'ids-spin' : ''} style={{ color: 'var(--danger)' }} />
            التطفلات عبر الزمن (IDS/IPS Timeline)
            <span className="badge badge-accent" style={{ marginRight: 'auto' }}>آخر {alerts.length} حدثاً</span>
          </div>
        }
      >
        <CxAreaChart
          data={chartData.length > 0 ? chartData : [{ time: '—', count: 0 }]}
          dataKeys={[{ key: 'count', name: 'تنبيهات', color: 'var(--danger)' }]}
          xKey="time"
          height={180}
          unit=" تنبيه"
        />
      </SectionCard>

      {/* Alerts Table */}
      <SectionCard
        title={
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            تنبيهات التوقيع الحية وقاعدة البيانات
            <LiveDot active={true} />
          </div>
        }
        icon={Activity}
        actions={
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            {refetchAlerts && (
              <button
                className="ids-tab"
                onClick={() => refetchAlerts()}
                title="تحديث قائمة الأحداث"
                style={{ padding: '4px 8px', fontSize: '0.75rem' }}
              >
                <RefreshCw size={13} className={alertsLoading ? 'ids-spin' : ''} /> تحديث
              </button>
            )}
            <div className="ids-engine-badge" data-mode={cfg.mode}>
              <span className="ids-engine-dot" />
              {cfg.mode === 'blocking' ? 'حجب نشط (IPS)' : 'مراقبة فقط (IDS)'}
            </div>
          </div>
        }
      >
        <FilterBar placeholder="بحث بالـ IP، التوقيع، الهجوم..." value={search} onChange={setSearch} />
        {setHours && (
          <div style={{ display: 'flex', gap: 6, marginBottom: 8 }}>
            {TIME_OPTS.map(o => (
              <button
                key={o.value}
                className={`ids-tab${hours === o.value ? ' active' : ''}`}
                style={{ padding: '3px 10px', fontSize: '0.72rem' }}
                onClick={() => setHours(o.value)}
              >
                {o.label}
              </button>
            ))}
          </div>
        )}

        <div style={{ overflowX: 'auto', maxHeight: 480 }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>معرف التوقيع</th>
                <th>فئة الهجوم</th>
                <th>الخطورة</th>
                <th>المصدر → الهدف</th>
                <th>البروتوكول</th>
                <th>الوقت</th>
                <th style={{ width: 150, textAlign: 'center' }}>الاستجابة والتقييم</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 && (
                <tr><td colSpan={7}><EmptyState message="لا توجد تهديدات مكتشفة في هذه النافذة الزمنية" icon={Activity} /></td></tr>
              )}
              <AnimatePresence>
                {filtered.map(a => {
                  const sev = SEVERITY_META[a.severity] || SEVERITY_META.info;
                  return (
                    <motion.tr
                      key={a.id}
                      initial={{ x: 8, opacity: 0 }}
                      animate={{ x: 0, opacity: 1 }}
                      exit={{ opacity: 0 }}
                      transition={{ duration: 0.15 }}
                    >
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <span className="badge badge-accent mono">{a.sig_id}</span>
                          {a.is_live && <span className="badge badge-danger" style={{ fontSize: '0.65rem' }}>مباشر</span>}
                        </div>
                      </td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <AlertTriangle size={12} style={{ color: a.severity === 'critical' ? 'var(--danger)' : 'var(--warning)', flexShrink: 0 }} />
                          {a.category}
                        </div>
                      </td>
                      <td><span className={`badge ${sev.cls}`}>{sev.label}</span></td>
                      <td>
                        <div className="ids-ip-flow" dir="ltr">
                          <span className="mono" style={{ color: 'var(--danger)' }}>{a.src_ip}</span>
                          <Target size={10} style={{ color: 'var(--text-muted)' }} />
                          <span className="mono" style={{ color: 'var(--accent)' }}>{a.dst_ip}</span>
                        </div>
                      </td>
                      <td><span className="mono">{a.proto}</span></td>
                      <td><span className="mono" style={{ color: 'var(--text-muted)' }}>{a.time}</span></td>
                      <td style={{ textAlign: 'center' }}>
                        <div style={{ display: 'flex', gap: 8, justifyContent: 'center', alignItems: 'center' }}>
                          <FeedbackSelector
                            sampleId={a.sample_id || `sample_${a.id}`}
                            feedbackMutation={feedbackMutation}
                            notify={notify}
                          />
                          <button
                            className="ids-block-btn"
                            title={`حجب ${a.src_ip}`}
                            onClick={() => handleBlock(a.src_ip, a.category)}
                            disabled={blockMutation.isPending}
                          >
                            <Ban size={14} />
                          </button>
                        </div>
                      </td>
                    </motion.tr>
                  );
                })}
              </AnimatePresence>
            </tbody>
          </table>
        </div>
      </SectionCard>
    </div>
  );
}

export default AlertsView;

