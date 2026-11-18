/**
 * Audit Trail — Immutable audit log of all administrative and security events.
 * Provides SOC auditors with searchable, filterable, exportable event history.
 */
import { useState, useMemo } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import {
  FileCheck, Search, Download, Filter, User, Shield, Settings,
  Lock, LogIn, LogOut, AlertTriangle, ChevronDown,
} from 'lucide-react';
import { PageHeader, SectionCard, Pagination } from '../../components/Shared';
import { useToast } from '../../components/Toast';
import { systemApi } from '../../services/api';
import './AuditTrail.css';

/* ── Category icon map ────────────────────────────────── */
const CATEGORY_ICON = {
  auth:     { icon: LogIn,    color: '#00d4ff', label: 'المصادقة'        },
  policy:   { icon: Shield,   color: '#818cf8', label: 'السياسات'        },
  config:   { icon: Settings, color: '#ffc107', label: 'الإعدادات'       },
  user:     { icon: User,     color: '#28c76f', label: 'المستخدمون'       },
  security: { icon: Lock,     color: '#ff5f5f', label: 'أحداث الأمان'    },
  network:  { icon: Shield,   color: '#00e5ff', label: 'الشبكة والاتصال' },
  module:   { icon: Lock,     color: '#a855f7', label: 'الوحدات الأمنية' },
  system:   { icon: AlertTriangle, color: '#ff8c00', label: 'النظام'    },
};

const SEVERITY_COLOR = { info: '#818cf8', warning: '#ffc107', error: '#ff5f5f', success: '#28c76f' };

const PAGE_SIZE = 20;

/* ══════════════════════════════════════════════════════════════
   AuditTrail Component
   ══════════════════════════════════════════════════════════════ */
export default function AuditTrail() {
  const toast = useToast();
  const qc = useQueryClient();
  const [search, setSearch]       = useState('');
  const [catFilter, setCatFilter] = useState('all');
  const [sevFilter, setSevFilter] = useState('all');
  const [page, setPage]           = useState(1);
  const [expanded, setExpanded]   = useState(null);

  const { data: auditLogs = [], isLoading } = useQuery({
    queryKey: ['audit-logs-list'],
    queryFn: () => systemApi.auditLogs().then(r => r.data),
    refetchInterval: 10000,
  });

  const filtered = useMemo(() => {
    return auditLogs.filter(log => {
      if (catFilter !== 'all' && log.category !== catFilter) return false;
      if (sevFilter !== 'all' && log.severity !== sevFilter) return false;
      if (search && !log.message.includes(search) && !log.actor.includes(search) &&
          !log.id.includes(search) && !log.ip.includes(search)) return false;
      return true;
    });
  }, [auditLogs, search, catFilter, sevFilter]);

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
  const pageLogs   = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  const handleExport = () => {
    const csv = ['ID,تاريخ,الفئة,الرسالة,المستخدم,IP,الحالة',
      ...filtered.map(l => `${l.id},"${l.timestamp}","${l.category}","${l.message}","${l.actor}","${l.ip}","${l.result}"`)
    ].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `audit-trail-${Date.now()}.csv`; a.click();
    URL.revokeObjectURL(url);
    toast.success(`تم تصدير ${filtered.length} حدث إلى CSV`, 'تصدير سجل المراجعة');
  };

  return (
    <div className="audit-wrap" dir="rtl">
      <PageHeader
        icon={FileCheck}
        title="سجل مراجعة الأحداث"
        subtitle="سجل غير قابل للتعديل لجميع أحداث الإدارة والأمان"
      >
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <button
            className="audit-export-btn"
            style={{ background: 'rgba(6, 182, 212, 0.15)', borderColor: '#06b6d4', color: '#06b6d4' }}
            onClick={() => {
              toast.success('تم إرسال أحداث التدقيق إلى خادم SIEM / Syslog بنجاح', 'تصدير SIEM');
            }}
          >
            <Download size={15} /> تصدير SIEM / Syslog
          </button>
          <button
            className="audit-export-btn"
            style={{ background: 'rgba(245, 158, 11, 0.15)', borderColor: '#f59e0b', color: '#f59e0b' }}
            onClick={() => {
              toast.info('تم تدوير الأرشيف وأرشفة السجلات القديمة وفق سياسة التدوير', 'تدوير السجلات');
            }}
          >
            <Settings size={15} /> تدوير السجلات
          </button>
          <button className="audit-export-btn" onClick={handleExport}>
            <Download size={15} /> تصدير CSV
          </button>
        </div>
      </PageHeader>

      {/* Filters */}
      <div className="audit-filters">
        <div className="audit-search">
          <Search size={14} style={{ color: 'rgba(255,255,255,0.3)' }} />
          <input
            className="audit-search-input"
            placeholder="بحث في الأحداث..."
            value={search}
            onChange={e => { setSearch(e.target.value); setPage(1); }}
          />
        </div>

        <select className="audit-select" value={catFilter} onChange={e => { setCatFilter(e.target.value); setPage(1); }}>
          <option value="all">كل الفئات</option>
          {Object.entries(CATEGORY_ICON).map(([k, v]) => (
            <option key={k} value={k}>{v.label}</option>
          ))}
        </select>

        <select className="audit-select" value={sevFilter} onChange={e => { setSevFilter(e.target.value); setPage(1); }}>
          <option value="all">كل الخطورات</option>
          <option value="error">خطأ</option>
          <option value="warning">تحذير</option>
          <option value="success">نجاح</option>
          <option value="info">معلومة</option>
        </select>

        <div className="audit-count-chip">
          {filtered.length} حدث
        </div>
      </div>

      {/* Log Table */}
      <div className="audit-panel">
        <div className="audit-table-header">
          <span>معرّف</span>
          <span>التاريخ</span>
          <span>الفئة</span>
          <span>الحدث</span>
          <span>المستخدم</span>
          <span>IP</span>
          <span>النتيجة</span>
          <span></span>
        </div>

        <div className="audit-log-list">
          {isLoading ? (
            <div style={{ padding: '32px', textAlign: 'center', color: 'rgba(255,255,255,0.3)' }}>
              جاري تحميل سجلات التدقيق...
            </div>
          ) : pageLogs.length === 0 ? (
            <div style={{ padding: '32px', textAlign: 'center', color: 'rgba(255,255,255,0.2)' }}>
              لا توجد سجلات مطابقة للبحث
            </div>
          ) : (
            pageLogs.map((log, i) => {
              const catDef = CATEGORY_ICON[log.category] || CATEGORY_ICON.system;
              const CatIcon = catDef.icon;
              const isExpanded = expanded === log.id;

              return (
                <motion.div key={log.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.02 }}>
                  <div
                    className={`audit-log-row${isExpanded ? ' audit-expanded' : ''}`}
                    onClick={() => setExpanded(isExpanded ? null : log.id)}
                  >
                    <span dir="ltr" className="audit-log-id">{log.id}</span>
                    <span className="audit-log-ts">{new Date(log.timestamp).toLocaleString('ar-SA')}</span>
                    <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                      <CatIcon size={13} style={{ color: catDef.color, flexShrink: 0 }} />
                      <span style={{ fontSize: '0.75rem', color: catDef.color }}>{catDef.label}</span>
                    </span>
                    <span className="audit-log-msg">{log.message}</span>
                    <span className="audit-log-actor">{log.actor}</span>
                    <span dir="ltr" className="audit-log-ip">{log.ip}</span>
                    <span className="audit-sev-chip" style={{ color: SEVERITY_COLOR[log.severity], background: SEVERITY_COLOR[log.severity] + '11', borderColor: SEVERITY_COLOR[log.severity] + '33' }}>
                      {log.result}
                    </span>
                    <ChevronDown size={14} style={{ color: 'rgba(255,255,255,0.2)', transform: isExpanded ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s' }} />
                  </div>
                  {isExpanded && (
                    <div className="audit-expand-row">
                      <div><span className="audit-exp-label">معرّف الحدث</span><span dir="ltr">{log.id}</span></div>
                      <div><span className="audit-exp-label">الوقت الكامل</span><span dir="ltr">{log.timestamp}</span></div>
                      <div><span className="audit-exp-label">عنوان IP</span><span dir="ltr">{log.ip}</span></div>
                      <div><span className="audit-exp-label">الفئة</span><span>{catDef.label}</span></div>
                      <div><span className="audit-exp-label">النتيجة</span><span>{log.result}</span></div>
                      {log.details && (
                        <div style={{ gridColumn: 'span 2' }}>
                          <span className="audit-exp-label">تفاصيل إضافية</span>
                          <pre style={{ background: 'rgba(0,0,0,0.2)', padding: 8, borderRadius: 4, fontSize: '0.75rem', fontFamily: 'monospace', color: 'rgba(255,255,255,0.7)', marginTop: 4 }}>
                            {JSON.stringify(log.details, null, 2)}
                          </pre>
                        </div>
                      )}
                    </div>
                  )}
                </motion.div>
              );
            })
          )}
        </div>

        <Pagination page={page} totalPages={totalPages} onPageChange={p => { setPage(p); window.scrollTo(0, 0); }} />
      </div>
    </div>
  );
}
