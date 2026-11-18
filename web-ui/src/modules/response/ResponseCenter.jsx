/**
 * Response Center — Incident Response Management.
 * Refactored: Split into modular components, hook, and decentralized API layer.
 */
import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ShieldAlert, Search, AlertTriangle, Activity, Clock, CheckCircle2, Eye,
  Trash, Shield, Plus, Database
} from 'lucide-react';
import { PageHeader, KpiCard, SectionCard, ErrorState } from '../../components/Shared';
import useResponse from './hooks/useResponse';
import IncidentDetail from './components/IncidentDetail';
import './ResponseCenter.css';

const SEV_COLOR  = { critical: '#ff5f5f', high: '#ffc107', medium: '#00d4ff', low: '#28c76f', info: '#818cf8' };
const SEV_LABEL  = { critical: 'حرج', high: 'عالٍ', medium: 'متوسط', low: 'منخفض', info: 'معلومة' };
const STAT_COLOR = { open: '#ff5f5f', investigating: '#ffc107', contained: '#00d4ff', closed: '#28c76f' };
const STAT_LABEL = { open: 'مفتوح', investigating: 'قيد التحقيق', contained: 'محدود', closed: 'مغلق' };

export default function ResponseCenter() {
  const qc = useQueryClient();
  const {
    selected,
    setSelected,
    filter,
    setFilter,
    search,
    setSearch,
    isLoading,
    error,
    filtered,
    counts,
    kpis,
    selectedDetail,
    isDetailLoading,
    updateStatus,
    triggerAction,
    engines = [],
    isEnginesLoading,
    ttlEntries = {},
    isTtlLoading,
    removeTtlEntry,
    addTtlEntry,
    hardwareBlocks = [],
    isBlocksLoading,
    unblockIp
  } = useResponse();

  // Local Form State for manual temporary block
  const [newTarget, setNewTarget] = useState('');
  const [newAction, setNewAction] = useState('BLOCK');
  const [newTtl, setNewTtl] = useState(3600);
  const [newReason, setNewReason] = useState('إجراء وقائي يدوي');
  const [newRate, setNewRate] = useState(10);

  const getKpiIcon = (name) => {
    switch (name) {
      case 'alert': return <AlertTriangle size={18} />;
      case 'activity': return <Activity size={18} />;
      case 'clock': return <Clock size={18} />;
      case 'success': default: return <CheckCircle2 size={18} />;
    }
  };

  const handleSubmitTtl = (e) => {
    e.preventDefault();
    if (!newTarget) return;
    addTtlEntry({
      action: newAction,
      target: newTarget,
      ttl: Number(newTtl),
      reason: newReason,
      rate: newAction === 'RATE_LIMIT' ? Number(newRate) : undefined
    });
    setNewTarget('');
  };

  if (error) {
    return <ErrorState message="فشل تحميل قائمة حوادث الأمان" onRetry={() => qc.invalidateQueries({ queryKey: ['incidents-list'] })} />;
  }

  const ttlList = Object.values(ttlEntries);

  return (
    <div className="rc-wrap" dir="rtl">
      <PageHeader
        icon={ShieldAlert}
        title="مركز الاستجابة للحوادث"
        subtitle="تحليل وإدارة الحوادث الأمنية في الوقت الحقيقي"
      />

      {/* KPIs */}
      <div className="rc-kpi-grid">
        {kpis.map((k, i) => (
          <KpiCard key={k.label} icon={getKpiIcon(k.icon)} value={k.value} label={k.label} color={k.color} delay={i * 0.07} />
        ))}
      </div>

      <SectionCard
        title="قائمة الحوادث"
        icon={ShieldAlert}
        actions={
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            {/* Search */}
            <div className="rc-search">
              <Search size={14} style={{ color: 'rgba(255,255,255,0.3)' }} />
              <input
                placeholder="ابحث بالعنوان أو IP..."
                value={search}
                onChange={e => setSearch(e.target.value)}
                className="rc-search-input"
              />
            </div>
            {/* Filter tabs */}
            {[
              { key: 'all',      label: `الكل (${counts.all})` },
              { key: 'open',     label: `مفتوح (${counts.open})` },
              { key: 'critical', label: `حرج (${counts.critical})` },
            ].map(f => (
              <button key={f.key} onClick={() => setFilter(f.key)} className={`rc-filter-btn${filter === f.key ? ' active' : ''}`}>
                {f.label}
              </button>
            ))}
          </div>
        }
      >
        {/* Table header */}
        <div className="rc-table-header">
          <span>الحادثة</span>
          <span>الخطورة</span>
          <span>الحالة</span>
          <span>IP المصدر</span>
          <span>الوحدة</span>
          <span>الوقت</span>
          <span></span>
        </div>

        <div className="rc-incident-list">
          {isLoading ? (
            <div style={{ padding: '32px', textAlign: 'center', color: 'rgba(255,255,255,0.3)' }}>
              جاري تحميل الحوادث الحية...
            </div>
          ) : filtered.length === 0 ? (
            <div style={{ padding: '32px', textAlign: 'center', color: 'rgba(255,255,255,0.2)', fontSize: '0.9rem' }}>
              لا توجد حوادث نشطة مطابقة
            </div>
          ) : (
            filtered.map((inc, i) => (
              <motion.div
                key={inc.id}
                className="rc-incident-row"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.04 }}
                onClick={() => setSelected(inc)}
              >
                <div>
                  <div className="rc-inc-id" dir="ltr">{inc.id}</div>
                  <div className="rc-inc-title">{inc.title}</div>
                </div>
                <span className="rc-sev-badge" style={{ color: SEV_COLOR[inc.severity], borderColor: SEV_COLOR[inc.severity] + '44', background: SEV_COLOR[inc.severity] + '11' }}>
                  {SEV_LABEL[inc.severity]}
                </span>
                <span className="rc-status-badge" style={{ color: STAT_COLOR[inc.status], borderColor: STAT_COLOR[inc.status] + '44', background: STAT_COLOR[inc.status] + '11' }}>
                  {STAT_LABEL[inc.status]}
                </span>
                <span dir="ltr" className="rc-ip">{inc.src_ip || '---'}</span>
                <span className="rc-module">{inc.module}</span>
                <span className="rc-time">{inc.ts ? new Date(inc.ts).toLocaleString('ar-SA') : 'منذ قليل'}</span>
                <button className="rc-detail-btn" onClick={e => { e.stopPropagation(); setSelected(inc); }}>
                  <Eye size={14} />
                </button>
              </motion.div>
            ))
          )}
        </div>
      </SectionCard>

      {/* Policy Engines, Active TTL blocks, and Hardware eBPF Blocks */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.8fr 1.2fr', gap: 16, marginTop: 16 }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Active TTL blocks */}
          <SectionCard
            title="قرارات الحظر والتقييد المؤقتة (Active TTL Decisions)"
            icon={Activity}
          >
            <div className="rc-table-header" style={{ gridTemplateColumns: '1.2fr 1fr 1fr 1.5fr 1fr 0.4fr' }}>
              <span>الهدف</span>
              <span>الإجراء</span>
              <span>الزمن المتبقي</span>
              <span>السبب</span>
              <span>تاريخ الانتهاء</span>
              <span></span>
            </div>

            <div className="rc-incident-list" style={{ maxHeight: 350, overflowY: 'auto' }}>
              {isTtlLoading ? (
                <div style={{ padding: '24px', textAlign: 'center', color: 'rgba(255,255,255,0.3)' }}>
                  جاري تحميل قرارات الحظر المؤقتة...
                </div>
              ) : ttlList.length === 0 ? (
                <div style={{ padding: '32px', textAlign: 'center', color: 'rgba(255,255,255,0.2)', fontSize: '0.88rem' }}>
                  لا توجد قرارات حظر أو تقييد مؤقتة نشطة حالياً.
                </div>
              ) : (
                ttlList.map((entry, idx) => (
                  <div
                    key={idx}
                    className="rc-incident-row"
                    style={{ gridTemplateColumns: '1.2fr 1fr 1fr 1.5fr 1fr 0.4fr', padding: '12px 16px' }}
                  >
                    <span dir="ltr" className="mono bold" style={{ color: '#00d4ff' }}>{entry.target}</span>
                    <span className="rc-status-badge" style={{
                      color: entry.action === 'BLOCK' ? '#ff5f5f' : entry.action === 'RATE_LIMIT' ? '#ffc107' : '#00d4ff',
                      borderColor: (entry.action === 'BLOCK' ? '#ff5f5f' : entry.action === 'RATE_LIMIT' ? '#ffc107' : '#00d4ff') + '44',
                      background: (entry.action === 'BLOCK' ? '#ff5f5f' : entry.action === 'RATE_LIMIT' ? '#ffc107' : '#00d4ff') + '11'
                    }}>
                      {entry.action === 'BLOCK' ? 'حظر مؤقت' : entry.action === 'RATE_LIMIT' ? 'تحديد معدل' : 'عزل مؤقت'}
                    </span>
                    <span style={{ color: '#28c76f', fontFamily: 'Fira Code, monospace', fontSize: '0.8rem' }}>
                      {Math.round(entry.time_remaining)} ثانية
                    </span>
                    <span style={{ color: 'rgba(255,255,255,0.6)', fontSize: '0.8rem' }}>{entry.reason}</span>
                    <span style={{ color: 'rgba(255,255,255,0.35)', fontSize: '0.78rem' }}>
                      {new Date(entry.expires_at).toLocaleTimeString('ar-SA')}
                    </span>
                    <button
                      className="rc-detail-btn"
                      style={{ color: '#ff5f5f', borderColor: 'rgba(255,95,95,0.2)', background: 'rgba(255,95,95,0.05)' }}
                      onClick={() => removeTtlEntry(entry.action, entry.target)}
                    >
                      <Trash size={12} />
                    </button>
                  </div>
                ))
              )}
            </div>
          </SectionCard>

          {/* Active Hardware eBPF Blocked IPs */}
          <SectionCard
            title="عناوين IP المحجوبة عتادياً (Hardware eBPF Blocks)"
            icon={Database}
          >
            <div className="rc-table-header" style={{ gridTemplateColumns: '2fr 1.5fr 1fr' }}>
              <span>عنوان IP المحجوب</span>
              <span>مستوى الحظر</span>
              <span></span>
            </div>

            <div className="rc-incident-list" style={{ maxHeight: 220, overflowY: 'auto' }}>
              {isBlocksLoading ? (
                <div style={{ padding: '16px', textAlign: 'center', color: 'rgba(255,255,255,0.3)', fontSize: '0.85rem' }}>
                  جاري تحميل محجوبات العتاد...
                </div>
              ) : hardwareBlocks.length === 0 ? (
                <div style={{ padding: '24px', textAlign: 'center', color: 'rgba(255,255,255,0.2)', fontSize: '0.85rem' }}>
                  لا توجد عناوين IP محجوبة على مستوى العتاد حالياً.
                </div>
              ) : (
                hardwareBlocks.map((item, idx) => {
                  const ipStr = typeof item === 'string' ? item : (item?.ip || '');
                  const reasonStr = typeof item === 'object' 
                    ? (item?.reason || item?.blocked_by || 'eBPF Kernel XDP Block') 
                    : 'eBPF Kernel XDP Block';
                  return (
                    <div
                      key={ipStr || idx}
                      className="rc-incident-row"
                      style={{ gridTemplateColumns: '2fr 1.5fr 1fr', padding: '10px 14px' }}
                    >
                      <span dir="ltr" className="mono bold" style={{ color: '#ff5f5f' }}>{ipStr}</span>
                      <span className="rc-status-badge" style={{ color: '#ff5f5f', borderColor: 'rgba(255,95,95,0.3)', background: 'rgba(255,95,95,0.1)' }}>
                        {reasonStr}
                      </span>
                      <button
                        className="rc-detail-btn"
                        style={{ color: '#28c76f', borderColor: 'rgba(40,199,111,0.2)', background: 'rgba(40,199,111,0.05)', justifySelf: 'end' }}
                        title="فك الحجب العتادي"
                        onClick={() => unblockIp(ipStr)}
                      >
                        <Trash size={12} />
                      </button>
                    </div>
                  );
                })
              )}
            </div>
          </SectionCard>
        </div>

        {/* Sidebar: Engine list & manual trigger */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Engines Panel */}
          <SectionCard title="محركات السياسات النشطة" icon={Shield}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, padding: '8px 0' }}>
              {isEnginesLoading ? (
                <div style={{ color: 'rgba(255,255,255,0.3)', fontSize: '0.85rem' }}>جاري التحميل...</div>
              ) : engines.length === 0 ? (
                <div style={{ color: 'rgba(255,255,255,0.2)', fontSize: '0.85rem' }}>لا توجد محركات مسجلة.</div>
              ) : (
                engines.map((eng, idx) => (
                  <div key={idx} style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    background: 'rgba(255,255,255,0.02)',
                    border: '1px solid var(--border)',
                    borderRadius: 4,
                    padding: '8px 12px'
                  }}>
                    <span style={{ fontSize: '0.85rem', fontWeight: 700, color: '#f0f0f5' }}>{eng}</span>
                    <span style={{ fontSize: '0.7rem', color: '#28c76f', background: 'rgba(40,199,111,0.15)', padding: '2px 6px', borderRadius: 4, fontWeight: 700 }}>
                      مفعّل
                    </span>
                  </div>
                ))
              )}
            </div>
          </SectionCard>

          {/* Manual Entry Form Panel */}
          <SectionCard title="إضافة إجراء وقائي يدوي" icon={Plus}>
            <form onSubmit={handleSubmitTtl} style={{ display: 'flex', flexDirection: 'column', gap: 12, padding: '8px 0' }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                <label style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.4)' }}>عنوان IP المستهدف:</label>
                <input
                  type="text"
                  placeholder="مثال: 192.168.1.50..."
                  value={newTarget}
                  onChange={e => setNewTarget(e.target.value)}
                  required
                  style={{
                    background: 'rgba(0,0,0,0.2)',
                    border: '1px solid var(--border)',
                    borderRadius: 4,
                    padding: '8px 10px',
                    color: '#f0f0f5',
                    fontSize: '0.85rem',
                    outline: 'none'
                  }}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <label style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.4)' }}>الإجراء:</label>
                  <select
                    value={newAction}
                    onChange={e => setNewAction(e.target.value)}
                    style={{
                      background: 'rgba(0,0,0,0.2)',
                      border: '1px solid var(--border)',
                      borderRadius: 4,
                      padding: '7px 8px',
                      color: '#f0f0f5',
                      fontSize: '0.85rem',
                      outline: 'none'
                    }}
                  >
                    <option value="BLOCK">حظر مؤقت</option>
                    <option value="RATE_LIMIT">تحديد معدل</option>
                    <option value="QUARANTINE">عزل مؤقت</option>
                  </select>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <label style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.4)' }}>الـ TTL (بالثواني):</label>
                  <input
                    type="number"
                    value={newTtl}
                    onChange={e => setNewTtl(e.target.value)}
                    required
                    style={{
                      background: 'rgba(0,0,0,0.2)',
                      border: '1px solid var(--border)',
                      borderRadius: 4,
                      padding: '8px 10px',
                      color: '#f0f0f5',
                      fontSize: '0.85rem',
                      outline: 'none'
                    }}
                  />
                </div>
              </div>

              {newAction === 'RATE_LIMIT' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <label style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.4)' }}>المعدل المسموح (طلب/ثانية):</label>
                  <input
                    type="number"
                    value={newRate}
                    onChange={e => setNewRate(e.target.value)}
                    required
                    style={{
                      background: 'rgba(0,0,0,0.2)',
                      border: '1px solid var(--border)',
                      borderRadius: 4,
                      padding: '8px 10px',
                      color: '#f0f0f5',
                      fontSize: '0.85rem',
                      outline: 'none'
                    }}
                  />
                </div>
              )}

              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                <label style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.4)' }}>سبب الحظر:</label>
                <input
                  type="text"
                  value={newReason}
                  onChange={e => setNewReason(e.target.value)}
                  style={{
                    background: 'rgba(0,0,0,0.2)',
                    border: '1px solid var(--border)',
                    borderRadius: 4,
                    padding: '8px 10px',
                    color: '#f0f0f5',
                    fontSize: '0.85rem',
                    outline: 'none'
                  }}
                />
              </div>

              <button
                type="submit"
                style={{
                  background: 'rgba(40,199,111,0.15)',
                  color: '#28c76f',
                  border: '1px solid rgba(40,199,111,0.25)',
                  borderRadius: 4,
                  padding: '8px 12px',
                  cursor: 'pointer',
                  fontSize: '0.85rem',
                  fontWeight: 700,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: 6,
                  marginTop: 6
                }}
              >
                <Plus size={14} /> إضافة القرار الوقائي
              </button>
            </form>
          </SectionCard>
        </div>
      </div>

      <AnimatePresence>
        {selected && (
          <IncidentDetail
            incident={selectedDetail || selected}
            isLoading={isDetailLoading}
            onClose={() => setSelected(null)}
            onStatusUpdate={updateStatus}
            onAction={triggerAction}
          />
        )}
      </AnimatePresence>
    </div>
  );
}
