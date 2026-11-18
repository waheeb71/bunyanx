/**
 * Firewall Module — Central access control policies dashboard.
 * Enterprise SOC Grade: Persistent State, Realtime Telemetry, Multi-Select Bulk Actions, Data Export.
 */
import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield, Plus, Trash2, Edit2, XCircle, CheckCircle2,
  BrainCircuit, ArrowUpDown, ToggleLeft, ToggleRight,
  ShieldOff, Zap, Filter, ChevronDown, Play, Settings,
  Server, RefreshCw, Download, FileSpreadsheet, AlertTriangle, X, Activity, Cpu
} from 'lucide-react';
import {
  PageHeader, KpiCard, SectionCard, FilterBar,
  StatusBadge, EmptyState, LiveDot
} from '../../components/Shared';
import useFirewall from './hooks/useFirewall';
import RuleRow from './components/RuleRow';
import AddEditModal from './components/AddEditModal';
import XDPPanel from './components/XDPPanel';
import PolicyTester from './components/PolicyTester';
import FirewallSettings from './components/FirewallSettings';
import Optimizer from './Optimizer';
import IPBlocklist from './IPBlocklist';
import IPWhitelist from './IPWhitelist';
import './Firewall.css';

const TABS = [
  { id: 'rules',     icon: Shield,       label: 'قواعد السياسة' },
  { id: 'blocklist', icon: ShieldOff,    label: 'قائمة الحظر (IP)' },
  { id: 'whitelist', icon: CheckCircle2, label: 'قائمة الاستثناءات (Whitelist)' },
  { id: 'optimizer', icon: BrainCircuit, label: 'المُحسِّن الذكي' },
  { id: 'xdp',       icon: Zap,          label: 'تسريع XDP / eBPF' },
  { id: 'tester',    icon: Play,         label: 'فاحص السياسات (Flow Tester)' },
  { id: 'settings',  icon: Settings,     label: 'الإعدادات والمناطق' },
];

export default function Firewall() {
  const {
    tab,
    setTab,
    search,
    setSearch,
    filterAction,
    setFilterAction,
    selectedRuleIds,
    toggleRuleSelect,
    selectAllRules,
    clearRuleSelect,
    activeModal,
    setActiveModal,
    confirmBulkDeleteModal,
    setConfirmBulkDeleteModal,
    editRule,
    isLoading,
    rules,
    allRulesCount,
    handleEdit,
    handleSave,
    onDelete,
    onToggle,
    onBulkDelete,
    onBulkToggle,
    exportRulesCSV,
    exportRulesJSON,
    isSaving,
    toast,
    hideToast,
    liveStats,
  } = useFirewall();

  const [showFilter, setShowFilter] = useState(false);

  const allowCount = rules.filter(r => r.action === 'ALLOW' && r.enabled).length;
  const dropCount = rules.filter(r => (r.action === 'DROP' || r.action === 'BLOCK' || r.action === 'REJECT') && r.enabled).length;
  const activeConn = liveStats?.active_connections ?? 0;
  const cbHealth = liveStats?.circuit_breaker ?? 'NORMAL';

  const isAllSelected = rules.length > 0 && selectedRuleIds.length === rules.length;

  return (
    <div className="module-page">
      {/* ── Toast Notification Banner ──────────────── */}
      <AnimatePresence>
        {toast && (
          <motion.div
            initial={{ opacity: 0, y: -15 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -15 }}
            style={{
              position: 'fixed',
              top: 20,
              left: '50%',
              transform: 'translateX(-50%)',
              zIndex: 9999,
              background: toast.type === 'error' ? 'rgba(255, 77, 106, 0.92)' : toast.type === 'success' ? 'rgba(40, 199, 111, 0.92)' : 'rgba(0, 200, 255, 0.92)',
              color: '#000',
              padding: '10px 20px',
              borderRadius: '8px',
              fontWeight: 700,
              boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
              display: 'flex',
              alignItems: 'center',
              gap: 10,
              fontSize: '0.88rem'
            }}
          >
            {toast.type === 'error' ? <AlertTriangle size={18} /> : <CheckCircle2 size={18} />}
            <span>{toast.message}</span>
            <X size={15} style={{ cursor: 'pointer', marginRight: 8 }} onClick={hideToast} />
          </motion.div>
        )}
      </AnimatePresence>

      {/* ── Header ──────────────────────────── */}
      <PageHeader
        icon={Shield}
        title="قواعد الجدار الناري"
        subtitle="إدارة سياسات التحكم في الوصول الشبكي — ACL Engine"
      >
        <StatusBadge status="active" />
        <LiveDot active />
      </PageHeader>

      {/* ── KPI & Telemetry Cards ───────────────────────── */}
      <div className="kpi-row">
        <KpiCard icon={<Shield size={18} />} value={allRulesCount} label="إجمالي القواعد" color="var(--accent)" delay={0} />
        <KpiCard icon={<CheckCircle2 size={18} />} value={allowCount} label="قواعد سماح نشطة" color="var(--success)" delay={0.05} />
        <KpiCard icon={<XCircle size={18} />} value={dropCount} label="قواعد حجب نشطة" color="var(--danger)" delay={0.1} />
        <KpiCard icon={<Activity size={18} />} value={activeConn.toLocaleString()} label="الاتصالات النشطة" color="var(--warning)" delay={0.15} />
        <KpiCard icon={<Cpu size={18} />} value={cbHealth} label="صحة المحرك (Breaker)" color={cbHealth === 'NORMAL' ? 'var(--success)' : 'var(--danger)'} delay={0.2} />
      </div>

      {/* ── Custom Tabs ─────────────────────── */}
      <div className="fw-tabs">
        {TABS.map(t => {
          const Icon = t.icon;
          return (
            <button key={t.id} className={`fw-tab ${tab === t.id ? 'active' : ''}`} onClick={() => setTab(t.id)}>
              <Icon size={15} /> {t.label}
            </button>
          );
        })}
      </div>

      {/* ── View Area ───────────────────────── */}
      <AnimatePresence mode="wait">
        <motion.div
          key={tab}
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -6 }}
          transition={{ duration: 0.2 }}
        >
          {tab === 'rules' && (
            <SectionCard
              title={`قواعد السياسة (${rules.length} / ${allRulesCount})`}
              icon={Shield}
              actions={
                <div style={{ display: 'flex', gap: 8 }}>
                  <button className="fw-btn-ghost" title="تصدير CSV" onClick={exportRulesCSV}>
                    <FileSpreadsheet size={15} /> تصدير CSV
                  </button>
                  <button className="fw-btn-ghost" title="تصدير JSON" onClick={exportRulesJSON}>
                    <Download size={15} /> تصدير JSON
                  </button>
                  <button className="fw-btn-primary" onClick={() => setActiveModal('add')}>
                    <Plus size={15} /> إضافة قاعدة
                  </button>
                </div>
              }
            >
              {/* Filter & Bulk Bar */}
              <div style={{ display: 'flex', gap: 10, marginBottom: 'var(--sp-3)', alignItems: 'center', flexWrap: 'wrap' }}>
                <FilterBar placeholder="ابحث بالاسم، المنفذ، المصدر..." value={search} onChange={setSearch} />
                <div style={{ position: 'relative' }}>
                  <button className="fw-filter-btn" onClick={() => setShowFilter(v => !v)}>
                    <Filter size={13} /> تصفية <ChevronDown size={11} />
                  </button>
                  {showFilter && (
                    <div className="fw-filter-dropdown">
                      {[
                        { val: 'all', label: 'الكل' },
                        { val: 'ALLOW', label: 'سماح (ALLOW)' },
                        { val: 'DROP', label: 'حجب (DROP)' },
                        { val: 'REJECT', label: 'رفض (REJECT)' },
                        { val: 'LOG', label: 'تسجيل (LOG)' },
                      ].map(f => (
                        <button key={f.val} className={`fw-filter-opt ${filterAction === f.val ? 'active' : ''}`} onClick={() => { setFilterAction(f.val); setShowFilter(false); }}>
                          {f.label}
                        </button>
                      ))}
                    </div>
                  )}
                </div>

                {/* Bulk Actions Controls */}
                {selectedRuleIds.length > 0 && (
                  <motion.div
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    style={{
                      marginRight: 'auto',
                      display: 'flex',
                      alignItems: 'center',
                      gap: 8,
                      background: 'rgba(0, 200, 255, 0.08)',
                      border: '1px solid var(--accent)',
                      borderRadius: '8px',
                      padding: '4px 12px'
                    }}
                  >
                    <span style={{ fontSize: '0.8rem', color: 'var(--accent)', fontWeight: 700 }}>
                      محدد: {selectedRuleIds.length} قاعدة
                    </span>
                    <button className="fw-btn-ghost" style={{ padding: '4px 8px', fontSize: '0.75rem' }} onClick={() => onBulkToggle(true)}>
                      <ToggleRight size={13} /> تفعيل
                    </button>
                    <button className="fw-btn-ghost" style={{ padding: '4px 8px', fontSize: '0.75rem' }} onClick={() => onBulkToggle(false)}>
                      <ToggleLeft size={13} /> تعطيل
                    </button>
                    <button className="fw-btn-primary" style={{ background: 'var(--danger)', color: '#fff', padding: '4px 8px', fontSize: '0.75rem' }} onClick={() => setConfirmBulkDeleteModal(true)}>
                      <Trash2 size={13} /> حذف الملاحظات
                    </button>
                    <button className="fw-btn-ghost" style={{ padding: '4px 6px', fontSize: '0.75rem' }} onClick={clearRuleSelect}>
                      <X size={13} />
                    </button>
                  </motion.div>
                )}
              </div>

              {/* Table */}
              <div style={{ overflowX: 'auto', maxHeight: 520 }}>
                <table className="data-table">
                  <thead>
                    <tr>
                      <th style={{ width: 40, textAlign: 'center' }}>
                        <input
                          type="checkbox"
                          checked={isAllSelected}
                          onChange={() => isAllSelected ? clearRuleSelect() : selectAllRules()}
                          style={{ cursor: 'pointer', accentColor: 'var(--accent)' }}
                        />
                      </th>
                      <th><div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>الاسم / الأولوية <ArrowUpDown size={11} style={{ opacity: 0.3 }} /></div></th>
                      <th>الإجراء</th>
                      <th>البروتوكول</th>
                      <th>المصدر</th>
                      <th>الوجهة</th>
                      <th>المنفذ</th>
                      <th>الحالة</th>
                      <th style={{ width: 70 }}></th>
                    </tr>
                  </thead>
                  <tbody>
                    {isLoading ? (
                      <tr><td colSpan={9} style={{ textAlign: 'center', padding: '32px' }}><RefreshCw className="spin" size={24} style={{ opacity: 0.3 }} /></td></tr>
                    ) : rules.length === 0 ? (
                      <tr><td colSpan={9}><EmptyState message="لا توجد قواعد تطابق البحث" icon={Shield} /></td></tr>
                    ) : (
                      rules.map(rule => (
                        <RuleRow
                          key={rule.id}
                          rule={rule}
                          isSelected={selectedRuleIds.includes(rule.id)}
                          onSelectToggle={toggleRuleSelect}
                          onDelete={onDelete}
                          onEdit={handleEdit}
                          onToggle={onToggle}
                        />
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </SectionCard>
          )}
          {tab === 'blocklist'  && <IPBlocklist />}
          {tab === 'whitelist'  && <IPWhitelist />}
          {tab === 'optimizer'  && <Optimizer />}
          {tab === 'xdp'        && <XDPPanel />}
          {tab === 'tester'     && <PolicyTester />}
          {tab === 'settings'   && <FirewallSettings />}
        </motion.div>
      </AnimatePresence>

      {/* ── Modals ── */}
      {activeModal === 'add' && (
        <AddEditModal onClose={() => setActiveModal(false)} onSave={handleSave} loading={isSaving} />
      )}
      {activeModal === 'edit' && (
        <AddEditModal rule={editRule} onClose={() => setActiveModal(false)} onSave={handleSave} loading={isSaving} />
      )}

      {/* Bulk Delete Modal */}
      {confirmBulkDeleteModal && (
        <div className="fw-overlay" onClick={() => setConfirmBulkDeleteModal(false)}>
          <div className="fw-modal" onClick={e => e.stopPropagation()} dir="rtl">
            <div className="fw-modal-header" style={{ borderBottom: '1px solid rgba(255,77,106,0.3)' }}>
              <h3 style={{ margin: 0, fontWeight: 800, color: 'var(--danger)', display: 'flex', alignItems: 'center', gap: 8 }}>
                <AlertTriangle size={18} /> تأكيد الحذف الجماعي
              </h3>
              <button className="fw-icon-btn" onClick={() => setConfirmBulkDeleteModal(false)}><X size={16} /></button>
            </div>
            <div className="fw-modal-body">
              <p style={{ margin: 0, fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
                هل أنت متأكد من رغبتك في حذف <strong style={{ color: 'var(--danger)' }}>{selectedRuleIds.length}</strong> قاعدة بشكل نهائي من محرك الجدار الناري؟
              </p>
              <div style={{ display: 'flex', justifyContent: 'flex-start', gap: 12, marginTop: 20 }}>
                <button
                  type="button"
                  className="fw-btn-primary"
                  style={{ background: 'var(--danger)', color: '#fff' }}
                  onClick={onBulkDelete}
                  disabled={isSaving}
                >
                  {isSaving ? 'جاري الحذف...' : 'حذف القواعد المحددة'}
                </button>
                <button type="button" className="fw-btn-ghost" onClick={() => setConfirmBulkDeleteModal(false)}>إلغاء</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
