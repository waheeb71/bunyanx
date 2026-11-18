import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Globe, ShieldAlert, Settings, Activity, Plus, Search, Trash2, CheckCircle2, XCircle, RefreshCw,
  Download, ChevronRight, ChevronLeft, Filter, AlertTriangle
} from 'lucide-react';
import { useWebFilter } from './hooks/useWebFilter';
import { ActionBadge, ACTION_META } from './components/ActionBadge';
import { CategoryCard } from './components/CategoryCard';
import { LogsPanel } from './components/LogsPanel';
import { SettingsPanel } from './components/SettingsPanel';
import { CategoryThreatChart } from './components/CategoryThreatChart';
import { CategoryModal } from './components/CategoryModal';
import { DomainModal } from './components/DomainModal';
import './WebFilter.css';

export default function WebFilter() {
  const [tab, setTab] = useState('categories');
  const [searchCat, setSearchCat] = useState('');
  const [searchDom, setSearchDom] = useState('');
  const [domActionFilter, setDomActionFilter] = useState('ALL');
  
  // Modals
  const [isCatModalOpen, setIsCatModalOpen] = useState(false);
  const [isDomModalOpen, setIsDomModalOpen] = useState(false);
  const [confirmDeleteId, setConfirmDeleteId] = useState(null); // { id, type: 'domain'|'cat' }

  // Pagination for Domains
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 12;

  const {
    status,
    statusLoading,
    categories,
    categoriesLoading,
    domains,
    domainsLoading,
    config,
    configLoading,
    logs,
    logsLoading,
    refetchLogs,
    liveStreamPaused,
    setLiveStreamPaused,
    toast,

    addDomain,
    addingDomain,
    deleteDomain,
    addCategory,
    addingCategory,
    deleteCategory,
    updateCategory,
    updateConfig,
    trainModel,
    trainingModel
  } = useWebFilter();

  /* ── Handlers ── */
  const handleAddDomainSubmit = async (data) => {
    await addDomain(data);
    setIsDomModalOpen(false);
  };

  const handleAddCategorySubmit = async (data) => {
    await addCategory(data);
    setIsCatModalOpen(false);
  };

  const handleExportDomains = () => {
    const csvContent = "data:text/csv;charset=utf-8," 
      + ["ID,Domain Pattern,Category,Action", ...domains.map(d => `${d.id},"${d.domain_pattern}","${d.category_name || ''}",${d.action}`)].join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `web_filter_domain_overrides_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  /* ── Derived Data ── */
  const filteredCats = categories.filter(c => c.name.toLowerCase().includes(searchCat.toLowerCase()));
  const filteredDoms = domains.filter(d => {
    const matchesSearch = d.domain_pattern.toLowerCase().includes(searchDom.toLowerCase()) || (d.category_name || '').toLowerCase().includes(searchDom.toLowerCase());
    const matchesAction = domActionFilter === 'ALL' || d.action === domActionFilter;
    return matchesSearch && matchesAction;
  });

  const totalPages = Math.ceil(filteredDoms.length / pageSize) || 1;
  const paginatedDoms = filteredDoms.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  const isActive = status?.status === 'active';
  const isEnforce = status?.mode === 'enforce';

  const TABS = [
    { id: 'categories', label: 'قاعدة التصنيفات',  icon: ShieldAlert },
    { id: 'logs',       label: 'المراقبة الحية',    icon: Activity    },
    { id: 'domains',    label: 'تجاوز النطاقات',   icon: Globe       },
    { id: 'settings',   label: 'الإعدادات العامة',  icon: Settings    },
  ];

  return (
    <div className="wf-root" dir="rtl">

      {/* ── Toast Notifications ── */}
      <AnimatePresence>
        {toast && (
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className={`wf-toast wf-toast--${toast.type}`}
            style={{
              position: 'fixed',
              top: '24px',
              left: '50%',
              transform: 'translateX(-50%)',
              zIndex: 9999,
              padding: '12px 24px',
              borderRadius: '10px',
              background: toast.type === 'error' ? '#991b1b' : '#15803d',
              color: '#fff',
              fontWeight: 700,
              boxShadow: '0 8px 30px rgba(0,0,0,0.5)',
              border: '1px solid rgba(255,255,255,0.2)',
              fontSize: '13px',
              display: 'flex',
              alignItems: 'center',
              gap: '8px'
            }}
          >
            {toast.type === 'error' ? <AlertTriangle size={16} /> : <CheckCircle2 size={16} />}
            {toast.msg}
          </motion.div>
        )}
      </AnimatePresence>

      {/* ── Hero ── */}
      <div className="wf-hero">
        <div className="wf-hero-glow" />
        <div className="wf-hero-inner">
          <div className="wf-hero-left">
            <div className="wf-hero-icon">
              <Globe size={26} style={{ color: '#f97316' }} />
            </div>
            <div>
              <h1 className="wf-hero-title">محرك تصفية الويب الحيوية (Enterprise Web Filter)</h1>
              <p className="wf-hero-sub">HoloFilter HDC AI · Dual-Layer URL Categorization · Zero-Trust Policy · SafeSearch</p>
            </div>
          </div>

          <div className="wf-hero-kpis">
            {/* Engine status */}
            <div className="wf-hero-kpi">
              <div className={`wf-status-badge ${isActive ? 'wf-status-badge--on' : 'wf-status-badge--off'}`}>
                {isActive ? <CheckCircle2 size={14} /> : <XCircle size={14} />}
                {isActive ? 'نشط (ACTIVE)' : 'متوقف (INACTIVE)'}
              </div>
              <div className="wf-kpi-lbl">حالة المحرك</div>
            </div>

            {/* Mode */}
            <div className="wf-hero-kpi">
              <div className={`wf-mode-badge ${isEnforce ? 'wf-mode-badge--enforce' : 'wf-mode-badge--monitor'}`}>
                {isEnforce ? 'ENFORCE (حظر)' : 'MONITOR (مراقبة)'}
              </div>
              <div className="wf-kpi-lbl">وضع التطبيق</div>
            </div>

            {/* Counts */}
            <div className="wf-count-chips">
              <div className="wf-count-chip" style={{ '--cc': '#f97316' }}>
                <span className="wf-count-val" style={{ color: '#f97316' }}>{categories.length}</span>
                <span className="wf-count-lbl">تصنيف</span>
              </div>
              <div className="wf-count-chip" style={{ '--cc': '#60a5fa' }}>
                <span className="wf-count-val" style={{ color: '#60a5fa' }}>{domains.length}</span>
                <span className="wf-count-lbl">تجاوز</span>
              </div>
              <div className="wf-count-chip" style={{ '--cc': '#ff5f5f' }}>
                <span className="wf-count-val" style={{ color: '#ff5f5f' }}>
                  {categories.filter(c => c.action === 'BLOCK').length}
                </span>
                <span className="wf-count-lbl">تصنيف محجوب</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ── Visual Analytics (SOC Charts) ── */}
      <CategoryThreatChart categories={categories} domains={domains} />

      {/* ── Tab bar ── */}
      <div className="wf-tab-row">
        <div className="wf-tabs">
          {TABS.map(t => {
            const Icon = t.icon;
            return (
              <button
                key={t.id}
                className={`wf-tab ${tab === t.id ? 'wf-tab--active' : ''}`}
                onClick={() => setTab(t.id)}
              >
                <Icon size={14} /> {t.label}
              </button>
            );
          })}
        </div>

        {/* Tab actions */}
        {tab === 'categories' && (
          <button className="wf-btn wf-btn--primary wf-btn--sm" onClick={() => setIsCatModalOpen(true)}>
            <Plus size={13} /> إضافة تصنيف مخصص
          </button>
        )}
        {tab === 'domains' && (
          <div style={{ display: 'flex', gap: '8px' }}>
            <button className="wf-btn wf-btn--secondary wf-btn--sm" onClick={handleExportDomains}>
              <Download size={13} /> تصدير CSV
            </button>
            <button className="wf-btn wf-btn--primary wf-btn--sm" onClick={() => setIsDomModalOpen(true)}>
              <Plus size={13} /> إضافة قاعدة تجاوز
            </button>
          </div>
        )}
      </div>

      {/* ══ TABS CONTENT ══ */}
      <AnimatePresence mode="wait">

        {/* ══ CATEGORIES ══ */}
        {tab === 'categories' && (
          <motion.div key="cats" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>
            {/* Search toolbar */}
            <div className="wf-toolbar">
              <div className="wf-search-bar">
                <Search size={13} />
                <input
                  className="wf-search"
                  placeholder="بحث في التصنيفات..."
                  value={searchCat}
                  onChange={e => setSearchCat(e.target.value)}
                />
              </div>
              <span className="wf-count-info">
                {filteredCats.length} تصنيف
                · {filteredCats.filter(c => c.action === 'BLOCK').length} محجوب
                · {filteredCats.filter(c => c.action === 'ALLOW').length} مسموح
              </span>
            </div>

            {/* Categories grid */}
            <motion.div className="wf-cat-grid" layout>
              <AnimatePresence>
                {filteredCats.map(cat => (
                  <CategoryCard
                    key={cat.id}
                    cat={cat}
                    onUpdateAction={(id, action) => updateCategory({ id, d: { action } })}
                    onDelete={(id) => setConfirmDeleteId({ id, type: 'cat' })}
                  />
                ))}
              </AnimatePresence>
              {filteredCats.length === 0 && (
                <div className="wf-empty" style={{ gridColumn: '1/-1' }}>
                  <Globe size={28} style={{ opacity: 0.1 }} />
                  <span>لا توجد تصنيفات تطابق بحثك.</span>
                </div>
              )}
            </motion.div>
          </motion.div>
        )}

        {/* ══ LIVE LOGS ══ */}
        {tab === 'logs' && (
          <motion.div key="logs" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>
            <LogsPanel
              logs={logs}
              isLoading={logsLoading}
              liveStreamPaused={liveStreamPaused}
              setLiveStreamPaused={setLiveStreamPaused}
              onRefresh={refetchLogs}
            />
          </motion.div>
        )}

        {/* ══ DOMAINS OVERRIDES ══ */}
        {tab === 'domains' && (
          <motion.div key="doms" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
            style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>

            {/* Domains table panel */}
            <div className="wf-panel">
              <div className="wf-panel-header">
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <div className="wf-search-bar">
                    <Search size={13} />
                    <input
                      className="wf-search"
                      placeholder="بحث في نمط النطاق أو السبب..."
                      value={searchDom}
                      onChange={e => { setSearchDom(e.target.value); setCurrentPage(1); }}
                    />
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                    <Filter size={12} style={{ color: '#aaa', marginLeft: '4px' }} />
                    <select
                      className="wf-select"
                      style={{ padding: '4px 8px', fontSize: '12px' }}
                      value={domActionFilter}
                      onChange={e => { setDomActionFilter(e.target.value); setCurrentPage(1); }}
                    >
                      <option value="ALL">جميع الإجراءات</option>
                      <option value="BLOCK">حظر (BLOCK)</option>
                      <option value="ALLOW">سماح (ALLOW)</option>
                      <option value="MONITOR">مراقبة (MONITOR)</option>
                    </select>
                  </div>
                </div>

                <span className="wf-count-info">{filteredDoms.length} قاعدة استثناء</span>
              </div>

              <div className="wf-table-wrap">
                <table className="wf-table">
                  <thead>
                    <tr>
                      <th>نمط النطاق (Domain Pattern)</th>
                      <th>التصنيف / السبب</th>
                      <th>الإجراء المتخذ (Action)</th>
                      <th style={{ width: 44 }}></th>
                    </tr>
                  </thead>
                  <tbody>
                    {paginatedDoms.length === 0 && (
                      <tr><td colSpan={4}>
                        <div className="wf-empty">
                          <Globe size={26} style={{ opacity: 0.09 }} />
                          <span>لا توجد قواعد تجاوز مجدولة تطابق البحث.</span>
                        </div>
                      </td></tr>
                    )}
                    {paginatedDoms.map(d => (
                      <tr key={d.id} className="wf-row">
                        <td>
                          <span className="wf-mono" dir="ltr" style={{ fontWeight: 700, color: '#f0f0f5' }}>{d.domain_pattern}</span>
                        </td>
                        <td>
                          {d.category_name
                            ? <span className="wf-cat-pill">{d.category_name}</span>
                            : <span className="wf-uncat">غير مصنف</span>}
                        </td>
                        <td><ActionBadge action={d.action} /></td>
                        <td>
                          <button
                            className="wf-del-btn"
                            onClick={() => setConfirmDeleteId({ id: d.id, type: 'domain' })}
                            title="حذف القاعدة"
                          >
                            <Trash2 size={12} />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Pagination controls */}
              {totalPages > 1 && (
                <div style={{ display: 'flex', alignItems: 'center', justifyRight: 'space-between', padding: '12px 18px', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
                  <span className="wf-count-info">الصفحة {currentPage} من {totalPages}</span>
                  <div style={{ display: 'flex', gap: '6px' }}>
                    <button
                      className="wf-btn wf-btn--secondary wf-btn--sm"
                      disabled={currentPage === 1}
                      onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))}
                    >
                      <ChevronRight size={14} /> السابق
                    </button>
                    <button
                      className="wf-btn wf-btn--secondary wf-btn--sm"
                      disabled={currentPage === totalPages}
                      onClick={() => setCurrentPage(prev => Math.min(prev + 1, totalPages))}
                    >
                      التالي <ChevronLeft size={14} />
                    </button>
                  </div>
                </div>
              )}
            </div>
          </motion.div>
        )}

        {/* ══ SETTINGS ══ */}
        {tab === 'settings' && (
          <motion.div key="settings" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>
            <SettingsPanel
              config={config}
              configLoading={configLoading}
              status={status}
              statusLoading={statusLoading}
              updateConfig={updateConfig}
              trainModel={trainModel}
              trainingModel={trainingModel}
            />
          </motion.div>
        )}
      </AnimatePresence>

      {/* ── Modals ── */}
      <CategoryModal
        isOpen={isCatModalOpen}
        onClose={() => setIsCatModalOpen(false)}
        onSubmit={handleAddCategorySubmit}
        isSubmitting={addingCategory}
      />

      <DomainModal
        isOpen={isDomModalOpen}
        onClose={() => setIsDomModalOpen(false)}
        onSubmit={handleAddDomainSubmit}
        isSubmitting={addingDomain}
        categories={categories}
      />

      {/* Confirmation Modal */}
      <AnimatePresence>
        {confirmDeleteId && (
          <div className="wf-modal-overlay">
            <motion.div
              className="wf-modal"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              style={{ maxWidth: '420px' }}
            >
              <div className="wf-modal-header">
                <div className="wf-modal-title" style={{ color: '#ff5f5f' }}>
                  <AlertTriangle size={18} />
                  تأكيد إجراء الحذف
                </div>
              </div>
              <div className="wf-modal-body" style={{ fontSize: '13px', color: '#cbd5e1' }}>
                هل أنت تأكد من رغبتك في حذف هذا العنصر؟ لا يمكن التراجع عن هذا الإجراء بعد تنفيذه.
              </div>
              <div className="wf-modal-footer">
                <button className="wf-btn wf-btn--secondary" onClick={() => setConfirmDeleteId(null)}>
                  إلغاء
                </button>
                <button
                  className="wf-btn"
                  style={{ background: '#dc2626', color: '#fff' }}
                  onClick={async () => {
                    if (confirmDeleteId.type === 'domain') {
                      await deleteDomain(confirmDeleteId.id);
                    } else if (confirmDeleteId.type === 'cat') {
                      await deleteCategory(confirmDeleteId.id);
                    }
                    setConfirmDeleteId(null);
                  }}
                >
                  نعم، تأكيد الحذف
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

    </div>
  );
}
