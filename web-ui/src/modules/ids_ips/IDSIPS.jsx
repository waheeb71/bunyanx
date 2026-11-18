/**
 * bunyanx — IDS/IPS Module
 * Enterprise IDS/IPS Control Panel & Threat Monitor
 */
import { motion, AnimatePresence } from 'framer-motion';
import { Activity, Shield, Settings2, AlertTriangle, AlertOctagon, CheckCircle2, XCircle } from 'lucide-react';
import { useIDSIPS } from './hooks/useIDSIPS';
import { PageHeader, KpiCard, StatusBadge, LiveDot } from '../../components/Shared';
import AlertsView from './components/AlertsView';
import RulesView from './components/RulesView';
import SettingsView from './components/SettingsView';
import './IDSIPS.css';

export default function IDSIPS() {
  const {
    tab,
    setTab,
    hours,
    setHours,
    idsStats,
    alerts,
    alertsLoading,
    refetchAlerts,
    cfg,
    phantomStatus,
    phantomDrift,
    traps,
    rules,
    rulesLoading,
    critical,
    warning,
    isBlocking,
    notification,
    notify,
    blockMutation,
    feedbackMutation,
    updateConfig,
    createRule,
    deleteRule,
  } = useIDSIPS();

  return (
    <div className="module-page">

      {/* ── Notification Banner Toast ─────────────────── */}
      <AnimatePresence>
        {notification && (
          <motion.div
            initial={{ opacity: 0, y: -12 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -12 }}
            className={`ids-toast ids-toast-${notification.type}`}
          >
            {notification.type === 'success' ? (
              <CheckCircle2 size={16} style={{ color: 'var(--success)' }} />
            ) : (
              <XCircle size={16} style={{ color: 'var(--danger)' }} />
            )}
            <span>{notification.message}</span>
          </motion.div>
        )}
      </AnimatePresence>

      {/* ── Header ──────────────────────────── */}
      <PageHeader
        icon={Shield}
        title="نظام كشف ومنع التطفل (IDS / IPS)"
        subtitle="مطابقة التوقيعات · كشف سلوكي بالذكاء الاصطناعي (PHANTOM) · استجابة نشطة eBPF"
      >
        <div className="ids-mode-chip" data-mode={cfg.mode}>
          <span className="ids-mode-dot" />
          {isBlocking ? 'IPS — حجب نشط' : 'IDS — مراقبة فقط'}
        </div>
        <StatusBadge status={cfg.is_active ? 'active' : 'disabled'} />
        <LiveDot active={cfg.is_active} />
      </PageHeader>

      {/* ── KPI Cards ───────────────────────── */}
      <div className="kpi-row">
        <KpiCard
          icon={<AlertOctagon size={18} />}
          value={idsStats?.critical ?? critical}
          label="تنبيهات حرجة"
          color="var(--danger)"
          delay={0}
        />
        <KpiCard
          icon={<AlertTriangle size={18} />}
          value={idsStats?.high ?? warning}
          label="تهديدات عالية"
          color="var(--warning)"
          delay={0.05}
        />
        <KpiCard
          icon={<Activity size={18} />}
          value={idsStats?.total ?? alerts.length}
          label="إجمالي الأحداث"
          color="var(--accent)"
          delay={0.1}
        />
        <KpiCard
          icon={<Shield size={18} />}
          value={idsStats?.blocked ?? 0}
          label="تم حجبه"
          color="var(--danger)"
          delay={0.12}
        />
      </div>

      {/* ── Custom Tabs ─────────────────────── */}
      <div className="ids-tabs">
        {[
          { id: 'alerts', label: 'الأحداث الحية والتنبيهات', icon: Activity },
          { id: 'rules', label: 'توقيعات IPS (Snort Rules)', icon: Shield },
          { id: 'settings', label: 'إعداد محرك PHANTOM', icon: Settings2 },
        ].map(t => {
          const Icon = t.icon;
          return (
            <button
              key={t.id}
              className={`ids-tab ${tab === t.id ? 'active' : ''}`}
              onClick={() => setTab(t.id)}
            >
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
          {tab === 'alerts' && (
            <AlertsView
              alerts={alerts}
              alertsLoading={alertsLoading}
              refetchAlerts={refetchAlerts}
              cfg={cfg}
              hours={hours}
              setHours={setHours}
              blockMutation={blockMutation}
              feedbackMutation={feedbackMutation}
              notify={notify}
            />
          )}
          {tab === 'rules' && (
            <RulesView
              rules={rules}
              rulesLoading={rulesLoading}
              createRule={createRule}
              deleteRule={deleteRule}
              notify={notify}
            />
          )}
          {tab === 'settings' && (
            <SettingsView
              cfg={cfg}
              phantomStatus={phantomStatus}
              phantomDrift={phantomDrift}
              traps={traps}
              updateConfig={updateConfig}
              notify={notify}
            />
          )}
        </motion.div>
      </AnimatePresence>

    </div>
  );
}

