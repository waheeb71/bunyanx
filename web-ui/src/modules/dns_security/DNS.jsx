/**
 * bunyanx — DNS Security Module
 * تمت إعادة تصميمه باستخدام المكونات المشتركة (Shared Components).
 */
import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Globe2, Shield, Zap, Settings, Network, Activity, CheckCircle, AlertTriangle, RefreshCw, Radio, Percent } from 'lucide-react';
import { useDNS } from './hooks/useDNS';
import { PageHeader, KpiCard, StatusBadge, LiveDot } from '../../components/Shared';
import DNSStatsView from './components/DNSStatsView';
import DNSLiveQueriesView from './components/DNSLiveQueriesView';
import DNSDartAlertsView from './components/DNSDartAlertsView';
import DNSRulesView from './components/DNSRulesView';
import DNSSteeringView from './components/DNSSteeringView';
import DNSSettingsView from './components/DNSSettingsView';
import './DNS.css';

const TABS = [
  { key: 'stats', label: 'الإحصائيات والتحليلات', icon: Activity },
  { key: 'queries', label: 'سجل الاستعلامات الحية', icon: Radio },
  { key: 'dart_alerts', label: 'تحليلات DART AI', icon: Zap },
  { key: 'rules', label: 'قواعد الفلترة', icon: Shield },
  { key: 'steering', label: 'توجيه النطاقات', icon: Globe2 },
  { key: 'settings', label: 'الإعدادات', icon: Settings },
];

export default function DNS() {
  const [tab, setTab] = useState(() => {
    return sessionStorage.getItem('dns_security_tab') || 'stats';
  });

  const handleTabChange = (key) => {
    setTab(key);
    sessionStorage.setItem('dns_security_tab', key);
  };

  const {
    config, stats, rules, dartAlerts, steeringRules, queries, isFetching, refetchAll,
    updateConfig, createRule, updateRule, deleteRule,
    reviewAlert, flagFalsePositive, createSteering, deleteSteering, syncThreatIntel,
    clearQueries
  } = useDNS();

  const enginesOn = [
    config.enable_dga_detection,
    config.enable_tunneling_detection,
    config.enable_threat_intel,
    config.enable_rate_limiting,
    config.enable_tld_blocking,
    config.enable_dart_detection,
  ].filter(Boolean).length;

  return (
    <div className="module-page">

      {/* ── Header ──────────────────────────── */}
      <PageHeader
        icon={Network}
        title="أمان النطاقات (DNS Security)"
        subtitle="تصفية DNS · كشف DGA · ذكاء التهديدات · Sinkhole · سجل الاستعلامات الفوري"
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <StatusBadge status={config.is_active ? 'active' : 'disabled'} />
          <LiveDot active={config.is_active} />
          <button
            className="dns-btn-primary"
            style={{ padding: '6px 12px', fontSize: '0.8rem', background: 'var(--bg-hover)', color: 'var(--text-primary)', border: '1px solid var(--border)' }}
            onClick={refetchAll}
            title="تحديث البيانات الفوري"
          >
            <RefreshCw size={14} className={isFetching ? 'spin' : ''} />
            تحديث
          </button>
        </div>
      </PageHeader>

      {/* ── KPI Cards ───────────────────────── */}
      <div className="kpi-row">
        <KpiCard
          icon={<Activity size={18} />}
          value={(stats.total_queries || stats.total_rules || 0).toLocaleString()}
          label="إجمالي الاستعلامات"
          color="var(--accent)"
          delay={0}
        />
        <KpiCard
          icon={<AlertTriangle size={18} />}
          value={(stats.blocked_count || 0).toLocaleString()}
          label="التهديدات المحجوبة"
          color="var(--danger)"
          delay={0.05}
        />
        <KpiCard
          icon={<Percent size={18} />}
          value={`${stats.block_rate || 0}%`}
          label="معدل الحظر"
          color="var(--success)"
          delay={0.1}
        />
        <KpiCard
          icon={<Zap size={18} />}
          value={`${enginesOn} / 6`}
          label="المحركات النشطة"
          color="var(--warning)"
          delay={0.15}
        />
      </div>

      {/* ── Custom Tabs ─────────────────────── */}
      <div className="dns-tabs">
        {TABS.map(({ key, label, icon: Icon }) => (
          <button
            key={key}
            className={`dns-tab ${tab === key ? 'active' : ''}`}
            onClick={() => handleTabChange(key)}
          >
            <Icon size={15} /> {label}
            {key === 'queries' && queries.length > 0 && (
              <span className="tab-badge" style={{ background: 'var(--accent)' }}>{queries.length}</span>
            )}
            {key === 'dart_alerts' && dartAlerts.filter(a => !a.reviewed).length > 0 && (
              <span className="tab-badge">{dartAlerts.filter(a => !a.reviewed).length}</span>
            )}
          </button>
        ))}
      </div>

      {/* ── View Area ───────────────────────── */}
      <div className="dns-view-area">
        <AnimatePresence mode="wait">
          <motion.div
            key={tab}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            transition={{ duration: 0.2 }}
          >
            {tab === 'stats' && <DNSStatsView stats={stats} />}
            {tab === 'queries' && (
              <DNSLiveQueriesView
                queries={queries}
                clearQueries={clearQueries}
              />
            )}
            {tab === 'dart_alerts' && (
              <DNSDartAlertsView
                alerts={dartAlerts}
                reviewAlert={reviewAlert}
                flagFalsePositive={flagFalsePositive}
              />
            )}
            {tab === 'rules' && (
              <DNSRulesView
                rules={rules}
                createRule={createRule}
                updateRule={updateRule}
                deleteRule={deleteRule}
              />
            )}
            {tab === 'steering' && (
              <DNSSteeringView
                rules={steeringRules}
                createSteering={createSteering}
                deleteSteering={deleteSteering}
              />
            )}
            {tab === 'settings' && (
              <DNSSettingsView
                config={config}
                updateConfig={updateConfig}
                syncThreatIntel={syncThreatIntel}
              />
            )}
          </motion.div>
        </AnimatePresence>
      </div>

    </div>
  );
}

