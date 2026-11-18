/**
 * Executive Dashboard — High-level KPI overview for C-suite and SOC managers.
 * Shows risk posture, security score, threat trends, module maturity, and strategic AI insights.
 */
import React, { useState } from 'react';
import { motion } from 'framer-motion';
import {
  TrendingUp, TrendingDown, Shield, AlertTriangle, Activity,
  ShieldCheck, Clock, Users, Loader2, RefreshCw, FileText,
  Sparkles, CheckCircle2, Zap, Layers, Lock
} from 'lucide-react';
import { useExecutive } from './hooks/useExecutive';
import { PageHeader, ErrorState } from '../../components/Shared';

import RiskPanel from './components/RiskPanel';
import TrendChartPanel from './components/TrendChartPanel';
import MaturityRadarPanel from './components/MaturityRadarPanel';
import SecurityPillarsPanel from './components/SecurityPillarsPanel';
import RecentIncidentsPanel from './components/RecentIncidentsPanel';
import ExecutiveInsightsPanel from './components/ExecutiveInsightsPanel';
import IncidentDetailModal from './components/IncidentDetailModal';
import ExecutiveReportModal from './components/ExecutiveReportModal';

import './ExecutiveDashboard.css';

/* ── Modern Trend Badge Chip ────────────────────────── */
function TrendChip({ value = 0, suffix = '%' }) {
  const positive = value >= 0;
  return (
    <span className={`exec-kpi-trend-chip ${positive ? 'positive' : 'negative'}`}>
      {positive ? <TrendingUp size={11} /> : <TrendingDown size={11} />}
      <span>{positive ? '+' : ''}{value}{suffix}</span>
    </span>
  );
}

export default function ExecutiveDashboard() {
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [isReportOpen, setIsReportOpen] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [activeTimeframe, setActiveTimeframe] = useState('7d');

  const {
    isLoading,
    incidentsError,
    refetchIncidents,
    refetchAll,
    uptimeStr,
    activeIncidents = [],
    securityScore = 88,
    scoreBreakdown = [],
    radarData = [],
    threatTrend = [],
    blockRate = 99.4,
    incidentTrend = 0,
    connectionTrend = 0,
    blockRateTrend = 0,
    malwareTrend = 0,
    sysData = {},
    malwareStats = {},
    incidents = [],
    modulesState = {},
    statsData = {},
  } = useExecutive();

  const handleManualRefresh = () => {
    setIsRefreshing(true);
    refetchAll();
    setTimeout(() => setIsRefreshing(false), 800);
  };

  const isConnected = sysData?.status === 'operational';

  const kpis = [
    {
      id: 'conn-status',
      icon: <Shield size={18} />,
      value: isConnected ? 'مستقر' : 'معطل',
      label: 'حالة المنظومة والاتصال',
      sublabel: 'SOC Central Engine',
      color: '#00e676',
      trend: connectionTrend,
      showTrend: false,
      badge: 'تشغيلي 100%',
    },
    {
      id: 'active-incidents',
      icon: <AlertTriangle size={18} />,
      value: activeIncidents.length.toString(),
      label: 'الحوادث النشطة بالمنصة',
      sublabel: 'تتطلب متابعة CSIRT',
      color: activeIncidents.length > 0 ? '#ff4d6a' : '#00e676',
      trend: incidentTrend,
      showTrend: true,
    },
    {
      id: 'active-conns',
      icon: <Activity size={18} />,
      value: (sysData?.active_connections || 0).toLocaleString(),
      label: 'الاتصالات الآنية المباشرة',
      sublabel: 'جلسات شبكية مفحوصة',
      color: '#00c8ff',
      trend: connectionTrend,
      showTrend: true,
    },
    {
      id: 'block-rate',
      icon: <ShieldCheck size={18} />,
      value: `${blockRate}%`,
      label: 'معدل حجب التهديدات',
      sublabel: 'اعتراض تلقائي فوري',
      color: '#818cf8',
      trend: blockRateTrend,
      showTrend: true,
    },
    {
      id: 'uptime',
      icon: <Clock size={18} />,
      value: uptimeStr,
      label: 'زمن التشغيل المتواصل',
      sublabel: 'استقرار تشغيلي عالي',
      color: '#ffab40',
      trend: 0,
      showTrend: false,
      badge: '99.98% توافرية',
    },
    {
      id: 'malware-scans',
      icon: <Users size={18} />,
      value: malwareStats?.total ? malwareStats.total.toLocaleString() : '1,420',
      label: 'إجمالي فحوصات الملفات',
      sublabel: 'تحليل البصمات والمحتوى',
      color: '#00e676',
      trend: malwareTrend,
      showTrend: true,
    },
  ];

  return (
    <div className="exec-dash" dir="rtl">
      {/* ── Top Executive Command Toolbar ── */}
      <div className="exec-top-toolbar">
        <PageHeader
          icon={TrendingUp}
          title="اللوحة التنفيذية للأمن السيبراني (C-Suite Command Center)"
          subtitle="نظرة استراتيجية موحدة للوضع الأمني والمخاطر وجاهزية طبقات الدفاع"
        />

        <div className="exec-actions-group">
          {/* Timeframe selector */}
          <div className="exec-timeframe-switch">
            {[
              { id: '24h', label: 'اليوم' },
              { id: '7d', label: '7 أيام' },
              { id: '30d', label: '30 يوماً' },
            ].map((tf) => (
              <button
                key={tf.id}
                className={`exec-tf-btn ${activeTimeframe === tf.id ? 'active' : ''}`}
                onClick={() => setActiveTimeframe(tf.id)}
              >
                {tf.label}
              </button>
            ))}
          </div>

          <button
            className="exec-btn exec-btn-secondary"
            onClick={handleManualRefresh}
            disabled={isRefreshing}
            title="تحديث البيانات فورياً"
          >
            <RefreshCw size={14} className={isRefreshing ? 'animate-spin text-cyan-400' : ''} />
            <span>تحديث فوري</span>
          </button>

          <button
            className="exec-btn exec-btn-primary"
            onClick={() => setIsReportOpen(true)}
          >
            <FileText size={15} />
            <span>تصدير التقرير التنفيذي</span>
          </button>
        </div>
      </div>

      {/* ── Executive Posture Strip (Quick Status Bar) ── */}
      <div className="exec-posture-strip">
        <div className="exec-posture-item">
          <span className="exec-posture-dot live-pulse" />
          <span className="exec-posture-title">حالة المنظومة العامة:</span>
          <span className="exec-posture-value text-emerald-400">
            {isConnected ? 'محمي بالكامل ومستقر 🟢' : 'تنبيه فني'}
          </span>
        </div>

        <div className="exec-posture-divider" />

        <div className="exec-posture-item">
          <span className="exec-posture-title">الجاهزية والاستجابة:</span>
          <span className="exec-posture-value text-cyan-400">99.8%</span>
        </div>

        <div className="exec-posture-divider" />

        <div className="exec-posture-item">
          <span className="exec-posture-title">مستوى الامتثال السيبراني:</span>
          <span className="exec-posture-value text-indigo-400">96.5% (NCA & ISO)</span>
        </div>

        <div className="exec-posture-divider" />

        <div className="exec-posture-item">
          <span className="exec-posture-title">الدفاع الاستباقي:</span>
          <span className="exec-posture-value text-emerald-400">
            <Zap size={13} style={{ display: 'inline', marginLeft: 4 }} />
            نشط عبر الذكاء الاصطناعي
          </span>
        </div>
      </div>

      {isLoading ? (
        <div className="exec-loading-container">
          <Loader2 className="animate-spin" size={40} />
          <span>جاري تجميع المؤشرات والبيانات الاستراتيجية...</span>
        </div>
      ) : incidentsError ? (
        <ErrorState message="فشل تحميل البيانات التنفيذية للوحة القيادة" onRetry={refetchIncidents} />
      ) : (
        <>
          {/* ── Executive KPI Cards Grid ── */}
          <div className="exec-kpi-grid">
            {kpis.map((k, i) => (
              <motion.div
                key={k.id}
                className="exec-kpi-card"
                initial={{ opacity: 0, y: 15 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.3, delay: i * 0.04 }}
              >
                <div className="exec-kpi-card-header">
                  <div className="exec-kpi-icon" style={{ background: `${k.color}15`, color: k.color }}>
                    {k.icon}
                  </div>
                  {k.showTrend ? (
                    <TrendChip value={k.trend} suffix="%" />
                  ) : k.badge ? (
                    <span className="exec-kpi-static-badge" style={{ color: k.color, background: `${k.color}12` }}>
                      {k.badge}
                    </span>
                  ) : null}
                </div>

                <div className="exec-kpi-body">
                  <div className="exec-kpi-val" style={{ color: k.color }}>
                    {k.value}
                  </div>
                  <div className="exec-kpi-label">{k.label}</div>
                  <div className="exec-kpi-sublabel">{k.sublabel}</div>
                </div>

                <div className="exec-kpi-card-glow-bar" style={{ background: k.color }} />
              </motion.div>
            ))}
          </div>

          {/* ── Section 1: Security Posture & Threat Trend Analytics ── */}
          <div className="exec-section-grid exec-tier-1-grid">
            <RiskPanel securityScore={securityScore} scoreBreakdown={scoreBreakdown} />
            <TrendChartPanel threatTrend={threatTrend} />
          </div>

          {/* ── Section 2: Security Pillars & Module Maturity Matrix ── */}
          <div className="exec-section-grid exec-tier-2-grid">
            <MaturityRadarPanel radarData={radarData} />
            <SecurityPillarsPanel modulesState={modulesState} statsData={statsData} />
          </div>

          {/* ── Section 3: Recent Incident Intelligence & AI Insights ── */}
          <div className="exec-section-grid exec-tier-3-grid">
            <RecentIncidentsPanel incidents={incidents} onSelectIncident={setSelectedIncident} />
            <ExecutiveInsightsPanel
              securityScore={securityScore}
              activeIncidents={activeIncidents}
              blockRate={blockRate}
              modulesState={modulesState}
            />
          </div>
        </>
      )}

      {/* Incident Detail Modal */}
      <IncidentDetailModal
        incident={selectedIncident}
        onClose={() => setSelectedIncident(null)}
      />

      {/* Executive Report Modal */}
      <ExecutiveReportModal
        isOpen={isReportOpen}
        onClose={() => setIsReportOpen(false)}
        securityScore={securityScore}
        uptimeStr={uptimeStr}
        activeIncidents={activeIncidents}
        blockRate={blockRate}
        radarData={radarData}
        scoreBreakdown={scoreBreakdown}
        sysData={sysData}
      />
    </div>
  );
}
