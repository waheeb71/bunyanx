import React from 'react';
import {
  Settings, ShieldAlert, BrainCircuit, FileText, RefreshCw, Zap, Activity,
  AlertTriangle, Shield, CheckCircle2, Lock, Sparkles, Layers, Sliders
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

import { PageHeader, StatusBadge, LiveDot } from '../../components/Shared';
import DLPSettings from './DLPSettings';
import DLPRules from './DLPRules';
import DLPMonitor from './DLPMonitor';
import DLPAudit from './DLPAudit';
import { useDLPStore } from './store/dlpStore';
import { useDLP } from './hooks/useDLP';

const TABS = [
  { key: 'monitor', label: 'مراقبة السلوك (BEFP)', icon: BrainCircuit },
  { key: 'rules', label: 'قواعد المطابقة والتسريب', icon: ShieldAlert },
  { key: 'audit', label: 'سجلات التحقيق والتنبيهات', icon: FileText },
  { key: 'settings', label: 'الإعدادات المتقدمة', icon: Settings },
];

export default function DLP() {
  const { activeTab, setActiveTab } = useDLPStore();
  const { status, config, highRiskIps = [], pendingFeedback = [], isFetchingStatus } = useDLP();

  const mergedStatus = {
    ...status,
    is_active: config.is_active,
    befp_enabled: config.befp_enabled,
    deception_enabled: config.deception_enabled,
  };

  const isActive = mergedStatus.is_active;
  const befpActive = mergedStatus.befp_enabled;
  const deceptionActive = mergedStatus.deception_enabled;

  return (
    <div className="module-page" dir="rtl" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* ── Top Header ──────────────────────────────────────── */}
      <PageHeader
        icon={Lock}
        title="منع تسريب البيانات (DLP Engine)"
        subtitle="حماية استباقية ثلاثية الطبقات — مطابقة المحتوى · التحليل السلوكي المتجهي (BEFP) · فخاخ الخداع السببي"
      >
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap', direction: 'ltr' }}>
          {isFetchingStatus && (
            <RefreshCw size={15} style={{ color: '#00c8ff', animation: 'spin 1s linear infinite' }} />
          )}

          {highRiskIps.length > 0 && (
            <span
              className="badge"
              style={{
                padding: '5px 12px',
                fontSize: '0.78rem',
                fontWeight: 800,
                background: 'rgba(255, 77, 106, 0.15)',
                color: '#ff4d6a',
                border: '1px solid rgba(255, 77, 106, 0.3)',
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
              }}
            >
              <AlertTriangle size={13} />
              {highRiskIps.length} عنوان عالي الخطورة
            </span>
          )}

          {pendingFeedback.length > 0 && (
            <span
              style={{
                padding: '5px 12px',
                fontSize: '0.78rem',
                fontWeight: 700,
                background: 'rgba(129, 140, 248, 0.15)',
                color: '#818cf8',
                border: '1px solid rgba(129, 140, 248, 0.3)',
                borderRadius: 'var(--radius-full)',
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
              }}
            >
              <Sparkles size={13} /> {pendingFeedback.length} تقييم بانتظار المراجعة
            </span>
          )}

          {befpActive && (
            <span
              style={{
                padding: '5px 12px',
                fontSize: '0.78rem',
                fontWeight: 700,
                background: 'rgba(0, 200, 255, 0.12)',
                color: '#00c8ff',
                border: '1px solid rgba(0, 200, 255, 0.3)',
                borderRadius: 'var(--radius-full)',
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
              }}
            >
              <BrainCircuit size={13} /> التحليل السلوكي نشط (AI ON)
            </span>
          )}

          {deceptionActive && (
            <span
              style={{
                padding: '5px 12px',
                fontSize: '0.78rem',
                fontWeight: 700,
                background: 'rgba(255, 171, 64, 0.12)',
                color: '#ffab40',
                border: '1px solid rgba(255, 171, 64, 0.3)',
                borderRadius: 'var(--radius-full)',
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
              }}
            >
              <Zap size={13} /> الخداع الاستباقي نشط
            </span>
          )}

          <StatusBadge status={isActive ? 'active' : 'disabled'} />
          <LiveDot active={isActive} />
        </div>
      </PageHeader>

      {/* ── High-Impact 4-Column Metric Ribbon ──────────────── */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
          gap: 14,
        }}
      >
        <div
          className="card"
          style={{
            position: 'relative',
            padding: '16px 18px',
            background: 'rgba(10, 14, 26, 0.75)',
            border: '1px solid rgba(0, 200, 255, 0.15)',
            borderRadius: 'var(--radius-lg)',
            overflow: 'hidden',
          }}
        >
          <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: isActive ? '#00e676' : '#ff4d6a' }} />
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.74rem', color: 'var(--text-secondary)' }}>حالة محرك DLP المركزي</span>
            <Shield size={16} style={{ color: isActive ? '#00e676' : '#ff4d6a' }} />
          </div>
          <div style={{ fontSize: '1.3rem', fontWeight: 800, color: isActive ? '#00e676' : '#ff4d6a', marginTop: 4 }}>
            {isActive ? 'نشط ومحمي 🟢' : 'معطل 🔴'}
          </div>
        </div>

        <div
          className="card"
          style={{
            position: 'relative',
            padding: '16px 18px',
            background: 'rgba(10, 14, 26, 0.75)',
            border: '1px solid rgba(0, 200, 255, 0.15)',
            borderRadius: 'var(--radius-lg)',
            overflow: 'hidden',
          }}
        >
          <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: highRiskIps.length > 0 ? '#ff4d6a' : '#00e676' }} />
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.74rem', color: 'var(--text-secondary)' }}>العناوين عالية الخطورة (24h)</span>
            <AlertTriangle size={16} style={{ color: highRiskIps.length > 0 ? '#ff4d6a' : '#00e676' }} />
          </div>
          <div style={{ fontSize: '1.3rem', fontWeight: 800, color: highRiskIps.length > 0 ? '#ff4d6a' : '#00e676', marginTop: 4, fontFamily: 'JetBrains Mono, monospace' }}>
            {highRiskIps.length} IP
          </div>
        </div>

        <div
          className="card"
          style={{
            position: 'relative',
            padding: '16px 18px',
            background: 'rgba(10, 14, 26, 0.75)',
            border: '1px solid rgba(0, 200, 255, 0.15)',
            borderRadius: 'var(--radius-lg)',
            overflow: 'hidden',
          }}
        >
          <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: '#ffab40' }} />
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.74rem', color: 'var(--text-secondary)' }}>عتبة الحظر السلوكي (Block Threshold)</span>
            <Sliders size={16} style={{ color: '#ffab40' }} />
          </div>
          <div style={{ fontSize: '1.3rem', fontWeight: 800, color: '#ffab40', marginTop: 4, fontFamily: 'JetBrains Mono, monospace' }} dir="ltr">
            {((config.befp_block_threshold ?? 0.80) * 100).toFixed(0)}% ERS
          </div>
        </div>

        <div
          className="card"
          style={{
            position: 'relative',
            padding: '16px 18px',
            background: 'rgba(10, 14, 26, 0.75)',
            border: '1px solid rgba(0, 200, 255, 0.15)',
            borderRadius: 'var(--radius-lg)',
            overflow: 'hidden',
          }}
        >
          <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: deceptionActive ? '#00c8ff' : 'rgba(255,255,255,0.2)' }} />
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.74rem', color: 'var(--text-secondary)' }}>فخاخ الخداع السببي</span>
            <Zap size={16} style={{ color: deceptionActive ? '#00c8ff' : 'var(--text-muted)' }} />
          </div>
          <div style={{ fontSize: '1.3rem', fontWeight: 800, color: deceptionActive ? '#00c8ff' : 'var(--text-muted)', marginTop: 4 }}>
            {deceptionActive ? 'حقن وهمي نشط' : 'غير مفعّل'}
          </div>
        </div>
      </div>

      {/* ── Tab Switcher Bar ─────────────────────────────────── */}
      <div
        style={{
          display: 'flex',
          gap: 6,
          background: 'rgba(10, 14, 26, 0.7)',
          border: '1px solid rgba(0, 200, 255, 0.15)',
          borderRadius: 'var(--radius-md)',
          padding: 4,
          width: 'fit-content',
        }}
      >
        {TABS.map((t) => {
          const Icon = t.icon;
          const isCurrent = activeTab === t.key;
          return (
            <button
              key={t.key}
              onClick={() => setActiveTab(t.key)}
              className="btn"
              style={{
                background: isCurrent ? 'rgba(0, 200, 255, 0.18)' : 'transparent',
                color: isCurrent ? '#00c8ff' : 'var(--text-secondary)',
                borderColor: isCurrent ? 'rgba(0, 200, 255, 0.35)' : 'transparent',
                display: 'inline-flex',
                alignItems: 'center',
                gap: 8,
                fontSize: '0.82rem',
                fontWeight: isCurrent ? 700 : 500,
                padding: '8px 16px',
                borderRadius: '8px',
                boxShadow: isCurrent ? '0 0 12px rgba(0, 200, 255, 0.2)' : 'none',
              }}
            >
              <Icon size={16} /> {t.label}
            </button>
          );
        })}
      </div>

      {/* ── Tab Content Area ─────────────────────────────────── */}
      <AnimatePresence mode="wait">
        <motion.div
          key={activeTab}
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -8 }}
          transition={{ duration: 0.2 }}
        >
          {activeTab === 'monitor' && <DLPMonitor />}
          {activeTab === 'rules' && <DLPRules />}
          {activeTab === 'audit' && <DLPAudit />}
          {activeTab === 'settings' && (
            <div style={{ maxWidth: 840, margin: '0 auto' }}>
              <DLPSettings />
            </div>
          )}
        </motion.div>
      </AnimatePresence>
    </div>
  );
}
