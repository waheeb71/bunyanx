import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ShieldCheck, Activity, Shield, Cpu, Eye, Lock, Settings, UploadCloud } from 'lucide-react';
import { useWAF } from './hooks/useWAF';
import { OverviewPanel } from './components/OverviewPanel';
import { WaapShieldsPanel } from './components/WaapShieldsPanel';
import { GnnTrainingPanel } from './components/GnnTrainingPanel';
import { AutopilotPanel } from './components/AutopilotPanel';
import { AccessControlPanel } from './components/AccessControlPanel';
import { SettingsPanel } from './components/SettingsPanel';
import { SchemaUploadModal } from './components/SchemaUploadModal';
import {
  PageHeader, SectionCard, StatusBadge, LiveDot, SkeletonLines
} from '../../components/Shared';
import './WAF.css';

export default function WAF() {
  const [tab, setTab] = useState('overview');
  const [isSchemaModalOpen, setIsSchemaModalOpen] = useState(false);

  const waf = useWAF();

  const activeFeatures = Object.values(waf.status?.features || {}).filter(Boolean).length;
  const isEnabled = waf.status?.waf_enabled;

  return (
    <div className="module-page">
      {/* ── Header ──────────────────────────── */}
      <PageHeader
        icon={ShieldCheck}
        title="محرك WAAP المؤسسي"
        subtitle="حماية تطبيقات الويب وAPI بـ 10 طبقات ذكاء اصطناعي ونماذج عصبيّة"
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <button
            className="btn btn-ghost"
            onClick={() => setIsSchemaModalOpen(true)}
            style={{ border: '1px solid var(--border)', background: 'var(--bg-raised)', fontSize: '0.85rem' }}
          >
            <UploadCloud size={14} style={{ color: 'var(--accent)' }} /> رفع مخطط API
          </button>
          
          <div className="badge" style={{ background: 'var(--bg-raised)', border: '1px solid var(--border)' }}>
            <span style={{ fontWeight: 800, color: 'var(--accent)', marginLeft: 4 }}>{activeFeatures} / 12</span> وحدة نشطة
          </div>
          <StatusBadge status={isEnabled ? 'active' : 'disabled'} />
          <LiveDot active={isEnabled} />
        </div>
      </PageHeader>

      {/* ── Custom Tabs ─────────────────────── */}
      <div className="waf-tabs" style={{ flexWrap: 'wrap' }}>
        {[
          { id: 'overview', label: 'المراقبة والتهديدات', icon: Activity },
          { id: 'waap', label: 'طبقات دفاع WAAP', icon: Shield },
          { id: 'gnn', label: 'محرك GNN والتدريب', icon: Cpu },
          { id: 'autopilot', label: 'الطيار الآلي', icon: Eye },
          { id: 'access', label: 'الوصول والقوائم', icon: Lock },
          { id: 'settings', label: 'الإعدادات المتقدمة', icon: Settings },
        ].map(t => {
          const Icon = t.icon;
          return (
            <button
              key={t.id}
              className={`waf-tab ${tab === t.id ? 'active' : ''}`}
              onClick={() => setTab(t.id)}
            >
              <Icon size={15} /> {t.label}
            </button>
          );
        })}
      </div>

      {/* ── View Area ───────────────────────── */}
      <div className="waf-view-area">
        {waf.statusLoading && tab === 'overview' ? (
          <SectionCard><SkeletonLines count={6} /></SectionCard>
        ) : (
          <AnimatePresence mode="wait">
            <motion.div
              key={tab}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -6 }}
              transition={{ duration: 0.2 }}
            >
              {tab === 'overview' && (
                <OverviewPanel
                  status={waf.status}
                  activeFeatures={activeFeatures}
                  events={waf.events}
                  eventsLoading={waf.eventsLoading}
                  onSimulateAttack={waf.simulateAttack}
                  isSimulating={waf.simulatingAttack}
                />
              )}
              {tab === 'waap' && (
                <WaapShieldsPanel
                  status={waf.status}
                  handleToggle={waf.toggleFeature}
                  handleGnnToggle={waf.toggleGnn}
                />
              )}
              {tab === 'gnn' && (
                <GnnTrainingPanel
                  gnnStatus={waf.gnnStatus}
                  gnnStatusLoading={waf.gnnStatusLoading}
                  gnnLogs={waf.gnnLogs}
                  gnnLogsLoading={waf.gnnLogsLoading}
                  trainingStatus={waf.trainingStatus}
                  flushSessionLogs={waf.flushSessionLogs}
                  flushingLogs={waf.flushingLogs}
                  startGnnTraining={waf.startGnnTraining}
                  startingTraining={waf.startingTraining}
                  activateGnnModel={waf.activateGnnModel}
                  activatingModel={waf.activatingModel}
                />
              )}
              {tab === 'autopilot' && (
                <AutopilotPanel
                  apStatus={waf.shadowStatus}
                  startShadowMode={waf.startShadowMode}
                  stopShadowMode={waf.stopShadowMode}
                  exportShadowSchema={waf.exportShadowSchema}
                  isLearning={waf.status?.features?.shadow_mode}
                  startingShadowMode={waf.startingShadowMode}
                  stoppingShadowMode={waf.stoppingShadowMode}
                  exportingShadowSchema={waf.exportingShadowSchema}
                />
              )}
              {tab === 'access' && (
                <AccessControlPanel
                  settings={waf.settings}
                  mutators={waf}
                  clearIpSession={waf.clearIpSession}
                />
              )}
              {tab === 'settings' && (
                <SettingsPanel 
                  settings={waf.settings}
                  loading={waf.settingsLoading}
                  mutators={waf}
                  onOpenSchemaModal={() => setIsSchemaModalOpen(true)}
                />
              )}
            </motion.div>
          </AnimatePresence>
        )}
      </div>

      {/* ── OpenAPI Schema Upload Modal ──────── */}
      <SchemaUploadModal
        isOpen={isSchemaModalOpen}
        onClose={() => setIsSchemaModalOpen(false)}
        onUpload={waf.uploadApiSchema}
      />

    </div>
  );
}
