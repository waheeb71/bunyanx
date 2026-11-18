import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Server, Settings, Globe, Activity,
  Layers, Zap, ShieldCheck, Network, Shield, CheckCircle, AlertCircle, X, Download, Copy, Check
} from 'lucide-react';
import { useProxy } from './hooks/useProxy';
import { PageHeader, KpiCard, StatusBadge, LiveDot } from '../../components/Shared';

import ConfigPanel from './components/ConfigPanel';
import VipPanel from './components/VipPanel';
import SessionsPanel from './components/SessionsPanel';

import './Proxy.css';

/* ── Mode metadata definitions ──────────────────────────── */
const MODE_META = {
  transparent_proxy: {
    label: 'بروكسي شفاف (Transparent)',
    desc: 'يعترض حركة المرور تلقائياً دون حاجة لتعديل متصفحات العملاء — رائع للشبكات الداخلية.',
    color: 'var(--accent)',
    icon: Layers,
  },
  forward_proxy: {
    label: 'بروكسي توجيه قياسي (Forward)',
    desc: 'يتطلب إعداد المتصفح أو ملف PAC/WPAD للعملاء لتوجيه الطلبات عبر البروكسي.',
    color: 'var(--success)',
    icon: Globe,
  },
  reverse_proxy: {
    label: 'بروكسي عكسي (Reverse)',
    desc: 'يتلقى الطلبات الخارجية وينقلها للخوادم الداخلية — مناسب لتوزيع الحمل والحماية.',
    color: 'var(--warning)',
    icon: Server,
  },
};

export default function Proxy() {
  const [tab, setTab] = useState('config');
  const [toast, setToast] = useState(null);
  const [copiedPac, setCopiedPac] = useState(false);

  const {
    config: cfg, configLoading, vips, vipsLoading, stats, sessions,
    updateConfig, updateConfigPending, addVip, addVipPending, deleteVip,
    pacUrl
  } = useProxy(tab);

  const notify = (notice) => {
    setToast(notice);
    setTimeout(() => {
      setToast(prev => (prev === notice ? null : prev));
    }, 4000);
  };

  const copyPacLink = () => {
    const fullPacUrl = `${window.location.origin}${pacUrl}`;
    navigator.clipboard.writeText(fullPacUrl);
    setCopiedPac(true);
    notify({ type: 'success', message: `تم نسخ رابط ملف الـ PAC تلقائياً: ${fullPacUrl}` });
    setTimeout(() => setCopiedPac(false), 3000);
  };

  const isEnabled = cfg.is_active;
  const modeMeta = MODE_META[cfg.mode] || MODE_META.transparent_proxy;
  const ModeIcon = modeMeta.icon;

  return (
    <div className="module-page">

      {/* ── Toast Notification Banner ──────────────────────── */}
      <AnimatePresence>
        {toast && (
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className={`prx-toast ${toast.type}`}
          >
            {toast.type === 'success' ? <CheckCircle size={18} /> : <AlertCircle size={18} />}
            <span>{toast.message}</span>
            <button onClick={() => setToast(null)} className="prx-toast-close">
              <X size={14} />
            </button>
          </motion.div>
        )}
      </AnimatePresence>

      {/* ── Header ──────────────────────────── */}
      <PageHeader
        icon={Network}
        title="الوكيل الشبكي (Proxy)"
        subtitle="Transparent / Forward / Reverse Proxy · Interception & VIP Mapping · SSL Termination"
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          {cfg.mode === 'forward_proxy' && (
            <button
              onClick={copyPacLink}
              className="prx-btn-pac"
              title="نسخ رابط الإعداد التلقائي PAC / WPAD للعملاء"
            >
              {copiedPac ? <Check size={14} /> : <Copy size={14} />}
              <span>{copiedPac ? 'تم النسخ!' : 'رابط PAC/WPAD'}</span>
            </button>
          )}
          <StatusBadge status={isEnabled ? 'active' : 'disabled'} />
          <LiveDot active={isEnabled} />
        </div>
      </PageHeader>

      {/* ── KPI Cards ───────────────────────── */}
      <div className="kpi-row">
        <KpiCard
          icon={<Zap size={18} />}
          value={cfg.listen_port || '—'}
          label="منفذ الاستماع (Listen Port)"
          color="var(--accent)"
          delay={0}
        />
        <KpiCard
          icon={<Server size={18} />}
          value={cfg.max_connections ? Number(cfg.max_connections).toLocaleString() : '—'}
          label="أقصى اتصالات"
          color="var(--success)"
          delay={0.05}
        />
        <KpiCard
          icon={<ModeIcon size={18} />}
          value={modeMeta.label.split(' ')[0]}
          label="وضع التشغيل الحالي"
          color={modeMeta.color}
          delay={0.1}
        />
        <KpiCard
          icon={<ShieldCheck size={18} />}
          value={cfg.strict_cert_validation ? 'صارم' : 'مرن'}
          label="فحص الشهادات"
          color="var(--warning)"
          delay={0.15}
        />
      </div>

      {/* ── Tabs Navigation ─────────────────────── */}
      <div className="prx-tabs">
        <button
          className={`prx-tab ${tab === 'config' ? 'active' : ''}`}
          onClick={() => setTab('config')}
        >
          <Settings size={15} /> الإعدادات العامة
        </button>
        <button
          className={`prx-tab ${tab === 'vips' ? 'active' : ''}`}
          onClick={() => setTab('vips')}
        >
          <Shield size={15} /> خرائط الـ VIP ({vips?.length ?? 0})
        </button>
        <button
          className={`prx-tab ${tab === 'sessions' ? 'active' : ''}`}
          onClick={() => setTab('sessions')}
        >
          <Activity size={15} /> الجلسات الحية ({stats?.active_connections ?? 0})
        </button>
      </div>

      {/* ── Tab View Content ───────────────────────── */}
      <div className="prx-view-area">
        <AnimatePresence mode="wait">
          <motion.div
            key={tab}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            transition={{ duration: 0.2 }}
          >
            {tab === 'config' && (
              <ConfigPanel
                config={cfg}
                configLoading={configLoading}
                updateConfig={updateConfig}
                updateConfigPending={updateConfigPending}
                modeMeta={MODE_META}
                notify={notify}
              />
            )}

            {tab === 'vips' && (
              <VipPanel
                vips={vips}
                vipsLoading={vipsLoading}
                addVip={addVip}
                addVipPending={addVipPending}
                deleteVip={deleteVip}
                notify={notify}
              />
            )}

            {tab === 'sessions' && (
              <SessionsPanel
                stats={stats}
                sessions={sessions}
              />
            )}
          </motion.div>
        </AnimatePresence>
      </div>

    </div>
  );
}
