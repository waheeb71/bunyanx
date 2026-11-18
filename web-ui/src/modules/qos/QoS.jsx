import { useState, useEffect } from 'react';
import { AnimatePresence } from 'framer-motion';
import { Gauge, Activity, Users, Zap, AlertTriangle, Heart } from 'lucide-react';
import { useQoS } from './hooks/useQoS';
import { QoSStats } from './components/QoSStats';
import { QoSConfig } from './components/QoSConfig';
import { QoSBuckets } from './components/QoSBuckets';
import {
  PageHeader, KpiCard, SectionCard, EmptyState, LiveDot, StatusBadge
} from '../../components/Shared';
import './QoS.css';

/* ── helpers ──────────────────────────────────────────── */
function fmtBytes(b) {
  if (b == null) return '—';
  if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB/s';
  if (b >= 1e3) return (b / 1e3).toFixed(0) + ' KB/s';
  return b + ' B/s';
}
function fmtBits(bps) {
  if (bps == null) return '—';
  if (bps >= 1e9) return (bps / 1e9).toFixed(1) + ' Gbps';
  if (bps >= 1e6) return (bps / 1e6).toFixed(0) + ' Mbps';
  if (bps >= 1e3) return (bps / 1e3).toFixed(0) + ' Kbps';
  return bps + ' bps';
}

export default function QoS() {
  const [search, setSearch] = useState('');
  const [editMode, setEditMode] = useState(false);
  const [formData, setFormData] = useState({
    enabled: false,
    mode: 'monitor',
    default_user_rate_bytes: 1250000,
    default_user_burst_bytes: 2500000,
    global_rate_bytes: 0,
    traffic_classes: [],
    enable_ebpf_tc: true,
    enable_app_priority_boost: true,
  });

  const {
    status,
    statusLoading,
    config,
    configLoading,
    stats,
    statsLoading,
    resetBucket,
    resettingBucket,
    updateConfig,
    updatingConfig
  } = useQoS();

  // Sync formData with loaded config
  useEffect(() => {
    if (config && Object.keys(config).length > 0) {
      setFormData({
        enabled: config.enabled ?? false,
        mode: config.mode || 'monitor',
        default_user_rate_bytes: config.default_user_rate_bytes || 1250000,
        default_user_burst_bytes: config.default_user_burst_bytes || 2500000,
        global_rate_bytes: config.global_rate_bytes || 0,
        traffic_classes: config.traffic_classes || [],
        enable_ebpf_tc: config.enable_ebpf_tc ?? true,
        enable_app_priority_boost: config.enable_app_priority_boost ?? true,
      });
    }
  }, [config]);

  const handleInputChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : (name === 'mode' ? value : parseInt(value, 10) || 0)
    }));
  };

  const handleSave = (e) => {
    e.preventDefault();
    updateConfig(formData).then(() => {
      setEditMode(false);
    });
  };

  const handleCancel = () => {
    if (config) {
      setFormData({
        enabled: config.enabled ?? false,
        mode: config.mode || 'monitor',
        default_user_rate_bytes: config.default_user_rate_bytes || 1250000,
        default_user_burst_bytes: config.default_user_burst_bytes || 2500000,
        global_rate_bytes: config.global_rate_bytes || 0,
        traffic_classes: config.traffic_classes || [],
        enable_ebpf_tc: config.enable_ebpf_tc ?? true,
        enable_app_priority_boost: config.enable_app_priority_boost ?? true,
      });
    }
    setEditMode(false);
  };

  const buckets = stats?.buckets || [];
  const isEnabled = status?.enabled;
  const topUtilization = buckets.length > 0
    ? Math.max(...buckets.map(b => b.utilization_pct || 0))
    : 0;

  const criticalBuckets = buckets.filter(b => b.utilization_pct >= 80);

  return (
    <div className="module-page">

      {/* ── Header ──────────────────────────── */}
      <PageHeader
        icon={Gauge}
        title="جودة الخدمة (QoS)"
        subtitle="إدارة وتنظيم النطاق الترددي — Token Bucket لكل IP"
      >
        <StatusBadge status={isEnabled ? 'active' : 'disabled'} />
        <LiveDot active={isEnabled} />
      </PageHeader>

      {/* ── KPI Cards ───────────────────────── */}
      <div className="kpi-row">
        <KpiCard
          icon={<Activity size={18} />}
          value={statusLoading ? '...' : (isEnabled ? 'مُفعّل' : 'مُعطّل')}
          label="حالة المحرك"
          color={isEnabled ? 'var(--success)' : 'var(--text-muted)'}
          delay={0}
        />
        <KpiCard
          icon={<Users size={18} />}
          value={statusLoading ? '...' : (status?.active_buckets ?? 0)}
          label="عملاء نشطون"
          color="var(--accent)"
          delay={0.05}
        />
        <KpiCard
          icon={<Zap size={18} />}
          value={status ? fmtBits(status.rate_limit_bps) : '...'}
          label="معدل لكل IP"
          color="var(--info)"
          delay={0.1}
        />
        <KpiCard
          icon={<Heart size={18} />}
          value={statusLoading ? '...' : (status?.gc_thread_alive ? 'نشط (مستقر)' : 'متوقف 🔴')}
          label="خيط جمع القمامة (GC)"
          color={status?.gc_thread_alive ? 'var(--success)' : 'var(--danger)'}
          delay={0.15}
        />
      </div>

      {/* ── Chart + Config Form ─────────────── */}
      <div className="content-grid">
        <QoSStats
          topUtilization={topUtilization}
          activeBuckets={status?.active_buckets ?? buckets.length}
          criticalCount={criticalBuckets.length}
        />
        <QoSConfig
          config={config}
          configLoading={configLoading}
          editMode={editMode}
          setEditMode={setEditMode}
          formData={formData}
          setFormData={setFormData}
          handleInputChange={handleInputChange}
          handleSave={handleSave}
          handleCancel={handleCancel}
          updatingConfig={updatingConfig}
          fmtBytes={fmtBytes}
          fmtBits={fmtBits}
        />
      </div>

      {/* ── Logs & Alerts Section ────────────────── */}
      <div className="content-grid" style={{ marginTop: 'var(--sp-6)' }}>
        {/* Live Alerts Widget */}
        <SectionCard title="إنذارات تجاوز الحدود (Bandwidth Spikes)" icon={AlertTriangle}>
          {criticalBuckets.length === 0 ? (
            <EmptyState message="جميع العملاء ضمن النطاق الترددي المسموح، لا توجد اختناقات حالية" />
          ) : (
            <div className="qos-log-panel">
              {criticalBuckets.map((b, idx) => (
                <div key={idx} className="qos-log-item warning">
                  <AlertTriangle size={14} style={{ marginTop: 2 }} />
                  <span>
                    <strong>تنبيه:</strong> العميل <span className="mono" style={{ color: 'var(--info)' }}>{b.ip}</span> قارب على تجاوز السعة القصوى المحددة (نسبة الاستهلاك {b.utilization_pct}% - المتبقي {b.tokens_remaining} رموز).
                  </span>
                </div>
              ))}
            </div>
          )}
        </SectionCard>
      </div>

      {/* ── Buckets Table ───────────────────── */}
      <div style={{ marginTop: 'var(--sp-6)' }}>
        <QoSBuckets
          buckets={buckets}
          search={search}
          setSearch={setSearch}
          statsLoading={statsLoading}
          resetBucket={resetBucket}
          resettingBucket={resettingBucket}
          fmtBits={fmtBits}
          fmtBytes={fmtBytes}
        />
      </div>
    </div>
  );
}

