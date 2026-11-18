import React from 'react';
import { useSystemHealth } from './hooks/useSystemHealth';
import SecurityDiagnosticsCard from './components/SecurityDiagnosticsCard';
import CircuitBreakerGrid from './components/CircuitBreakerGrid';
import {
  Activity, Cpu, Server, RefreshCw, Wifi,
  CheckCircle2, AlertOctagon, AlertTriangle, Clock, Zap, Lock, ShieldCheck
} from 'lucide-react';
import './SystemHealth.css';
import './System.css';

/* ── Helpers ── */
function StatusDot({ ok, pulse }) {
  return (
    <span className={`sh-dot ${ok ? 'sh-dot--green' : 'sh-dot--amber'} ${pulse ? 'sh-dot--pulse' : ''}`} />
  );
}

function StatRow({ label, value, mono, color }) {
  return (
    <div className="sh-stat-row">
      <span className="sh-stat-label">{label}</span>
      <span
        className="sh-stat-value"
        style={{ color: color || undefined, fontFamily: mono ? 'Fira Code, monospace' : undefined }}
        dir={mono ? 'ltr' : undefined}
      >
        {value}
      </span>
    </div>
  );
}

function SectionCard({ icon: Icon, title, iconColor, children, accent }) {
  return (
    <div className="sh-card" style={accent ? { borderColor: accent, '--sh-accent': accent } : {}}>
      <div className="sh-card-header">
        <div className="sh-card-icon" style={{ background: `${iconColor}15`, border: `1px solid ${iconColor}25` }}>
          <Icon size={17} style={{ color: iconColor }} />
        </div>
        <span className="sh-card-title">{title}</span>
      </div>
      <div className="sh-card-body">{children}</div>
    </div>
  );
}

function CorePill({ core, role }) {
  const isData = role === 'data_plane';
  return (
    <span
      className="sh-core-pill"
      style={isData ? { background: 'rgba(255,193,7,0.1)', color: '#ffc107', border: '1px solid rgba(255,193,7,0.25)' } : {}}
      dir="ltr"
    >
      CPU {core}
    </span>
  );
}

export default function SystemHealth() {
  const {
    health,
    isHealthLoading,
    isHealthError,
    healthError,
    securityValidation,
    securityWarnings,
    isSecurityLoading,
  } = useSystemHealth();

  if (isHealthLoading && !health) {
    return (
      <div className="sh-root sh-loading" dir="rtl">
        <RefreshCw size={22} className="sh-spin" />
        <span>جاري تحميل صحة النظام...</span>
      </div>
    );
  }

  if (isHealthError && !health) {
    return (
      <div className="sh-root sh-error" dir="rtl">
        <AlertOctagon size={22} />
        <span>{healthError?.message || 'فشل في جلب تفاصيل صحة النظام.'}</span>
      </div>
    );
  }

  const h = health || {};
  const cbEntries = Object.entries(h.circuit_breakers || {});
  const openCBs = cbEntries.filter(([, cb]) => cb.state === 'OPEN').length;
  const lastTickStr = new Date().toLocaleTimeString('ar-SA');

  return (
    <div className="sh-root" dir="rtl">
      {/* ── Hero ── */}
      <div className="sh-hero">
        <div className="sh-hero-glow" />
        <div className="sh-hero-content">
          <div className="sh-hero-left">
            <div className="sh-hero-icon">
              <Activity size={26} style={{ color: '#a78bfa' }} />
            </div>
            <div>
              <h1 className="sh-hero-title">مركز صحة النظام — System Health</h1>
              <p className="sh-hero-sub">مراقبة وتشخيص مستوى التحكم المؤسسي — Control Plane</p>
            </div>
          </div>
          <div className="sh-hero-meta">
            <div className="sh-live-badge">
              <StatusDot ok pulse />
              <span>بث حي</span>
            </div>
            <div className="sh-last-tick">
              <Clock size={12} />
              {lastTickStr}
            </div>
          </div>
        </div>
      </div>

      {/* ── Quick KPIs ── */}
      <div className="sh-kpi-row">
        {[
          { label: 'eBPF نشط', value: h.ebpf_active ? 'نشط' : 'معطل', color: h.ebpf_active ? '#28c76f' : '#ffc107', icon: Zap },
          { label: 'mTLS الداخلي', value: h.mtls_active ? 'مُفعّل' : 'معطل', color: h.mtls_active ? '#28c76f' : '#ff5f5f', icon: Lock },
          {
            label: 'سلامة الأمان',
            value: isSecurityLoading ? '…' : securityValidation?.all_secure ? 'آمن' : 'ضعيف',
            color: isSecurityLoading ? '#ffc107' : securityValidation?.all_secure ? '#28c76f' : '#ffc107',
            icon: ShieldCheck,
          },
          { label: 'قواطع مفتوحة', value: openCBs, color: openCBs > 0 ? '#ff5f5f' : '#28c76f', icon: AlertOctagon },
          { label: 'نوى المعالج', value: h.affinity?.total_logical_cores || '—', color: '#00d4ff', icon: Cpu },
        ].map((k) => {
          const Icon = k.icon;
          return (
            <div className="sh-kpi" key={k.label}>
              <div className="sh-kpi-icon">
                <Icon size={17} style={{ color: k.color }} />
              </div>
              <div>
                <div className="sh-kpi-val" style={{ color: k.color }}>
                  {k.value}
                </div>
                <div className="sh-kpi-label">{k.label}</div>
              </div>
            </div>
          );
        })}
      </div>

      {/* ── Cards Grid ── */}
      <div className="sh-grid">
        {/* HA cluster */}
        <SectionCard icon={Wifi} title="مجموعة التوافرية العالية (HA)" iconColor="#a78bfa" accent="rgba(167,139,250,0.2)">
          <div
            className="sh-ha-role"
            style={{
              background: h.ha?.is_leader ? 'rgba(167,139,250,0.08)' : 'rgba(255,255,255,0.03)',
              borderColor: h.ha?.is_leader ? 'rgba(167,139,250,0.25)' : 'rgba(255,255,255,0.07)',
            }}
          >
            <span className="sh-ha-label">دور العقدة الحالية</span>
            <span className="sh-ha-value" style={{ color: h.ha?.is_leader ? '#a78bfa' : 'rgba(255,255,255,0.5)' }}>
              {h.ha?.is_leader ? '★ أساسي — MASTER' : h.ha?.enabled ? 'احتياطي — BACKUP' : 'مستقل — STANDALONE'}
            </span>
          </div>
          <StatRow
            label="مزامنة الحالة (etcd)"
            value={h.state_sync?.etcd_connected ? 'متصل' : 'محلي فقط'}
            color={h.state_sync?.etcd_connected ? '#28c76f' : '#ffc107'}
          />
          <StatRow label="المفاتيح المحلية" value={h.state_sync?.local_keys || 0} mono />
        </SectionCard>

        {/* CPU Affinity */}
        <SectionCard icon={Cpu} title="التقارب الجوهري للمعالج (CPU Affinity)" iconColor="#ffc107">
          <div className="sh-cpu-summary">
            <span>{h.affinity?.total_logical_cores || 0} نواة منطقية</span>
            {h.affinity?.pinned ? (
              <span className="sh-cpu-pinned">
                <CheckCircle2 size={12} /> نوى مثبتة
              </span>
            ) : (
              <span className="sh-cpu-unpinned">
                <AlertTriangle size={12} /> تثبيت معطل
              </span>
            )}
          </div>
          {h.affinity?.roles &&
            Object.entries(h.affinity.roles).map(([role, cores]) => (
              <div key={role} className="sh-cpu-role-group">
                <div className="sh-cpu-role-label">
                  {role.replace(/_/g, ' ')}
                  <span className="sh-cpu-role-count">{cores.length} نوى</span>
                </div>
                <div className="sh-cpu-cores">
                  {cores.map((c) => (
                    <CorePill key={c} core={c} role={role} />
                  ))}
                </div>
              </div>
            ))}
          {!h.affinity?.pinned && (
            <div className="sh-warn-note">
              <AlertTriangle size={13} /> تثبيت النوى معطل حالياً.
            </div>
          )}
        </SectionCard>

        {/* Platform Status */}
        <SectionCard icon={Server} title="حالة المنصة المحورية" iconColor="#00d4ff">
          <StatRow
            label="تسريع eBPF / XDP"
            value={h.ebpf_active ? 'نشط' : 'غير نشط'}
            color={h.ebpf_active ? '#28c76f' : '#ff5f5f'}
          />
          <StatRow
            label="تشفير mTLS الداخلي"
            value={h.mtls_active ? 'مُفعَّل' : 'مُعطَّل'}
            color={h.mtls_active ? '#28c76f' : '#ff5f5f'}
          />
          <StatRow
            label="صندوق WASM"
            value={h.wasm_active ? 'جاهز' : 'غير نشط'}
            color={h.wasm_active ? '#28c76f' : '#ffc107'}
          />
          <StatRow
            label="وقت النظام"
            value={h.timestamp ? new Date(h.timestamp * 1000).toLocaleTimeString('ar-SA') : '—'}
            mono
          />
        </SectionCard>

        {/* Security Diagnostics */}
        <SecurityDiagnosticsCard
          validation={securityValidation}
          warnings={securityWarnings}
          isLoading={isSecurityLoading}
        />
      </div>

      {/* ── Circuit Breakers Grid ── */}
      <CircuitBreakerGrid circuitBreakers={h.circuit_breakers || {}} />
    </div>
  );
}
