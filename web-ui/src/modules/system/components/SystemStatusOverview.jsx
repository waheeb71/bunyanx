import React from 'react';
import { Cpu, Server, HardDrive, RefreshCw, CheckCircle, AlertTriangle } from 'lucide-react';

function uptime(s) {
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  return `${d}ي ${h}س ${m}د`;
}

function GaugeBar({ value, color }) {
  const clampedVal = Math.min(Math.max(value || 0, 0), 100);
  return (
    <div className="sys-gauge-track">
      <div
        className="sys-gauge-fill"
        style={{ width: `${clampedVal}%`, background: color }}
      />
    </div>
  );
}

export default function SystemStatusOverview({ status, onOpenOta, onSyncHa, isSyncingHa }) {
  const cpu = typeof status?.cpu_usage === 'number' ? status.cpu_usage : 0;
  const ram = typeof status?.memory_usage === 'number' ? status.memory_usage : 0;

  return (
    <div className="sys-overview-container">
      {/* Resource Usage Card */}
      <div className="sys-card">
        <div className="sys-card-header">
          <Cpu size={18} className="text-accent" />
          <span>استهلاك الموارد وحالة النظام</span>
        </div>

        <div className="sys-card-body">
          <div className="sys-gauge-group">
            <div className="sys-gauge-header">
              <span className="sys-gauge-label">المعالج (CPU)</span>
              <span className="sys-gauge-val text-accent">{cpu.toFixed(1)}%</span>
            </div>
            <GaugeBar value={cpu} color="var(--accent, #00d4ff)" />
          </div>

          <div className="sys-gauge-group" style={{ marginTop: '1rem' }}>
            <div className="sys-gauge-header">
              <span className="sys-gauge-label">الذاكرة (RAM)</span>
              <span className="sys-gauge-val text-warning">{ram.toFixed(1)}%</span>
            </div>
            <GaugeBar value={ram} color="var(--warning, #ffc107)" />
          </div>

          <div className="sys-info-grid">
            <div className="sys-info-tile">
              <span className="sys-tile-label">وقت التشغيل</span>
              <span className="sys-tile-val mono">{uptime(status?.uptime_seconds || 0)}</span>
            </div>
            <div className="sys-info-tile">
              <span className="sys-tile-label">التوافرية العالية (HA)</span>
              <span className="sys-tile-val badge-ha">{status?.ha_state || 'MASTER'}</span>
            </div>
            <div className="sys-info-tile">
              <span className="sys-tile-label">الاتصالات النشطة</span>
              <span className="sys-tile-val mono">
                {(status?.active_connections || 0).toLocaleString()}
              </span>
            </div>
            <div className="sys-info-tile">
              <span className="sys-tile-label">نماذج الذكاء الاصطناعي</span>
              <span className="sys-tile-val">
                {status?.ml_models_loaded ? (
                  <span className="text-success" style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                    <CheckCircle size={14} /> محملة
                  </span>
                ) : (
                  <span className="text-muted" style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                    <AlertTriangle size={14} /> غير متاحة
                  </span>
                )}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Control Actions (OTA & HA Sync) */}
      <div className="sys-card-row">
        <div className="sys-card">
          <div className="sys-card-header">
            <HardDrive size={18} className="text-info" />
            <span>التحديث الهوائي (OTA)</span>
          </div>
          <div className="sys-card-body">
            <p className="sys-card-desc">
              التحقق من الإصدارات المتاحة على مستودع Platform Core وتطبيق التحديث التلقائي.
            </p>
            <div className="sys-btn-row">
              <button className="sys-btn sys-btn-secondary" onClick={onOpenOta}>
                <RefreshCw size={14} /> البحث عن تحديثات
              </button>
            </div>
          </div>
        </div>

        <div className="sys-card">
          <div className="sys-card-header">
            <Server size={18} className="text-success" />
            <span>مزامنة التوافرية العالية (HA)</span>
          </div>
          <div className="sys-card-body">
            <p className="sys-card-desc">
              مزامنة فورية للجلسات النشطة وقواعد البيانات التزامنية عبر العقد المتصلة.
            </p>
            <div className="sys-btn-row">
              <button
                className="sys-btn sys-btn-primary"
                onClick={onSyncHa}
                disabled={isSyncingHa}
              >
                <RefreshCw size={14} className={isSyncingHa ? 'sys-spin' : ''} />
                {isSyncingHa ? 'جاري المزامنة...' : 'فرض المزامنة الآن'}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
