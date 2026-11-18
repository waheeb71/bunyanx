import React from 'react';
import { Shield, AlertOctagon, Database } from 'lucide-react';

function CbState({ state }) {
  const map = {
    CLOSED: { label: 'مغلق — سليم', color: '#28c76f', bg: 'rgba(40,199,111,0.08)', border: 'rgba(40,199,111,0.2)' },
    OPEN: { label: 'مفتوح — خطر', color: '#ff5f5f', bg: 'rgba(255,95,95,0.08)', border: 'rgba(255,95,95,0.2)' },
    'HALF-OPEN': { label: 'نصف مفتوح', color: '#ffc107', bg: 'rgba(255,193,7,0.08)', border: 'rgba(255,193,7,0.2)' },
  };
  const m = map[state] || map.CLOSED;
  return (
    <span className="sh-cb-state" style={{ color: m.color, background: m.bg, border: `1px solid ${m.border}` }}>
      {m.label}
    </span>
  );
}

export default function CircuitBreakerGrid({ circuitBreakers = {} }) {
  const cbEntries = Object.entries(circuitBreakers);
  const openCBs = cbEntries.filter(([, cb]) => cb.state === 'OPEN').length;

  return (
    <div className="sh-cb-section">
      <div className="sh-cb-header">
        <Shield size={16} style={{ color: '#ff5f5f' }} />
        <span>قواطع الدائرة — Circuit Breakers</span>
        {openCBs > 0 && (
          <span className="sh-cb-alert">
            <AlertOctagon size={12} /> {openCBs} مفتوح
          </span>
        )}
      </div>

      <div className="sh-cb-grid">
        {cbEntries.map(([mod, cb]) => (
          <div
            key={mod}
            className={`sh-cb-card ${
              cb.state === 'OPEN'
                ? 'sh-cb-card--open'
                : cb.state === 'HALF-OPEN'
                ? 'sh-cb-card--half'
                : 'sh-cb-card--closed'
            }`}
          >
            <div className="sh-cb-mod-name">{mod.replace(/_/g, ' ')}</div>
            <CbState state={cb.state} />
            <div className="sh-cb-stats">
              <div className="sh-cb-stat">
                <span>فشل</span>
                <strong style={{ color: cb.failures > 0 ? '#ff5f5f' : 'rgba(255,255,255,0.6)' }}>
                  {cb.failures}
                </strong>
              </div>
              <div className="sh-cb-stat">
                <span>إعادة التشغيل</span>
                <strong style={{ fontFamily: 'monospace' }}>
                  {cb.reset_timeout_s > 0 ? `${cb.reset_timeout_s}ث` : '—'}
                </strong>
              </div>
            </div>
          </div>
        ))}

        {cbEntries.length === 0 && (
          <div className="sh-cb-empty">
            <Database size={24} style={{ opacity: 0.15 }} />
            <span>لا توجد قواطع دائرة مسجّلة بعد.</span>
          </div>
        )}
      </div>
    </div>
  );
}
