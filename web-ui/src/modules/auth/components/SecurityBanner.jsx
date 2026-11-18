import React from 'react';

export default function SecurityBanner({ sysStats }) {
  return (
    <div className="lp-cyber-strip">
      <div className="lp-cyber-cell">
        <span className="lp-cyber-val" style={{ color: sysStats.status === 'connected' ? '#00ffaa' : '#ff4d6a' }}>
          {sysStats.status === 'connected' ? 'نشط' : 'غير نشط'}
        </span>
        <span className="lp-cyber-lbl">محرك الحماية</span>
      </div>

      <div className="lp-cyber-cell">
        <span className="lp-cyber-val" style={{ color: '#00d4ff' }}>
          {sysStats.tls}
        </span>
        <span className="lp-cyber-lbl">القناة المشفرة</span>
      </div>

      <div className="lp-cyber-cell">
        <span className="lp-cyber-val" style={{ color: '#ffc107' }}>
          {sysStats.build}
        </span>
        <span className="lp-cyber-lbl">الإصدار</span>
      </div>

      <div className="lp-cyber-cell">
        <span className="lp-cyber-val" style={{ color: '#ff6b9d' }}>
          {sysStats.ai_core}
        </span>
        <span className="lp-cyber-lbl">الذكاء الاصطناعي</span>
      </div>
    </div>
  );
}
