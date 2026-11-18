import { Mail, Search, Shield, AlertTriangle, MailX, Activity, Check, CheckCircle2, ShieldCheck } from 'lucide-react';

const MODE_LABELS = { enforce: 'ENFORCE', monitor: 'MONITOR', learning: 'LEARNING' };

export default function EmailHeader({ status, stats = {}, config = {} }) {
  const isEnabled = config.enabled !== false;
  const mode = config.mode || 'enforce';

  const kpis = [
    { label: 'تم فحصه اليوم', value: stats.today_total ?? 0, color: '#00c8ff', icon: Search },
    { label: 'رسائل تصيّد (Phishing)', value: stats.phishing_detected ?? 0, color: '#ff4d6a', icon: AlertTriangle },
    { label: 'بريد مزعج (Spam)', value: stats.spam_detected ?? 0, color: '#ffab40', icon: MailX },
    { label: 'تم حظره اليوم', value: stats.today_blocked ?? 0, color: '#ff4d6a', icon: Shield },
  ];

  return (
    <>
      {/* ── Hero Bar ── */}
      <div className="em-hero">
        <div className="em-hero-glow" />
        <div className="em-hero-inner">
          <div className="em-hero-left">
            <div className="em-hero-icon">
              <Mail size={26} style={{ color: '#00c8ff' }} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                <h1 className="em-hero-title">منظومة أمان البريد الإلكتروني (Email Security Gateway)</h1>
                <span className="em-live-indicator" title="مزامنة فورية حية نشطة">
                  <span className="em-live-dot" />
                  مباشر LIVE
                </span>
              </div>
              <p className="em-hero-sub">
                خط أنابيب AI سُباعي الطبقات · فحص التوثيق (SPF / DKIM / DMARC) · كشف التصيد و Spam
              </p>
            </div>
          </div>

          <div className="em-hero-right">
            {/* Domain Auth Protocol Mini Indicators */}
            <div style={{ display: 'flex', gap: 6, alignItems: 'center', background: 'rgba(255, 255, 255, 0.03)', padding: '4px 10px', borderRadius: 8, border: '1px solid rgba(255, 255, 255, 0.06)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: '0.68rem', color: '#00e676', fontWeight: 800 }}>
                <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#00e676', boxShadow: '0 0 6px #00e676' }} />
                SPF
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: '0.68rem', color: '#00e676', fontWeight: 800 }}>
                <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#00e676', boxShadow: '0 0 6px #00e676' }} />
                DKIM
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: '0.68rem', color: '#00e676', fontWeight: 800 }}>
                <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#00e676', boxShadow: '0 0 6px #00e676' }} />
                DMARC
              </div>
            </div>

            <span className={`em-mode-badge em-mode-badge--${mode}`}>
              {MODE_LABELS[mode] || mode.toUpperCase()}
            </span>
            <span className={`em-active-badge ${isEnabled ? 'em-active-badge--on' : 'em-active-badge--off'}`}>
              {isEnabled ? '● نشط' : '○ معطل'}
            </span>
          </div>
        </div>
      </div>

      {/* ── KPI Strip ── */}
      <div className="em-kpi-strip">
        {kpis.map(({ label, value, color, icon: Icon }) => (
          <div key={label} className="em-kpi-card" style={{ '--ec': color }}>
            <div className="em-kpi-icon" style={{ background: `${color}15`, border: `1px solid ${color}30` }}>
              <Icon size={18} style={{ color }} />
            </div>
            <div>
              <div className="em-kpi-val" style={{ color, fontFamily: 'JetBrains Mono, monospace' }}>
                {value.toLocaleString('ar-SA')}
              </div>
              <div className="em-kpi-lbl">{label}</div>
            </div>
          </div>
        ))}
      </div>
    </>
  );
}
