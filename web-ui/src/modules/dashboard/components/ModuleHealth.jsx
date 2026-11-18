import { Shield, ShieldCheck, ShieldOff, AlertOctagon } from 'lucide-react';

const MODULE_INFO = {
  waf:   { name: 'WAF (حماية الويب)',              color: '#7c8cf8' },
  ids:   { name: 'IDS/IPS (كشف التسلل)',         color: '#ff5f5f' },
  dlp:   { name: 'DLP (تسريب البيانات)',         color: '#c084fc' },
  wf:    { name: 'Web Filter (فلترة الويب)',     color: '#f97316' },
  mal:   { name: 'Malware AV (مكافحة الفيروسات)',  color: '#ff9f43' },
  dns:   { name: 'DNS Security (أمان DNS)',       color: '#00b4d8' },
  email: { name: 'Email Security (أمان البريد)',   color: '#e879f9' },
  ssl:   { name: 'SSL/TLS Inspection (فحص التشفير)', color: '#38bdf8' },
  fw:    { name: 'Firewall (جدار الحماية)',         color: '#22c55e' },
  uba:   { name: 'UBA AI (تحليل السلوك)',          color: '#a855f7' },
  proxy: { name: 'Proxy (الوكيل)',                color: '#06b6d4' },
  vpn:   { name: 'VPN Engine (الشبكة الافتراضية)',  color: '#10b981' },
};

export function getModuleHealthList(mods) {
  if (!mods) return Object.entries(MODULE_INFO).map(([key, meta]) => ({ key, ...meta, enabled: true, errors: 0 }));

  const altKeys = {
    ids: 'ids_ips',
    wf: 'web_filter',
    mal: 'malware_av',
    dns: 'dns_security',
    email: 'email_security',
    ssl: 'ssl_inspection',
    fw: 'firewall',
  };

  return Object.entries(MODULE_INFO).map(([key, meta]) => {
    const data = mods[key] || (altKeys[key] ? mods[altKeys[key]] : null);
    if (!data) {
      return { key, ...meta, enabled: true, errors: 0 };
    }

    let enabled = true;

    // 1. Explicit Disable Checks (إذا تم تعطيل الوحدة في الإعدادات)
    if (
      data.enabled === false ||
      data.active === false ||
      data.running === false ||
      data.is_active === false ||
      data.waf_enabled === false ||
      data.status === 'disabled' ||
      data.status === 'inactive' ||
      data.status === 'off' ||
      data.status === 'stopped' ||
      data.mode === 'disabled' ||
      data.mode === 'off'
    ) {
      enabled = false;
    }
    // 2. Explicit Enable Checks
    else if (
      data.enabled === true ||
      data.active === true ||
      data.running === true ||
      data.is_active === true ||
      data.waf_enabled === true ||
      data.ready === true ||
      data.healthy === true ||
      ['active', 'operational', 'running', 'success', 'ok'].includes(data.status) ||
      ['enforce', 'blocking', 'monitoring', 'full_auto', 'active'].includes(data.mode)
    ) {
      enabled = true;
    }
    // 3. Fallback for general module presence
    else if (data.module || data.version || data.service || data.advanced_config) {
      enabled = true;
    }

    const errors = data?.errors ?? data?.error_count ?? 0;
    return { key, ...meta, enabled, errors };
  });
}

export default function ModuleHealthGrid({ modulesHealth }) {
  const healthList = Array.isArray(modulesHealth) && modulesHealth.length > 0
    ? modulesHealth
    : getModuleHealthList(null);

  return (
    <div className="db-panel" style={{ height: '100%', marginBottom: 0, display: 'flex', flexDirection: 'column' }}>
      <div className="db-panel-header" style={{ flexShrink: 0 }}>
        <div className="db-panel-title">
          <Shield size={16} /> صحة وحدات الفحص
        </div>
        <span style={{ fontSize: '0.7rem', color: 'rgba(255,255,255,0.4)', fontWeight: 700 }}>
          {healthList.filter(m => m.enabled).length}/{healthList.length} نشط
        </span>
      </div>
      <div className="db-mod-grid" style={{ flex: 1, overflowY: 'auto', padding: '10px 16px', display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(130px, 1fr))', gap: 8 }}>
        {healthList.map(m => (
          <div
            key={m.key}
            className={`db-mod-card ${m.enabled ? (m.errors > 0 ? 'db-mod-card--err' : 'db-mod-card--ok') : 'db-mod-card--off'}`}
            style={{ padding: '8px 10px', borderRadius: 6 }}
          >
            <div className="db-mod-name" style={{ color: m.enabled ? m.color : '#64748b', fontSize: '0.78rem', fontWeight: 700 }}>{m.name}</div>
            <div className="db-mod-status" style={{ color: m.enabled ? (m.errors > 0 ? '#ff5f5f' : '#28c76f') : 'rgba(255,255,255,0.25)', fontSize: '0.72rem', marginTop: 4 }}>
              {m.enabled
                ? m.errors > 0
                  ? <><AlertOctagon size={11} /> {m.errors} أخطاء</>
                  : <><ShieldCheck size={11} /> نشط</>
                : <><ShieldOff size={11} /> معطّل</>
              }
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
