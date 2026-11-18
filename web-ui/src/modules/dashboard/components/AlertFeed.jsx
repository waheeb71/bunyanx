import { AlertTriangle, AlertOctagon, Info } from 'lucide-react';

const SEV_META = {
  critical: { dot: 'db-alert-dot--critical', badge: 'db-sev-badge--critical', label: 'حرج',    Icon: AlertOctagon },
  high:     { dot: 'db-alert-dot--high',     badge: 'db-sev-badge--high',     label: 'عالٍ',   Icon: AlertTriangle },
  warning:  { dot: 'db-alert-dot--warning',  badge: 'db-sev-badge--warning',  label: 'تحذير',  Icon: AlertTriangle },
  info:     { dot: 'db-alert-dot--info',     badge: 'db-sev-badge--info',     label: 'معلومة', Icon: Info },
};

export default function AlertFeed({ alertsToShow, alerts, onSelectAlert }) {
  const feedList = alerts || alertsToShow || [];

  if (feedList.length === 0) {
    return (
      <div className="db-empty">
        <AlertTriangle size={28} style={{ opacity: 0.1 }} />
        <span>لا توجد تنبيهات حية — النظام هادئ</span>
      </div>
    );
  }

  return (
    <div className="db-alert-feed db-scroll">
      {feedList.map((alert, idx) => {
        const meta = SEV_META[alert.severity] || SEV_META.info;
        const { Icon } = meta;
        return (
          <div
            key={alert.id || idx}
            className="db-alert-item"
            onClick={() => onSelectAlert?.(alert)}
            style={{ cursor: 'pointer', transition: 'all 0.15s ease' }}
          >
            <span className={`db-alert-dot ${meta.dot}`} />
            <div style={{ flex: 1, minWidth: 0 }}>
              <div className="db-alert-title">{alert.title || alert.category || 'تنبيه أمني'}</div>
              <div className="db-alert-meta">
                {alert.flag ? `${alert.flag} ` : ''}{alert.src || alert.src_ip || '—'} · {alert.time || alert.timestamp}
              </div>
            </div>
            <span className={`db-sev-badge ${meta.badge}`}>
              <Icon size={10} />
              {meta.label}
            </span>
          </div>
        );
      })}
    </div>
  );
}
