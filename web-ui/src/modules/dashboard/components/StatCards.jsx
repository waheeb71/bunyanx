import { Shield, Activity, Zap, Clock, TrendingUp, TrendingDown } from 'lucide-react';

const formatUptime = (seconds) => {
  if (seconds === undefined || seconds === null) return null;
  const d = Math.floor(seconds / (3600 * 24));
  const h = Math.floor((seconds % (3600 * 24)) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  
  if (d > 0) return `${d} يوم و ${h} س`;
  if (h > 0) return `${h} س و ${m} د`;
  if (m > 0) return `${m} د و ${s} ث`;
  return `${s} ث`;
};

export const getStatCards = (liveStats, sysStatus) => [
  {
    label: 'معدل النقل الشبكي',
    value: liveStats
      ? `${Math.floor(((liveStats.bytes_per_second || 0) * 8) / 1_000_000)} Mbps`
      : '— Mbps',
    delta: 'مباشر',
    up:    true,
    icon:  Activity,
    clr:   'neon-cyan',
    color: '#00d4ff',
  },
  {
    label: 'معدل الحزم',
    value: liveStats ? `${(liveStats.packets_per_second || 0).toLocaleString()} pps` : '— pps',
    delta: 'مباشر',
    up:    true,
    icon:  Zap,
    clr:   'neon-amber',
    color: '#ffc107',
  },
  {
    label: 'الجلسات النشطة',
    value: (liveStats?.active_connections ?? sysStatus?.active_connections ?? '—').toLocaleString?.() ?? '—',
    delta: 'مباشر+',
    up:    true,
    icon:  Activity,
    clr:   'neon-blue',
    color: '#60a5fa',
  },
  {
    label: 'وقت تشغيل النظام',
    value: formatUptime(sysStatus?.uptime_seconds) || '—',
    delta: 'مستقر',
    up:    true,
    icon:  Clock,
    clr:   'neon-green',
    color: '#28c76f',
  },
];

export default function StatCardsGrid({ statCards }) {
  return (
    <div className="db-stat-row">
      {statCards.map(s => {
        const Icon = s.icon;
        return (
          <div
            key={s.label}
            className={`db-stat-card ${s.clr}`}
            style={{ '--stat-c': s.color }}
          >
            <div className="db-stat-top">
              <span className="db-stat-label">{s.label}</span>
              <div className="db-stat-icon" style={{ background: `${s.color}12`, border: `1px solid ${s.color}20` }}>
                <Icon size={16} style={{ color: s.color }} />
              </div>
            </div>
            <div className="db-stat-value">{s.value}</div>
            <div className={`db-stat-delta db-stat-delta--${s.up ? 'up' : 'down'}`}>
              {s.up ? <TrendingUp size={12} /> : <TrendingDown size={12} />}
              {s.delta}
            </div>
          </div>
        );
      })}
    </div>
  );
}
