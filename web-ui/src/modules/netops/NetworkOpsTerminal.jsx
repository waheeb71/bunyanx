/**
 * NetworkOpsTerminal — SOC-grade real-time network operations monitor
 */
import { useState } from 'react';
import {
  Network, Cpu, Activity, Wifi, Radio, Globe2,
  Server, ArrowUpDown, AlertCircle, CheckCircle2,
  XCircle, Zap, Terminal, RefreshCw, Eye
} from 'lucide-react';
import { useNetOps } from './hooks/useNetOps';

/* ── Shared palette ──────────────────────────────────────────────────────── */
const C = {
  bg:      '#060b19',
  surface: 'rgba(255,255,255,0.03)',
  border:  'rgba(0,212,255,0.12)',
  cyan:    '#00d4ff',
  green:   '#28c76f',
  amber:   '#ffc107',
  red:     '#ff5f5f',
  purple:  '#a78bfa',
  text:    'rgba(255,255,255,0.85)',
  muted:   'rgba(255,255,255,0.38)',
};

/* ── Status badge ────────────────────────────────────────────────────────── */
function StatusBadge({ status }) {
  const map = {
    ESTABLISHED:  { color: C.green,  dot: true },
    LISTEN:       { color: C.cyan,   dot: true },
    TIME_WAIT:    { color: C.amber,  dot: false },
    CLOSE_WAIT:   { color: C.amber,  dot: false },
    SYN_SENT:     { color: C.purple, dot: false },
    SYN_RECV:     { color: C.purple, dot: false },
    FIN_WAIT1:    { color: C.muted,  dot: false },
    FIN_WAIT2:    { color: C.muted,  dot: false },
    CLOSED:       { color: C.red,    dot: false },
    NONE:         { color: C.muted,  dot: false },
  };
  const cfg = map[status] || { color: C.muted, dot: false };
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 5,
      padding: '2px 8px', borderRadius: 6,
      background: `${cfg.color}18`, border: `1px solid ${cfg.color}40`,
      color: cfg.color, fontSize: '0.72rem', fontWeight: 700,
      fontFamily: 'monospace', letterSpacing: '0.04em',
    }}>
      {cfg.dot && (
        <span style={{
          width: 6, height: 6, borderRadius: '50%',
          background: cfg.color,
          boxShadow: `0 0 6px ${cfg.color}`,
          animation: 'pulse-dot 1.4s ease-in-out infinite',
        }} />
      )}
      {status}
    </span>
  );
}

/* ── Metric tile ─────────────────────────────────────────────────────────── */
function MetricTile({ icon: Icon, label, value, color = C.cyan, sub }) {
  return (
    <div style={{
      background: C.surface, border: `1px solid ${C.border}`,
      borderRadius: 14, padding: '16px 20px',
      display: 'flex', flexDirection: 'column', gap: 6,
      position: 'relative', overflow: 'hidden',
    }}>
      <div style={{
        position: 'absolute', top: -20, right: -20,
        width: 80, height: 80, borderRadius: '50%',
        background: `${color}08`,
      }} />
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <div style={{
          width: 32, height: 32, borderRadius: 8,
          background: `${color}18`, border: `1px solid ${color}40`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <Icon size={16} color={color} />
        </div>
        <span style={{ color: C.muted, fontSize: '0.78rem' }}>{label}</span>
      </div>
      <div style={{ color, fontSize: '1.6rem', fontWeight: 800, lineHeight: 1.1 }}>
        {value ?? '—'}
      </div>
      {sub && <div style={{ color: C.muted, fontSize: '0.72rem' }}>{sub}</div>}
    </div>
  );
}

/* ── Section card ────────────────────────────────────────────────────────── */
function SCard({ title, icon: Icon, children, color = C.cyan, right }) {
  return (
    <div style={{
      background: C.surface, border: `1px solid ${C.border}`,
      borderRadius: 16, padding: 20, display: 'flex', flexDirection: 'column', gap: 14,
    }}>
      <div style={{
        display: 'flex', justifyContent: 'space-between',
        alignItems: 'center', paddingBottom: 12,
        borderBottom: `1px solid ${C.border}`,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Icon size={16} color={color} />
          <span style={{ color: C.text, fontWeight: 700, fontSize: '0.9rem' }}>{title}</span>
        </div>
        {right}
      </div>
      {children}
    </div>
  );
}

/* ── Circuit breaker icon ────────────────────────────────────────────────── */
function CBIcon({ state }) {
  if (state === 'CLOSED')   return <CheckCircle2 size={14} color={C.green} />;
  if (state === 'OPEN')     return <XCircle      size={14} color={C.red}   />;
  if (state === 'HALF_OPEN') return <AlertCircle  size={14} color={C.amber} />;
  return <Eye size={14} color={C.muted} />;
}

export default function NetworkOpsTerminal() {
  const [connFilter, setConnFilter] = useState('');
  const [connStatus, setConnStatus] = useState('ALL');

  const {
    sockets,
    connections: connRaw,
    ports,
    modules,
    modulesCount,
    eventbus,
    websockets,
    refetchAll
  } = useNetOps();

  const topics = eventbus.topics || {};

  /* filter connections */
  const conns = connRaw.filter(c => {
    const matchF = !connFilter ||
      c.local?.includes(connFilter) ||
      c.remote?.includes(connFilter) ||
      String(c.pid)?.includes(connFilter);
    const matchS = connStatus === 'ALL' || c.status === connStatus;
    return matchF && matchS;
  });

  const fmtBytes = (b) => {
    if (b == null) return '—';
    if (b < 1024) return `${b} B`;
    if (b < 1024 ** 2) return `${(b / 1024).toFixed(1)} KB`;
    if (b < 1024 ** 3) return `${(b / 1024 ** 2).toFixed(1)} MB`;
    return `${(b / 1024 ** 3).toFixed(2)} GB`;
  };

  const byStatus = sockets.by_status || {};
  const established = byStatus.ESTABLISHED || 0;
  const listening   = byStatus.LISTEN      || 0;

  return (
    <div dir="rtl" style={{
      minHeight: '100vh', background: C.bg, padding: '24px 28px',
      fontFamily: "'Cairo', 'Inter', sans-serif", color: C.text,
    }}>
      {/* ── Header ───────────────────────────────────────────────────────── */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        marginBottom: 24,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{
            width: 48, height: 48, borderRadius: 14,
            background: `${C.cyan}18`, border: `1px solid ${C.cyan}40`,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <Terminal size={22} color={C.cyan} />
          </div>
          <div>
            <h1 style={{ margin: 0, fontSize: '1.4rem', fontWeight: 900, color: C.text }}>
              طرفية العمليات الشبكية
            </h1>
            <p style={{ margin: 0, fontSize: '0.8rem', color: C.muted }}>
              Network Operations Terminal — SOC Grade Real-Time Monitor
            </p>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{
            width: 8, height: 8, borderRadius: '50%',
            background: C.green, boxShadow: `0 0 8px ${C.green}`,
            animation: 'pulse-dot 1.4s ease-in-out infinite',
          }} />
          <span style={{ color: C.green, fontSize: '0.78rem', fontWeight: 700 }}>LIVE</span>
          <button onClick={refetchAll} style={{
            background: `${C.cyan}18`, border: `1px solid ${C.cyan}40`,
            color: C.cyan, borderRadius: 8, padding: '6px 12px',
            cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6,
            fontSize: '0.8rem', fontWeight: 600,
          }}>
            <RefreshCw size={13} /> تحديث
          </button>
        </div>
      </div>

      {/* ── Metric Tiles Row ──────────────────────────────────────────────── */}
      <div style={{
        display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))',
        gap: 14, marginBottom: 24,
      }}>
        <MetricTile icon={Network}    label="اتصالات نشطة"   value={established}             color={C.green}  />
        <MetricTile icon={Server}     label="منافذ مستمعة"   value={listening}               color={C.cyan}   />
        <MetricTile icon={Activity}   label="إجمالي السوكتات" value={sockets.total_sockets}     color={C.purple} />
        <MetricTile icon={ArrowUpDown} label="بيانات مُستقبلة" value={fmtBytes(sockets.bytes_recv)} color={C.amber} />
        <MetricTile icon={ArrowUpDown} label="بيانات مُرسلة"  value={fmtBytes(sockets.bytes_sent)} color={C.cyan}  />
        <MetricTile icon={Wifi}       label="جلسات WebSocket"
                    value={websockets?.total_connections ?? websockets?.active_connections ?? '—'}
                    color={C.purple} />
        <MetricTile icon={Zap}        label="وحدات الفحص"   value={modulesCount}    color={C.green}  />
        <MetricTile icon={Radio}      label="خطأ استقبال"    value={sockets.errin ?? 0}         color={sockets.errin > 0 ? C.red : C.muted}    sub="network errin" />
      </div>

      {/* ── Main Grid ────────────────────────────────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 20 }}>

        {/* Connections Table */}
        <div style={{ gridColumn: '1 / -1' }}>
          <SCard title="الاتصالات الحالية" icon={Network} color={C.cyan}
            right={
              <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
                <select value={connStatus} onChange={e => setConnStatus(e.target.value)} style={{
                  background: 'rgba(0,212,255,0.08)', border: `1px solid ${C.border}`,
                  color: C.text, borderRadius: 8, padding: '4px 10px',
                  fontSize: '0.8rem', cursor: 'pointer',
                }}>
                  {['ALL','ESTABLISHED','LISTEN','TIME_WAIT','CLOSE_WAIT'].map(s => (
                    <option key={s} value={s}>{s}</option>
                  ))}
                </select>
                <input
                  value={connFilter}
                  onChange={e => setConnFilter(e.target.value)}
                  placeholder="بحث بـ IP أو PID..."
                  style={{
                    background: 'rgba(255,255,255,0.04)', border: `1px solid ${C.border}`,
                    color: C.text, borderRadius: 8, padding: '4px 12px',
                    fontSize: '0.8rem', outline: 'none', width: 180,
                  }}
                />
                <span style={{ color: C.muted, fontSize: '0.78rem' }}>
                  {conns.length} / {connRaw.length}
                </span>
              </div>
            }
          >
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8rem' }}>
                <thead>
                  <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                    {['النوع','العنوان المحلي','العنوان البعيد','الحالة','PID'].map(h => (
                      <th key={h} style={{
                        padding: '8px 12px', color: C.muted, fontWeight: 600,
                        textAlign: 'right', whiteSpace: 'nowrap',
                      }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {conns.slice(0, 80).map((c, i) => (
                    <tr key={i} style={{
                      borderBottom: `1px solid ${C.border}22`,
                      transition: 'background 0.15s',
                    }}
                      onMouseEnter={e => e.currentTarget.style.background = 'rgba(0,212,255,0.04)'}
                      onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                    >
                      <td style={{ padding: '7px 12px', color: C.muted, fontFamily: 'monospace' }}>
                        {c.type}
                      </td>
                      <td style={{ padding: '7px 12px', fontFamily: 'monospace', color: C.cyan }}>
                        {c.local || '—'}
                      </td>
                      <td style={{ padding: '7px 12px', fontFamily: 'monospace', color: C.text }}>
                        {c.remote || '—'}
                      </td>
                      <td style={{ padding: '7px 12px' }}>
                        <StatusBadge status={c.status || 'NONE'} />
                      </td>
                      <td style={{ padding: '7px 12px', color: C.muted, fontFamily: 'monospace' }}>
                        {c.pid || '—'}
                      </td>
                    </tr>
                  ))}
                  {conns.length === 0 && (
                    <tr><td colSpan={5} style={{ padding: 24, textAlign: 'center', color: C.muted }}>
                      لا توجد اتصالات مطابقة للفلتر
                    </td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </SCard>
        </div>

        {/* Listening Ports */}
        <SCard title="المنافذ المستمعة" icon={Server} color={C.purple}>
          <div style={{ overflowY: 'auto', maxHeight: 320 }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8rem' }}>
              <thead>
                <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                  {['العنوان','النوع','PID'].map(h => (
                    <th key={h} style={{ padding: '6px 10px', color: C.muted, fontWeight: 600, textAlign: 'right' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {ports.slice(0, 60).map((p, i) => (
                  <tr key={i} style={{ borderBottom: `1px solid ${C.border}18` }}>
                    <td style={{ padding: '6px 10px', fontFamily: 'monospace', color: C.purple }}>{p.local}</td>
                    <td style={{ padding: '6px 10px', color: C.muted, fontSize: '0.75rem' }}>{p.type}</td>
                    <td style={{ padding: '6px 10px', color: C.muted, fontFamily: 'monospace' }}>{p.pid || '—'}</td>
                  </tr>
                ))}
                {ports.length === 0 && (
                  <tr><td colSpan={3} style={{ padding: 20, textAlign: 'center', color: C.muted }}>
                    لا توجد بيانات
                  </td></tr>
                )}
              </tbody>
            </table>
          </div>
        </SCard>

        {/* Socket Status Breakdown */}
        <SCard title="توزيع حالات السوكتات" icon={Activity} color={C.green}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {Object.entries(byStatus).sort((a,b) => b[1]-a[1]).map(([s, count]) => {
              const max = Math.max(...Object.values(byStatus), 1);
              const pct = Math.round((count / max) * 100);
              const colorMap = {
                ESTABLISHED: C.green, LISTEN: C.cyan,
                TIME_WAIT: C.amber, CLOSE_WAIT: C.amber,
                CLOSED: C.red,
              };
              const barColor = colorMap[s] || C.muted;
              return (
                <div key={s}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <StatusBadge status={s} />
                    <span style={{ color: barColor, fontWeight: 700, fontSize: '0.85rem' }}>{count}</span>
                  </div>
                  <div style={{ height: 4, background: 'rgba(255,255,255,0.06)', borderRadius: 4, overflow: 'hidden' }}>
                    <div style={{
                      height: '100%', width: `${pct}%`, background: barColor,
                      borderRadius: 4, transition: 'width 0.5s ease',
                      boxShadow: `0 0 8px ${barColor}60`,
                    }} />
                  </div>
                </div>
              );
            })}
            {Object.keys(byStatus).length === 0 && (
              <div style={{ color: C.muted, textAlign: 'center', padding: 20 }}>جاري التحميل...</div>
            )}
          </div>
        </SCard>
      </div>

      {/* ── Bottom Grid ──────────────────────────────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 20 }}>

        {/* Module Health */}
        <SCard title="صحة وحدات الفحص" icon={Cpu} color={C.amber}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 340, overflowY: 'auto' }}>
            {modules.map((m, i) => (
              <div key={i} style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                padding: '8px 12px', borderRadius: 10,
                background: m.enabled ? 'rgba(40,199,111,0.06)' : 'rgba(255,95,95,0.05)',
                border: `1px solid ${m.enabled ? C.green + '30' : C.red + '25'}`,
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <CBIcon state={m.circuit_breaker} />
                  <span style={{ fontSize: '0.82rem', color: C.text, fontWeight: 600 }}>{m.name}</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{
                    fontSize: '0.7rem', padding: '2px 7px', borderRadius: 5,
                    background: m.circuit_breaker === 'OPEN' ? `${C.red}18` : `${C.green}18`,
                    color: m.circuit_breaker === 'OPEN' ? C.red : C.green,
                    border: `1px solid ${m.circuit_breaker === 'OPEN' ? C.red : C.green}40`,
                    fontFamily: 'monospace', fontWeight: 700,
                  }}>{m.circuit_breaker}</span>
                  <span style={{ color: C.muted, fontSize: '0.7rem' }}>P{m.priority}</span>
                </div>
              </div>
            ))}
            {modules.length === 0 && (
              <div style={{ color: C.muted, textAlign: 'center', padding: 24 }}>
                لا توجد وحدات محملة
              </div>
            )}
          </div>
        </SCard>

        {/* Event Bus */}
        <SCard title="ناقل الأحداث" icon={Radio} color={C.purple}
          right={
            <span style={{
              fontSize: '0.72rem', color: eventbus?.available ? C.green : C.red,
              background: eventbus?.available ? `${C.green}18` : `${C.red}18`,
              border: `1px solid ${eventbus?.available ? C.green : C.red}40`,
              padding: '2px 8px', borderRadius: 6, fontWeight: 700,
            }}>
              {eventbus?.backend || '—'}
            </span>
          }
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 340, overflowY: 'auto' }}>
            {Object.entries(topics).length > 0
              ? Object.entries(topics).map(([topic, data]) => (
                <div key={topic} style={{
                  display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  padding: '8px 12px', borderRadius: 10,
                  background: 'rgba(167,139,250,0.06)', border: `1px solid ${C.purple}25`,
                }}>
                  <span style={{ fontSize: '0.78rem', color: C.text, fontFamily: 'monospace' }}>
                    {topic.split('.').pop()}
                  </span>
                  <span style={{ fontSize: '0.8rem', color: C.purple, fontWeight: 700 }}>
                    {typeof data === 'object'
                      ? (data.subscriber_count ?? data.publish_count ?? '—')
                      : data}
                  </span>
                </div>
              ))
              : (
                <div style={{ color: C.muted, textAlign: 'center', padding: 24 }}>
                  {eventbus?.available === false
                    ? (eventbus?.reason || 'غير متاح')
                    : 'لا توجد مواضيع مسجلة'}
                </div>
              )}
          </div>
        </SCard>

        {/* WebSocket Sessions */}
        <SCard title="جلسات WebSocket" icon={Globe2} color={C.cyan}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {[
              { label: 'الاتصالات النشطة', key: 'total_connections',   color: C.cyan   },
              { label: 'مشتركو الإحصاء',   key: 'stats_subscribers',   color: C.green  },
              { label: 'مشتركو التنبيهات', key: 'alert_subscribers',   color: C.amber  },
              { label: 'مشتركو الحركة',    key: 'traffic_subscribers', color: C.purple },
            ].map(({ label, key, color }) => {
              const val = key === 'total_connections' 
                ? (websockets?.total_connections) 
                : (key === 'stats_subscribers' 
                    ? (websockets?.subscriptions?.stats) 
                    : (key === 'alert_subscribers' 
                        ? (websockets?.subscriptions?.alerts) 
                        : (key === 'traffic_subscribers' 
                            ? (websockets?.subscriptions?.traffic) 
                            : undefined)));
              return (
                <div key={key} style={{
                  display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  padding: '10px 14px', borderRadius: 10,
                  background: `${color}08`, border: `1px solid ${color}25`,
                }}>
                  <span style={{ fontSize: '0.82rem', color: C.muted }}>{label}</span>
                  <span style={{ fontSize: '1.1rem', fontWeight: 800, color }}>
                    {val ?? '—'}
                  </span>
                </div>
              );
            })}
          </div>
        </SCard>

      </div>

      {/* ── Global keyframes ──────────────────────────────────────────────── */}
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800;900&display=swap');
        @keyframes pulse-dot {
          0%, 100% { opacity: 1; transform: scale(1); }
          50%       { opacity: 0.5; transform: scale(0.85); }
        }
        ::-webkit-scrollbar { width: 4px; height: 4px; }
        ::-webkit-scrollbar-track  { background: transparent; }
        ::-webkit-scrollbar-thumb  { background: rgba(0,212,255,0.25); border-radius: 4px; }
      `}</style>
    </div>
  );
}
