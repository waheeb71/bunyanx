import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip,
  BarChart, Bar, XAxis, YAxis, CartesianGrid
} from 'recharts';
import { ShieldAlert, BarChart2 } from 'lucide-react';

const PIE_COLORS = {
  allow:      '#28c76f',
  quarantine: '#fbbf24',
  block:      '#ff5f5f',
};
const PIE_LABELS = { allow: 'سماح', quarantine: 'عزل', block: 'حظر' };

function PieTooltip({ active, payload }) {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background: '#1a1b28', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, padding: '8px 12px', fontFamily: 'Cairo, sans-serif', fontSize: '.82rem', color: '#f0f0f5' }}>
      {payload[0].name}: <strong>{payload[0].value}</strong>
    </div>
  );
}

export default function EmailStats({ stats }) {
  const decisions = ['allow', 'quarantine', 'block']
    .map(k => ({ name: PIE_LABELS[k], value: stats.decision_breakdown?.[k] || 0, color: PIE_COLORS[k] }))
    .filter(d => d.value > 0);

  const topSenders = (stats.top_blocked_senders || []).map(s => ({
    name:  s.sender.length > 28 ? s.sender.slice(0, 26) + '…' : s.sender,
    full:  s.sender,
    count: s.count,
  }));

  return (
    <div className="em-stats-grid">

      {/* ── Pie chart ── */}
      <div className="em-panel">
        <div className="em-panel-header">
          <div className="em-panel-title"><ShieldAlert size={14} /> تحليل القرارات</div>
        </div>
        <div style={{ padding: '20px 16px' }}>
          {decisions.length === 0 ? (
            <div className="em-empty" style={{ padding: '40px 0' }}>لا توجد بيانات بعد.</div>
          ) : (
            <>
              <ResponsiveContainer width="100%" height={180}>
                <PieChart>
                  <Pie
                    data={decisions}
                    dataKey="value"
                    nameKey="name"
                    cx="50%" cy="50%"
                    innerRadius={55} outerRadius={80}
                    stroke="none"
                    paddingAngle={3}
                  >
                    {decisions.map((d, i) => (
                      <Cell key={i} fill={d.color} />
                    ))}
                  </Pie>
                  <Tooltip content={<PieTooltip />} />
                </PieChart>
              </ResponsiveContainer>
              <div className="em-pie-legend">
                {decisions.map(d => (
                  <div key={d.name} className="em-pie-label">
                    <span className="em-pie-dot" style={{ background: d.color }} />
                    {d.name}
                    <span className="em-pie-val">{d.value}</span>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      </div>

      {/* ── Bar chart ── */}
      <div className="em-panel">
        <div className="em-panel-header">
          <div className="em-panel-title" style={{ color: 'rgba(255,95,95,0.7)' }}>
            <BarChart2 size={14} /> أعلى المرسلين المحظورين
          </div>
        </div>
        <div style={{ padding: '16px 8px' }}>
          {topSenders.length === 0 ? (
            <div className="em-empty" style={{ padding: '40px 0' }}>لا يوجد مرسلون محظورون حتى الآن.</div>
          ) : (
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={topSenders} layout="vertical" margin={{ left: 8, right: 24, top: 4, bottom: 4 }}>
                <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="rgba(255,255,255,0.05)" />
                <XAxis type="number" tick={{ fill: 'rgba(255,255,255,0.2)', fontSize: 10 }} axisLine={false} tickLine={false} />
                <YAxis type="category" dataKey="name" width={190}
                  tick={{ fill: 'rgba(255,255,255,0.4)', fontSize: 10, fontFamily: 'Fira Code, monospace' }}
                  axisLine={false} tickLine={false}
                />
                <Tooltip
                  cursor={{ fill: 'rgba(255,255,255,0.03)' }}
                  contentStyle={{ background: '#1a1b28', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, fontFamily: 'Cairo, sans-serif', fontSize: '.82rem', direction: 'ltr' }}
                />
                <Bar dataKey="count" fill="#ff5f5f" radius={[0, 5, 5, 0]} barSize={18} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>
    </div>
  );
}
