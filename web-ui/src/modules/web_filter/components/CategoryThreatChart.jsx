import React from 'react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, PieChart, Pie
} from 'recharts';

export function CategoryThreatChart({ categories = [], domains = [] }) {
  // Aggregate Risk Scores by Category
  const categoryRiskData = categories.slice(0, 10).map(c => ({
    name: c.name.replace(/_/g, ' '),
    score: c.risk_score || 0,
    action: c.action || 'BLOCK',
  }));

  // Aggregate Action Distribution
  const actionCounts = { BLOCK: 0, ALLOW: 0, MONITOR: 0 };
  categories.forEach(c => {
    const act = (c.action || 'BLOCK').toUpperCase();
    if (actionCounts[act] !== undefined) actionCounts[act]++;
    else actionCounts.BLOCK++;
  });

  const pieData = [
    { name: 'حظر (BLOCK)', value: actionCounts.BLOCK, color: '#ff5f5f' },
    { name: 'سماح (ALLOW)', value: actionCounts.ALLOW, color: '#28c76f' },
    { name: 'مراقبة (MONITOR)', value: actionCounts.MONITOR, color: '#60a5fa' },
  ].filter(d => d.value > 0);

  const getBarColor = (score) => {
    if (score >= 80) return '#ff5f5f';
    if (score >= 50) return '#ffc107';
    return '#28c76f';
  };

  return (
    <div className="wf-chart-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px', marginBottom: '20px' }}>
      {/* Category Risk Spectrum Chart */}
      <div className="wf-panel" style={{ padding: '16px 20px' }}>
        <div className="wf-panel-header" style={{ border: 'none', padding: '0 0 12px 0' }}>
          <div className="wf-panel-title">
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#f97316' }} />
            مستوى خطورة التصنيفات الرئيسية (Category Risk Spectrum)
          </div>
        </div>
        <div style={{ width: '100%', height: 210 }}>
          {categoryRiskData.length === 0 ? (
            <div className="wf-empty" style={{ padding: '40px' }}>لا تتوفر تصنيفات لعرض الرسم البياني</div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={categoryRiskData} margin={{ top: 10, right: 10, left: -20, bottom: 25 }}>
                <XAxis
                  dataKey="name"
                  stroke="rgba(255,255,255,0.3)"
                  tick={{ fontSize: 11, fill: '#aaa' }}
                  interval={0}
                  angle={-25}
                  textAnchor="end"
                />
                <YAxis stroke="rgba(255,255,255,0.3)" tick={{ fontSize: 11, fill: '#aaa' }} domain={[0, 100]} />
                <Tooltip
                  contentStyle={{ background: '#181a26', borderColor: 'rgba(255,255,255,0.1)', borderRadius: '8px', color: '#fff', fontSize: '12px' }}
                  formatter={(val) => [`${val} / 100`, 'تقييم الخطر']}
                />
                <Bar dataKey="score" radius={[4, 4, 0, 0]}>
                  {categoryRiskData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={getBarColor(entry.score)} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Action Distribution Donut Chart */}
      <div className="wf-panel" style={{ padding: '16px 20px' }}>
        <div className="wf-panel-header" style={{ border: 'none', padding: '0 0 12px 0' }}>
          <div className="wf-panel-title">
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#60a5fa' }} />
            توزيع سياسات الإجراءات (Policy Action Breakdown)
          </div>
        </div>
        <div style={{ width: '100%', height: 210, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          {pieData.length === 0 ? (
            <div className="wf-empty" style={{ padding: '40px' }}>لا تتوفر سياسات مسجلة</div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={75}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {pieData.map((entry, index) => (
                    <Cell key={`pie-cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: '#181a26', borderColor: 'rgba(255,255,255,0.1)', borderRadius: '8px', color: '#fff', fontSize: '12px' }}
                />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>
    </div>
  );
}
