import { useMemo } from 'react';
import { ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';

export function AttackTypesCard({ attackTypes = {} }) {
  const chartData = useMemo(() => [
    { name: 'برمجيات خبيثة', value: attackTypes.malware || 0, color: '#00d4ff' },
    { name: 'هجمات ويب', value: attackTypes.web || 0, color: '#b388ff' },
    { name: 'استغلال ثغرات', value: attackTypes.exploit || 0, color: '#ffab40' },
    { name: 'هجمات الشبكة', value: attackTypes.network || 0, color: '#4dd0e1' },
    { name: 'أخرى', value: attackTypes.other || 0, color: '#ff7043' },
  ], [attackTypes]);

  const totalAttacks = useMemo(() => chartData.reduce((acc, d) => acc + d.value, 0), [chartData]);

  return (
    <div className="gtm-card">
      <div className="gtm-card-header">
        <h3 className="gtm-card-title">توزيع أنواع الهجمات</h3>
      </div>

      <div className="gtm-chart-row">
        <div className="gtm-donut-container">
          <ResponsiveContainer width="100%" height={140}>
            <PieChart>
              <Pie
                data={chartData}
                cx="50%"
                cy="50%"
                innerRadius={42}
                outerRadius={56}
                paddingAngle={3}
                dataKey="value"
              >
                {chartData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
            </PieChart>
          </ResponsiveContainer>
          <div className="gtm-donut-center">
            <span className="gtm-donut-value">{totalAttacks.toLocaleString()}</span>
            <span className="gtm-donut-label">إجمالي الهجمات</span>
          </div>
        </div>

        <div className="gtm-chart-legend">
          {chartData.map((item) => {
            const pct = totalAttacks > 0 ? Math.round((item.value / totalAttacks) * 100) : 0;
            return (
              <div key={item.name} className="gtm-legend-row">
                <div className="gtm-legend-row-label">
                  <span className="gtm-legend-row-dot" style={{ background: item.color }} />
                  <span>{item.name}</span>
                </div>
                <div className="gtm-legend-row-vals">
                  <span className="gtm-val-count">{pct}%</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

export default AttackTypesCard;
