import { useMemo } from 'react';
import { ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';

export function GlobalSeverityCard({ severityData = {} }) {
  const chartData = useMemo(() => [
    { name: 'حرج', value: severityData.critical || 0, color: '#ff4d6d' },
    { name: 'مرتفع', value: severityData.high || 0, color: '#ff9800' },
    { name: 'متوسط', value: severityData.medium || 0, color: '#ffc107' },
    { name: 'منخفض', value: severityData.low || 0, color: '#00d4ff' },
  ], [severityData]);

  const totalAlerts = useMemo(() => chartData.reduce((acc, d) => acc + d.value, 0), [chartData]);

  return (
    <div className="gtm-card">
      <div className="gtm-card-header flex-row">
        <h3 className="gtm-card-title">تفاصيل التهديدات العالمية</h3>
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
            <span className="gtm-donut-value">{totalAlerts.toLocaleString()}</span>
            <span className="gtm-donut-label">إجمالي التنبيهات</span>
          </div>
        </div>

        <div className="gtm-chart-legend">
          {chartData.map((item) => {
            const pct = totalAlerts > 0 ? ((item.value / totalAlerts) * 100).toFixed(1) : '0.0';
            return (
              <div key={item.name} className="gtm-legend-row">
                <div className="gtm-legend-row-label">
                  <span className="gtm-legend-row-dot" style={{ background: item.color }} />
                  <span>{item.name}</span>
                </div>
                <div className="gtm-legend-row-vals">
                  <span className="gtm-val-count">{item.value.toLocaleString()}</span>
                  <span className="gtm-val-pct">({pct}%)</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

export default GlobalSeverityCard;
