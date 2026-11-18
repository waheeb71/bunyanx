import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip } from 'recharts';
import { dashboardApi } from '../../../services/api';
import { useToast } from '../../../components/Toast';

// Stable tooltip prop objects — outside component to prevent new references on each render
const TOOLTIP_CONTENT_STYLE = {
  background: '#0f172a',
  border: '1px solid rgba(255,255,255,0.1)',
  borderRadius: 8,
  fontFamily: 'Cairo, sans-serif',
  direction: 'rtl',
};
const TOOLTIP_ITEM_STYLE = { color: '#fff', fontFamily: 'JetBrains Mono, monospace', fontSize: 12 };

export default function AlertsSeverityDonut({ onSelectSeverity }) {
  const toast = useToast();
  const { data: breakdown } = useQuery({
    queryKey: ['dashboard_severity_breakdown_data'],
    queryFn: () => dashboardApi.severityBreakdown().then(r => r?.data || {}),
    refetchInterval: 5000,
  });

  const data = useMemo(() => {
    const critical = breakdown?.critical || { value: 0, percentage: 0 };
    const high = breakdown?.high || { value: 0, percentage: 0 };
    const medium = breakdown?.medium || { value: 0, percentage: 0 };
    const low = breakdown?.low || { value: 0, percentage: 0 };
    return [
      { name: 'حرج', key: 'critical', value: critical.value, color: '#ef4444' },
      { name: 'عالي', key: 'high', value: high.value, color: '#f97316' },
      { name: 'متوسط', key: 'medium', value: medium.value, color: '#eab308' },
      { name: 'منخفض', key: 'low', value: low.value, color: '#3b82f6' },
    ];
  }, [breakdown]);

  const total = breakdown?.total || 0;

  const handleClickItem = (item) => {
    if (!item || !item.key) return;
    if (onSelectSeverity) {
      onSelectSeverity(item.key);
    }
    toast.info(`تم اختيار الفلترة حسب مستوى الخطورة: ${item.name || item.key} (${(item.value || 0).toLocaleString('ar-SA')} تنبيه)`);
  };

  return (
    <div className="pro-chart-card">
      <span className="pro-chart-title">التنبيهات حسب الخطورة</span>
      <div className="pro-donut-wrapper">
        <ResponsiveContainer width="100%" height={180}>
          <PieChart>
            <Tooltip
              contentStyle={TOOLTIP_CONTENT_STYLE}
              itemStyle={TOOLTIP_ITEM_STYLE}
            />
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={52}
              outerRadius={68}
              paddingAngle={4}
              dataKey="value"
              style={{ cursor: 'pointer' }}
              onClick={(entry) => handleClickItem(entry)}
            >
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Pie>
          </PieChart>
        </ResponsiveContainer>

        <div className="pro-donut-center-label">
          <span className="count">{total.toLocaleString('ar-SA')}</span>
          <span className="label">الإجمالي</span>
        </div>
      </div>

      <div className="pro-donut-legend">
        {data.map(item => {
          const pct = total > 0 ? Math.round((item.value / total) * 100) : 0;
          return (
            <div
              key={item.name}
              className="legend-item"
              style={{ cursor: 'pointer' }}
              onClick={() => handleClickItem(item)}
            >
              <span className="dot" style={{ backgroundColor: item.color }} />
              <span className="name">{item.name}</span>
              <span className="count">{item.value.toLocaleString('ar-SA')}</span>
              <span className="pct">({pct}%)</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
