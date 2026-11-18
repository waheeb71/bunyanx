import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts';
import { dashboardApi } from '../../../services/api';

const EMPTY_TIMELINE = [
  { time: '00:00', val: 0 },
  { time: '04:00', val: 0 },
  { time: '08:00', val: 0 },
  { time: '12:00', val: 0 },
  { time: '16:00', val: 0 },
  { time: '20:00', val: 0 },
  { time: '24:00', val: 0 },
];

// Stable chart prop objects — outside component to prevent new references on each render
const AREA_CHART_MARGIN = { top: 8, right: 8, left: -20, bottom: 0 };
const TOOLTIP_CONTENT_STYLE = {
  background: '#0f172a',
  border: '1px solid rgba(255,255,255,0.1)',
  borderRadius: 8,
  fontFamily: 'Cairo, sans-serif',
  direction: 'rtl',
};
const TOOLTIP_LABEL_STYLE = { color: '#94a3b8', fontSize: 11, fontFamily: 'JetBrains Mono, monospace' };
const TOOLTIP_ITEM_STYLE = { color: '#fff', fontSize: 12 };

export default function AlertsTrendArea() {
  const { data: trendData } = useQuery({
    queryKey: ['dashboard_alerts_trend_24h_data'],
    queryFn: () => dashboardApi.alertsTrend24h().then(r => r?.data || []),
    refetchInterval: 5000,
  });

  const chartData = useMemo(() => {
    return Array.isArray(trendData) && trendData.length > 0 ? trendData : EMPTY_TIMELINE;
  }, [trendData]);

  const peak = useMemo(() => {
    return Math.max(...chartData.map(d => Number(d?.val || 0)), 0);
  }, [chartData]);

  return (
    <div className="pro-chart-card">
      <div className="pro-chart-header">
        <span className="pro-chart-title">اتجاه التنبيهات</span>
        <div className="pro-trend-peak-pill">
          الذروة: <span style={{ color: '#fca5a5', marginRight: 4 }}>{peak.toLocaleString('ar-SA')}</span>
        </div>
      </div>

      <div className="pro-area-chart-container">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={chartData} margin={AREA_CHART_MARGIN}>
            <defs>
              <linearGradient id="trendGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#ef4444" stopOpacity={0.25} />
                <stop offset="100%" stopColor="#ef4444" stopOpacity={0.0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.03)" />
            <XAxis
              dataKey="time"
              stroke="rgba(255,255,255,0.2)"
              fontSize={10}
              tickLine={false}
              axisLine={false}
              fontFamily="JetBrains Mono, monospace"
            />
            <YAxis
              stroke="rgba(255,255,255,0.2)"
              fontSize={10}
              tickLine={false}
              axisLine={false}
              fontFamily="JetBrains Mono, monospace"
            />
            <Tooltip
              contentStyle={TOOLTIP_CONTENT_STYLE}
              labelStyle={TOOLTIP_LABEL_STYLE}
              itemStyle={TOOLTIP_ITEM_STYLE}
            />
            <Area
              type="monotone"
              dataKey="val"
              stroke="#ef4444"
              strokeWidth={2}
              fill="url(#trendGrad)"
              dot={false}
              name="تنبيهات"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
