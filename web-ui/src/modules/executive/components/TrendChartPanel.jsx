import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { BarChart3, TrendingUp, ShieldCheck, Activity, Eye } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';

/* ── Custom Luxury Tooltip for Recharts ────────────────── */
function CustomChartTooltip({ active, payload, label }) {
  if (!active || !payload || !payload.length) return null;
  return (
    <div className="exec-chart-tooltip">
      <div className="exec-tooltip-title">{label}</div>
      <div className="exec-tooltip-items">
        {payload.map((entry, index) => (
          <div key={`item-${index}`} className="exec-tooltip-row">
            <span className="exec-tooltip-dot" style={{ background: entry.color }} />
            <span className="exec-tooltip-name">{entry.name}:</span>
            <span className="exec-tooltip-val" style={{ color: entry.color }}>
              {entry.value?.toLocaleString()}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function TrendChartPanel({ threatTrend = [] }) {
  const [timeRange, setTimeRange] = useState('7d');

  // Fallback sample data if array is empty
  const defaultData = [
    { month: 'السبت', blocked: 420, detected: 435 },
    { month: 'الأحد', blocked: 610, detected: 625 },
    { month: 'الإثنين', blocked: 890, detected: 905 },
    { month: 'الثلاثاء', blocked: 740, detected: 752 },
    { month: 'الأربعاء', blocked: 1050, detected: 1070 },
    { month: 'الخميس', blocked: 930, detected: 945 },
    { month: 'الجمعة', blocked: 1180, detected: 1195 },
  ];

  const chartData = threatTrend.length > 0 ? threatTrend : defaultData;

  const totalBlocked = chartData.reduce((acc, curr) => acc + (curr.blocked || 0), 0);
  const totalDetected = chartData.reduce((acc, curr) => acc + (curr.detected || 0), 0);
  const efficiency = totalDetected > 0 ? ((totalBlocked / totalDetected) * 100).toFixed(1) : '99.4';

  return (
    <motion.div
      className="exec-panel exec-chart-panel"
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, delay: 0.15 }}
    >
      <div className="exec-panel-header">
        <div className="exec-panel-title-group">
          <div className="exec-panel-icon-wrap" style={{ background: 'rgba(0, 200, 255, 0.12)', color: '#00c8ff' }}>
            <BarChart3 size={18} />
          </div>
          <div>
            <h3 className="exec-panel-title">تحليل ورصد اتجاهات التهديدات السيبرانية</h3>
            <span className="exec-panel-sub">مقارنة التهديدات المكتشفة بالهجمات المحجوبة تلقائياً</span>
          </div>
        </div>

        <div className="exec-chart-header-actions">
          <div className="exec-range-pill-group">
            {['24h', '7d', '30d'].map((r) => (
              <button
                key={r}
                className={`exec-range-pill ${timeRange === r ? 'active' : ''}`}
                onClick={() => setTimeRange(r)}
              >
                {r === '24h' ? '24 ساعة' : r === '7d' ? '7 أيام' : '30 يوماً'}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Top Chart Metric Summary Bar */}
      <div className="exec-chart-summary-bar">
        <div className="exec-chart-metric-chip">
          <div className="exec-chart-metric-icon" style={{ color: '#00e676', background: 'rgba(0, 230, 118, 0.12)' }}>
            <ShieldCheck size={14} />
          </div>
          <div>
            <span className="exec-chart-metric-label">إجمالي التهديدات المحجوبة</span>
            <span className="exec-chart-metric-val" style={{ color: '#00e676' }}>
              {totalBlocked.toLocaleString()}
            </span>
          </div>
        </div>

        <div className="exec-chart-metric-chip">
          <div className="exec-chart-metric-icon" style={{ color: '#00c8ff', background: 'rgba(0, 200, 255, 0.12)' }}>
            <Eye size={14} />
          </div>
          <div>
            <span className="exec-chart-metric-label">إجمالي التهديدات المرصودة</span>
            <span className="exec-chart-metric-val" style={{ color: '#00c8ff' }}>
              {totalDetected.toLocaleString()}
            </span>
          </div>
        </div>

        <div className="exec-chart-metric-chip">
          <div className="exec-chart-metric-icon" style={{ color: '#818cf8', background: 'rgba(129, 140, 248, 0.12)' }}>
            <Activity size={14} />
          </div>
          <div>
            <span className="exec-chart-metric-label">كفاءة الاعتراض التلقائي</span>
            <span className="exec-chart-metric-val" style={{ color: '#818cf8' }}>
              {efficiency}%
            </span>
          </div>
        </div>
      </div>

      {/* Chart Canvas */}
      <div className="exec-chart-canvas-wrap">
        <ResponsiveContainer width="100%" height={260}>
          <AreaChart data={chartData} margin={{ top: 15, right: 10, bottom: 0, left: -15 }}>
            <defs>
              <linearGradient id="gradBlockedNeon" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#00e676" stopOpacity={0.35} />
                <stop offset="95%" stopColor="#00e676" stopOpacity={0.0} />
              </linearGradient>
              <linearGradient id="gradDetectedNeon" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#00c8ff" stopOpacity={0.35} />
                <stop offset="95%" stopColor="#00c8ff" stopOpacity={0.0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
            <XAxis
              dataKey="month"
              tick={{ fill: 'rgba(255,255,255,0.45)', fontSize: 11, fontFamily: 'Cairo, sans-serif' }}
              axisLine={{ stroke: 'rgba(255,255,255,0.1)' }}
              tickLine={false}
            />
            <YAxis
              tick={{ fill: 'rgba(255,255,255,0.4)', fontSize: 11, fontFamily: 'JetBrains Mono, monospace' }}
              axisLine={{ stroke: 'rgba(255,255,255,0.1)' }}
              tickLine={false}
            />
            <Tooltip content={<CustomChartTooltip />} />
            <Area
              type="monotone"
              dataKey="detected"
              name="التهديدات المكتشفة"
              stroke="#00c8ff"
              fill="url(#gradDetectedNeon)"
              strokeWidth={2.5}
              dot={{ r: 3, fill: '#00c8ff', strokeWidth: 0 }}
              activeDot={{ r: 6, fill: '#00c8ff', stroke: '#fff', strokeWidth: 2 }}
            />
            <Area
              type="monotone"
              dataKey="blocked"
              name="التهديدات المحجوبة"
              stroke="#00e676"
              fill="url(#gradBlockedNeon)"
              strokeWidth={2.5}
              dot={{ r: 3, fill: '#00e676', strokeWidth: 0 }}
              activeDot={{ r: 6, fill: '#00e676', stroke: '#fff', strokeWidth: 2 }}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </motion.div>
  );
}
