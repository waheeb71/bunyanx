import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip } from 'recharts';

export function ThreatTimelineCard({ timelineData = [] }) {
  const renderTimelinePin = (props) => {
    const { cx, cy, payload } = props;
    if (payload && payload.pin) {
      return (
        <g key={`pin-${payload.time}`}>
          <circle cx={cx} cy={cy} r={8} fill="none" stroke={payload.pinColor || '#ff4d6d'} strokeWidth={2}>
            <animate attributeName="r" values="5;14;5" dur="2.4s" repeatCount="indefinite" />
            <animate attributeName="opacity" values="0.9;0;0.9" dur="2.4s" repeatCount="indefinite" />
          </circle>
          <circle cx={cx} cy={cy} r={4.5} fill={payload.pinColor || '#ff4d6d'} />
          <line x1={cx} y1={cy} x2={cx} y2={cy - 22} stroke={payload.pinColor || '#ff4d6d'} strokeWidth={1} strokeDasharray="2 2" />
          <g transform={`translate(${cx - 11}, ${cy - 40})`}>
            <rect width="22" height="22" rx="5" fill="#070c16" stroke={payload.pinColor || '#ff4d6d'} strokeWidth={1.5} />
            <text x="11" y="15" fontSize="11" textAnchor="middle" fill="#fff">
              {payload.pinIcon || '🚨'}
            </text>
          </g>
        </g>
      );
    }
    return null;
  };

  return (
    <div className="gtm-card gtm-timeline-card">
      <div className="gtm-card-header">
        <h3 className="gtm-card-title">الخط الزمني للهجمات</h3>
      </div>
      <div className="gtm-timeline-chart-container">
        <ResponsiveContainer width="100%" height={140}>
          <AreaChart data={timelineData} margin={{ top: 25, bottom: 5, left: 10, right: 10 }}>
            <defs>
              <linearGradient id="colorAttacksGlobe" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#00d4ff" stopOpacity={0.25} />
                <stop offset="95%" stopColor="#00d4ff" stopOpacity={0.0} />
              </linearGradient>
            </defs>
            <XAxis
              dataKey="time"
              axisLine={false}
              tickLine={false}
              tick={{ fill: 'rgba(190, 212, 240, 0.45)', fontSize: 10, fontFamily: 'JetBrains Mono' }}
            />
            <YAxis hide domain={[0, 'dataMax + 20']} />
            <Tooltip
              content={({ active, payload }) => {
                if (active && payload && payload.length) {
                  return (
                    <div className="gtm-chart-tooltip">
                      <span className="gtm-tooltip-time">{payload[0].payload.time}</span>
                      <span className="gtm-tooltip-count">
                        {(payload[0].value || 0).toLocaleString()} هجوم
                      </span>
                    </div>
                  );
                }
                return null;
              }}
            />
            <Area
              type="monotone"
              dataKey="attacks"
              stroke="#00d4ff"
              strokeWidth={2}
              fillOpacity={1}
              fill="url(#colorAttacksGlobe)"
              dot={renderTimelinePin}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

export default ThreatTimelineCard;
