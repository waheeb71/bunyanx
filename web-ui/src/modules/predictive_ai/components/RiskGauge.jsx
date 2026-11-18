import { RadialBarChart, RadialBar, ResponsiveContainer } from 'recharts';

export function RiskGauge({ remaining, max }) {
  const pct   = max ? (remaining / max) * 100 : 0;
  const color = pct >= 70 ? '#28c76f' : pct >= 30 ? '#fbbf24' : '#ff5f5f';
  return (
    <div className="pai-gauge">
      <div className="pai-gauge-ring" style={{ display: 'flex', justifyContent: 'center' }}>
        <RadialBarChart width={130} height={130} cx="50%" cy="50%" innerRadius="68%" outerRadius="100%"
          startAngle={210} endAngle={-30}
          data={[{ value: pct, fill: color }]}>
          <RadialBar minAngle={8} dataKey="value" cornerRadius={6} background={{ fill: 'rgba(255,255,255,0.04)' }} isAnimationActive={true} />
        </RadialBarChart>
        <div className="pai-gauge-center">
          <span className="pai-gauge-val" style={{ color }}>{Math.round(remaining)}</span>
          <span className="pai-gauge-sub">/ {Math.round(max)}</span>
        </div>
      </div>
      <span className="pai-gauge-label">ميزانية المخاطرة (RL)</span>
    </div>
  );
}

export default RiskGauge;
