import React from 'react';
import { RadialBarChart, RadialBar, ResponsiveContainer } from 'recharts';
import { Gauge, ShieldAlert, Cpu, Activity } from 'lucide-react';
import { SectionCard } from '../../../components/Shared';

export function QoSStats({ topUtilization, activeBuckets = 0, totalCapacity = 0, criticalCount = 0 }) {
  const safeUtilization = Math.min(100, Math.max(0, topUtilization || 0));
  const gaugeColor = safeUtilization > 85 
    ? '#ff4d6a' 
    : safeUtilization > 60 
      ? '#ffab40' 
      : '#00c8ff';

  const gaugeData = [{
    name: 'استخدام',
    value: safeUtilization,
    fill: gaugeColor,
  }];

  return (
    <SectionCard title="مقياس الاستخدام الأعلى للنطاق الترددي" icon={Gauge}>
      <div style={{ display: 'flex', flexDirection: 'column', height: '100%', justifyContent: 'between' }}>
        <div style={{ width: '100%', height: 200, display: 'flex', alignItems: 'center', justifyContent: 'center', relative: 'relative' }}>
          <ResponsiveContainer width="100%" height={200}>
            <RadialBarChart
              cx="50%" cy="50%"
              innerRadius="65%" outerRadius="90%"
              startAngle={210} endAngle={-30}
              data={gaugeData}
              barSize={16}
            >
              <RadialBar
                background={{ fill: 'rgba(255,255,255,0.05)' }}
                dataKey="value"
                cornerRadius={10}
                isAnimationActive={true}
              />
              <text
                x="50%" y="45%"
                textAnchor="middle"
                dominantBaseline="middle"
                style={{
                  fill: gaugeColor,
                  fontSize: '2.2rem',
                  fontWeight: 700,
                  fontFamily: 'var(--font-mono)',
                  filter: `drop-shadow(0 0 10px ${gaugeColor}44)`
                }}
              >
                {safeUtilization.toFixed(0)}%
              </text>
              <text
                x="50%" y="62%"
                textAnchor="middle"
                style={{
                  fill: 'var(--text-muted)',
                  fontSize: '0.72rem',
                  fontWeight: 600,
                  letterSpacing: '1px'
                }}
              >
                أعلى نسبة استهلاك (PEAK)
              </text>
            </RadialBarChart>
          </ResponsiveContainer>
        </div>

        {/* Telemetry Footer Cards */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(3, 1fr)',
          gap: '8px',
          paddingTop: '12px',
          borderTop: '1px solid var(--border-color)',
          marginTop: 'auto'
        }}>
          <div style={{ background: 'var(--bg-overlay)', padding: '8px 10px', borderRadius: '6px', textAlign: 'center' }}>
            <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '4px' }}>
              <Activity size={11} /> عملاء نشطون
            </div>
            <div className="mono" style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)', marginTop: '2px' }}>
              {activeBuckets}
            </div>
          </div>

          <div style={{ background: 'var(--bg-overlay)', padding: '8px 10px', borderRadius: '6px', textAlign: 'center' }}>
            <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '4px' }}>
              <ShieldAlert size={11} /> تنبيهات الحظر
            </div>
            <div className="mono" style={{ fontSize: '0.95rem', fontWeight: 600, color: criticalCount > 0 ? '#ff4d6a' : 'var(--success)', marginTop: '2px' }}>
              {criticalCount}
            </div>
          </div>

          <div style={{ background: 'var(--bg-overlay)', padding: '8px 10px', borderRadius: '6px', textAlign: 'center' }}>
            <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '4px' }}>
              <Cpu size={11} /> حالة المحرك
            </div>
            <div className="mono" style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--accent)', marginTop: '2px' }}>
              TokenBucket
            </div>
          </div>
        </div>
      </div>
    </SectionCard>
  );
}

