import React from 'react';
import { motion } from 'framer-motion';
import { Globe, Shield, Sparkles } from 'lucide-react';
import { RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis, ResponsiveContainer } from 'recharts';

export default function MaturityRadarPanel({ radarData = [] }) {
  // Compute overall average maturity
  const avgMaturity = radarData.length > 0
    ? Math.round(radarData.reduce((acc, curr) => acc + (curr.A || 0), 0) / radarData.length)
    : 85;

  return (
    <motion.div
      className="exec-panel exec-radar-panel"
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, delay: 0.2 }}
    >
      <div className="exec-panel-header">
        <div className="exec-panel-title-group">
          <div className="exec-panel-icon-wrap" style={{ background: 'rgba(0, 200, 255, 0.12)', color: '#00c8ff' }}>
            <Globe size={18} />
          </div>
          <div>
            <h3 className="exec-panel-title">مخطط النضج الأمني الشامل</h3>
            <span className="exec-panel-sub">تقييم توازن وتكامل وحدات الحماية المؤسسية</span>
          </div>
        </div>

        <div className="exec-maturity-badge">
          <Sparkles size={13} />
          <span>{avgMaturity}% نضج تشغيلي</span>
        </div>
      </div>

      <div className="exec-radar-chart-wrap">
        <ResponsiveContainer width="100%" height={230}>
          <RadarChart data={radarData} margin={{ top: 10, right: 25, bottom: 10, left: 25 }}>
            <PolarGrid stroke="rgba(255, 255, 255, 0.08)" />
            <PolarAngleAxis
              dataKey="subject"
              tick={{ fill: 'rgba(255, 255, 255, 0.65)', fontSize: 11, fontFamily: 'Cairo, sans-serif', fontWeight: 600 }}
            />
            <PolarRadiusAxis
              angle={30}
              domain={[0, 100]}
              tick={{ fill: 'rgba(255, 255, 255, 0.25)', fontSize: 9, fontFamily: 'JetBrains Mono, monospace' }}
              axisLine={false}
            />
            <Radar
              name="نسبة الجاهزية والنضج"
              dataKey="A"
              stroke="#00c8ff"
              fill="#00c8ff"
              fillOpacity={0.25}
              strokeWidth={2.5}
            />
          </RadarChart>
        </ResponsiveContainer>
      </div>

      <div className="exec-radar-footer-grid">
        {radarData.slice(0, 4).map((item) => (
          <div key={item.subject} className="exec-radar-footer-item">
            <span className="exec-radar-footer-label">{item.subject}</span>
            <span className="exec-radar-footer-val" style={{ color: item.A >= 80 ? '#00e676' : '#00c8ff' }}>
              {item.A}%
            </span>
          </div>
        ))}
      </div>
    </motion.div>
  );
}
