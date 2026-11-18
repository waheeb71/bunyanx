import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Target, ShieldCheck, ShieldAlert, AlertTriangle, CheckCircle2 } from 'lucide-react';

/* ── Luxury Animated Risk Gauge ────────────────────────── */
function RiskGauge({ score = 88 }) {
  const [animated, setAnimated] = useState(0);

  useEffect(() => {
    const timer = setTimeout(() => setAnimated(score), 300);
    return () => clearTimeout(timer);
  }, [score]);

  const r = 80;
  const cx = 110;
  const cy = 100;
  const circumference = Math.PI * r; // Semi-circle arc length
  const dashOffset = circumference * (1 - Math.min(100, Math.max(0, animated)) / 100);

  const getStatus = (s) => {
    if (s >= 85) return { color: '#00e676', label: 'وضع أمني ممتاز', sub: 'محمي بالكامل وفق أفضل الممارسات', icon: ShieldCheck };
    if (s >= 70) return { color: '#00c8ff', label: 'مستوى أمان مستقر', sub: 'جميع الدفاعات الأساسية نشطة', icon: ShieldCheck };
    if (s >= 50) return { color: '#ffab40', label: 'يتطلب انتباه تشغيلي', sub: 'هناك وحدات غير مفعلة أو حوادث نشطة', icon: AlertTriangle };
    return { color: '#ff4d6a', label: 'وضع أمني حرج', sub: 'تهديدات نشطة تتطلب تدخلاً فورياً', icon: ShieldAlert };
  };

  const status = getStatus(score);
  const StatusIcon = status.icon;

  return (
    <div className="exec-gauge-container">
      <div className="exec-gauge-svg-wrap">
        <svg width="220" height="125" viewBox="0 0 220 125" className="exec-gauge-svg">
          <defs>
            <linearGradient id="gaugeBgGrad" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="rgba(255, 77, 106, 0.2)" />
              <stop offset="50%" stopColor="rgba(255, 171, 64, 0.2)" />
              <stop offset="100%" stopColor="rgba(0, 230, 118, 0.2)" />
            </linearGradient>
            <linearGradient id="gaugeActiveGrad" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#ff4d6a" />
              <stop offset="45%" stopColor="#ffab40" />
              <stop offset="75%" stopColor="#00c8ff" />
              <stop offset="100%" stopColor="#00e676" />
            </linearGradient>
            <filter id="gaugeGlow" x="-20%" y="-20%" width="140%" height="140%">
              <feDropShadow dx="0" dy="0" stdDeviation="4" floodColor={status.color} floodOpacity="0.4" />
            </filter>
          </defs>

          {/* Background Track */}
          <path
            d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
            fill="none"
            stroke="rgba(255, 255, 255, 0.07)"
            strokeWidth="14"
            strokeLinecap="round"
          />

          {/* Active Progress Arc with Glow */}
          <path
            d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
            fill="none"
            stroke="url(#gaugeActiveGrad)"
            strokeWidth="14"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={dashOffset}
            filter="url(#gaugeGlow)"
            style={{ transition: 'stroke-dashoffset 1.4s cubic-bezier(0.34, 1.56, 0.64, 1)' }}
          />

          {/* Scale Markers */}
          <text x={cx - r + 4} y={cy + 18} fill="rgba(255,255,255,0.3)" fontSize="10" fontFamily="JetBrains Mono, monospace" textAnchor="middle">0</text>
          <text x={cx} y={cy - r + 8} fill="rgba(255,255,255,0.3)" fontSize="10" fontFamily="JetBrains Mono, monospace" textAnchor="middle">50</text>
          <text x={cx + r - 4} y={cy + 18} fill="rgba(255,255,255,0.3)" fontSize="10" fontFamily="JetBrains Mono, monospace" textAnchor="middle">100</text>
        </svg>

        {/* Center Score Readout */}
        <div className="exec-gauge-center-val">
          <span className="exec-gauge-number" style={{ color: status.color }}>
            {score}
          </span>
          <span className="exec-gauge-max">/ 100</span>
        </div>
      </div>

      <div className="exec-gauge-posture-badge" style={{ color: status.color, background: `${status.color}15`, borderColor: `${status.color}35` }}>
        <StatusIcon size={14} />
        <span>{status.label}</span>
      </div>

      <div className="exec-gauge-subtext">
        {status.sub}
      </div>
    </div>
  );
}

export default function RiskPanel({ securityScore = 88, scoreBreakdown = [] }) {
  return (
    <motion.div
      className="exec-panel exec-risk-panel"
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, delay: 0.1 }}
    >
      <div className="exec-panel-header">
        <div className="exec-panel-title-group">
          <div className="exec-panel-icon-wrap" style={{ background: 'rgba(0, 200, 255, 0.12)', color: '#00c8ff' }}>
            <Target size={18} />
          </div>
          <div>
            <h3 className="exec-panel-title">مؤشر الوضع الأمني العام (Security Score)</h3>
            <span className="exec-panel-sub">تقييم شامل لحصانة المنظومة وجاهزية طبقات الدفاع</span>
          </div>
        </div>
      </div>

      <RiskGauge score={securityScore} />

      <div className="exec-score-breakdown-box">
        <div className="exec-breakdown-header">
          <span>تفصيل درجة التقييم حسب المحاور الأمنية</span>
          <span className="exec-breakdown-sub">الأداء التشغيلي</span>
        </div>

        <div className="exec-breakdown-list">
          {scoreBreakdown.map((item) => {
            const isGood = item.v >= 80;
            const barColor = item.v >= 80 ? '#00e676' : item.v >= 65 ? '#00c8ff' : '#ffab40';
            return (
              <div key={item.label} className="exec-breakdown-row">
                <div className="exec-breakdown-info">
                  <span className="exec-breakdown-label">{item.label}</span>
                  <span className="exec-breakdown-val" style={{ color: barColor }}>{item.v}%</span>
                </div>
                <div className="exec-breakdown-bar-wrap">
                  <div
                    className="exec-breakdown-bar-fill"
                    style={{
                      width: `${item.v}%`,
                      background: `linear-gradient(90deg, ${barColor}88, ${barColor})`,
                    }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </motion.div>
  );
}
