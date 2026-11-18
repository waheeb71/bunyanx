import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip } from 'recharts';
import { ArrowUpRight, ArrowDownRight, ExternalLink, X, Activity } from 'lucide-react';

const ROUTE_MAP = {
  'إجمالي التنبيهات': '/ids-ips',
  'التنبيهات الحرجة': '/ids-ips',
  'الحوادث النشطة': '/response',
  'الأصول المراقبة': '/netops',
  'النقاط الطرفية': '/netops',
  'المستخدمون': '/users',
};

// Stable object constants — defined outside component to avoid new references on every render
const CHART_MARGIN_ZERO = { top: 0, bottom: 0, left: 0, right: 0 };
const CHART_MARGIN_MODAL = { top: 10, right: 10, left: -20, bottom: 0 };
const TOOLTIP_CONTENT_STYLE = {
  background: '#0f172a',
  border: '1px solid rgba(255,255,255,0.1)',
  borderRadius: 8,
};

export default function StatCard({ title, value, change, isPositive, trendData, color, icon: Icon }) {
  const navigate = useNavigate();
  const [showDetailModal, setShowDetailModal] = useState(false);

  const glowColor = {
    red: 'rgba(239, 68, 68, 0.12)',
    orange: 'rgba(249, 115, 22, 0.12)',
    green: 'rgba(16, 185, 129, 0.12)',
    blue: 'rgba(59, 130, 246, 0.12)',
    purple: 'rgba(139, 92, 246, 0.12)',
    yellow: 'rgba(245, 158, 11, 0.12)',
    cyan: 'rgba(6, 182, 212, 0.12)',
  }[color] || 'rgba(255, 255, 255, 0.04)';

  const strokeColor = {
    red: '#ef4444',
    orange: '#f97316',
    green: '#10b981',
    blue: '#3b82f6',
    purple: '#8b5cf6',
    yellow: '#f5980b',
    cyan: '#06b6d4',
  }[color] || '#ffffff';

  const targetRoute = ROUTE_MAP[title] || '/ids-ips';

  return (
    <>
      <motion.div
        className="pro-stat-card"
        whileHover={{ y: -3 }}
        onClick={() => setShowDetailModal(true)}
        style={{
          background: `linear-gradient(135deg, rgba(16, 20, 36, 0.75) 0%, rgba(10, 14, 26, 0.85) 100%)`,
          border: '1px solid rgba(255, 255, 255, 0.05)',
          boxShadow: `0 8px 32px 0 rgba(0, 0, 0, 0.35), inset 0 0 14px ${glowColor}`,
          cursor: 'pointer',
        }}
      >
        <div className="pro-stat-card-header">
          <span className="pro-stat-card-title">{title}</span>
          <div className="pro-stat-card-icon-wrapper" style={{ background: glowColor }}>
            <Icon size={15} style={{ color: strokeColor }} />
          </div>
        </div>

        <div className="pro-stat-card-body">
          <h3 className="pro-stat-card-value">{value}</h3>
          <div className="pro-stat-card-badge-wrapper">
            <div className={`pro-stat-card-badge ${isPositive ? 'positive' : 'negative'}`}>
              {isPositive ? <ArrowUpRight size={11} /> : <ArrowDownRight size={11} />}
              <span>{change}</span>
            </div>
            <span className="pro-stat-card-subtext">آخر 24 ساعة</span>
          </div>
        </div>

        {trendData && trendData.length > 0 && (
          <div className="pro-stat-card-sparkline">
            <ResponsiveContainer width="100%" height={34}>
              <AreaChart data={trendData} margin={CHART_MARGIN_ZERO}>
                <defs>
                  <linearGradient id={`grad-${(title || 'stat').replace(/\s+/g, '')}`} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor={strokeColor} stopOpacity={0.2} />
                    <stop offset="100%" stopColor={strokeColor} stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <Area
                  type="monotone"
                  dataKey="val"
                  stroke={strokeColor}
                  strokeWidth={1.5}
                  fill={`url(#grad-${(title || 'stat').replace(/\s+/g, '')})`}
                  dot={false}
                  isAnimationActive={false}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}
      </motion.div>

      {/* ── Stat Card Details Modal ── */}
      <AnimatePresence>
        {showDetailModal && (
          <div className="map-modal-backdrop" onClick={() => setShowDetailModal(false)}>
            <motion.div
              className="map-filter-modal"
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              onClick={e => e.stopPropagation()}
              dir="rtl"
            >
              <div className="modal-hdr">
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Icon size={18} style={{ color: strokeColor }} />
                  <span style={{ color: '#fff', fontWeight: 800, fontSize: '0.95rem' }}>تحليل مؤشر: {title}</span>
                </div>
                <button className="close-btn" onClick={() => setShowDetailModal(false)}><X size={15} /></button>
              </div>

              <div className="modal-body" style={{ padding: '16px 20px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                  <div>
                    <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>القيمة الحالية المسجلة:</span>
                    <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#fff', fontFamily: 'JetBrains Mono, monospace' }}>{value}</div>
                  </div>
                  <div className={`pro-stat-card-badge ${isPositive ? 'positive' : 'negative'}`} style={{ fontSize: '0.85rem', padding: '4px 10px' }}>
                    {isPositive ? <ArrowUpRight size={14} /> : <ArrowDownRight size={14} />}
                    <span>{change} مقارنة باليوم السابق</span>
                  </div>
                </div>

                {trendData && trendData.length > 0 && (
                  <div style={{ height: 160, background: 'rgba(15,23,42,0.6)', borderRadius: 10, padding: 10, border: '1px solid rgba(255,255,255,0.05)', marginBottom: 20 }}>
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={trendData} margin={CHART_MARGIN_MODAL}>
                        <defs>
                          <linearGradient id={`modal-grad-${(title || 'stat').replace(/\s+/g, '')}`} x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor={strokeColor} stopOpacity={0.4} />
                            <stop offset="100%" stopColor={strokeColor} stopOpacity={0.0} />
                          </linearGradient>
                        </defs>
                        <XAxis dataKey="id" stroke="rgba(255,255,255,0.2)" fontSize={10} />
                        <YAxis stroke="rgba(255,255,255,0.2)" fontSize={10} />
                        <Tooltip contentStyle={TOOLTIP_CONTENT_STYLE} />
                        <Area type="monotone" dataKey="val" stroke={strokeColor} strokeWidth={2} fill={`url(#modal-grad-${(title || 'stat').replace(/\s+/g, '')})`} />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                )}

                <div style={{ display: 'flex', gap: 10 }}>
                  <button
                    className="modal-btn-primary"
                    onClick={() => {
                      setShowDetailModal(false);
                      navigate(targetRoute);
                    }}
                  >
                    <ExternalLink size={15} />
                    الانتقال لوحدة التحكم المختصة ({title})
                  </button>

                  <button
                    className="modal-btn-secondary"
                    onClick={() => setShowDetailModal(false)}
                  >
                    إغلاق
                  </button>
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </>
  );
}
