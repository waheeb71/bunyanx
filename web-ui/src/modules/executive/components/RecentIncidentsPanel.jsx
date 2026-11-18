import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { AlertTriangle, ChevronLeft, ShieldAlert, Filter, Clock, Server, ArrowUpRight } from 'lucide-react';

const SEV_COLORS = {
  critical: '#ff4d6a',
  high: '#ffab40',
  medium: '#00c8ff',
  low: '#00e676',
  info: '#818cf8',
};

const SEV_LABELS = {
  critical: 'حرج جداً',
  high: 'عالٍ',
  medium: 'متوسط',
  low: 'منخفض',
  info: 'معلوماتي',
};

const formatTimeAgo = (isoString) => {
  if (!isoString) return 'منذ قليل';
  const diffMs = Date.now() - new Date(isoString).getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffMins < 1) return 'الآن';
  if (diffMins < 60) return `منذ ${diffMins} دقيقة`;
  if (diffHours < 24) return `منذ ${diffHours} ساعة`;
  return `منذ ${diffDays} يوم`;
};

export default function RecentIncidentsPanel({ incidents = [], onSelectIncident }) {
  const [filterSev, setFilterSev] = useState('all');

  const filteredIncidents = incidents.filter((inc) => {
    if (filterSev === 'all') return true;
    if (filterSev === 'active') return inc.status !== 'closed' && inc.status !== 'contained';
    return inc.severity === filterSev;
  });

  return (
    <motion.div
      className="exec-panel exec-incidents-panel"
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, delay: 0.28 }}
    >
      <div className="exec-panel-header">
        <div className="exec-panel-title-group">
          <div className="exec-panel-icon-wrap" style={{ background: 'rgba(255, 77, 106, 0.12)', color: '#ff4d6a' }}>
            <AlertTriangle size={18} />
          </div>
          <div>
            <h3 className="exec-panel-title">أحدث الحوادث والتهديدات الأمنية المسجلة</h3>
            <span className="exec-panel-sub">رصد فوري لأهم البلاغات والأنشطة المشبوهة عبر الشبكة</span>
          </div>
        </div>

        {/* Severity Filter Tabs */}
        <div className="exec-inc-filter-group">
          <button
            className={`exec-inc-filter-btn ${filterSev === 'all' ? 'active' : ''}`}
            onClick={() => setFilterSev('all')}
          >
            الكل ({incidents.length})
          </button>
          <button
            className={`exec-inc-filter-btn critical ${filterSev === 'critical' ? 'active' : ''}`}
            onClick={() => setFilterSev('critical')}
          >
            حرجة
          </button>
          <button
            className={`exec-inc-filter-btn high ${filterSev === 'high' ? 'active' : ''}`}
            onClick={() => setFilterSev('high')}
          >
            عالية
          </button>
          <button
            className={`exec-inc-filter-btn active-state ${filterSev === 'active' ? 'active' : ''}`}
            onClick={() => setFilterSev('active')}
          >
            النشطة
          </button>
        </div>
      </div>

      <div className="exec-incidents-list">
        {filteredIncidents.length === 0 ? (
          <div className="exec-incidents-empty">
            <div className="exec-inc-empty-icon">
              <ShieldAlert size={32} />
            </div>
            <div className="exec-inc-empty-title">لا توجد حوادث أمنية مسجلة في هذا التصنيف</div>
            <div className="exec-inc-empty-sub">المنظومة تعمل في وضع الحماية الكامل والاستقرار</div>
          </div>
        ) : (
          filteredIncidents.slice(0, 5).map((inc) => {
            const sevColor = SEV_COLORS[inc.severity] || '#818cf8';
            return (
              <div
                key={inc.id}
                className="exec-incident-row clickable"
                onClick={() => onSelectIncident && onSelectIncident(inc)}
              >
                <div
                  className="exec-inc-dot"
                  style={{ background: sevColor, boxShadow: `0 0 10px ${sevColor}88` }}
                />

                <div className="exec-inc-main-content">
                  <div className="exec-inc-title-row">
                    <span className="exec-inc-title">{inc.title || 'تهديد أمني مكتشف'}</span>
                    <span className="exec-inc-id-tag" dir="ltr">#{inc.id}</span>
                  </div>

                  <div className="exec-inc-meta">
                    <span className="exec-inc-meta-item">
                      <Clock size={11} /> {formatTimeAgo(inc.ts || inc.timestamp)}
                    </span>
                    <span className="exec-inc-meta-item">
                      <Server size={11} /> وحدة: {inc.module || 'مركزي'}
                    </span>
                  </div>
                </div>

                <div className="exec-inc-end-group">
                  <span
                    className="exec-sev-badge"
                    style={{
                      color: sevColor,
                      borderColor: `${sevColor}44`,
                      background: `${sevColor}15`,
                    }}
                  >
                    {SEV_LABELS[inc.severity] || inc.severity}
                  </span>

                  <span className="exec-status-pill">
                    {inc.status === 'open' ? 'نشط' : inc.status === 'investigating' ? 'قيد التحقيق' : inc.status === 'contained' ? 'محتوى' : 'مغلق'}
                  </span>

                  <div className="exec-inc-action-icon">
                    <ChevronLeft size={16} />
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </motion.div>
  );
}
