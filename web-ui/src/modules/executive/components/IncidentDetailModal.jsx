import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, AlertTriangle, Shield, Clock, Server, CheckCircle2, ShieldAlert, Cpu, Activity } from 'lucide-react';

const SEV_COLORS = {
  critical: '#ff4d6a',
  high: '#ffab40',
  medium: '#00c8ff',
  low: '#00e676',
  info: '#818cf8',
};

const SEV_LABELS = {
  critical: 'حرج جداً',
  high: 'مرتفع',
  medium: 'متوسط',
  low: 'منخفض',
  info: 'معلومات',
};

export default function IncidentDetailModal({ incident, onClose }) {
  if (!incident) return null;

  const sevColor = SEV_COLORS[incident.severity] || '#818cf8';

  return (
    <AnimatePresence>
      <div className="exec-modal-backdrop" onClick={onClose}>
        <motion.div
          className="exec-modal-card"
          initial={{ opacity: 0, scale: 0.94, y: 15 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.94, y: 15 }}
          transition={{ duration: 0.2 }}
          onClick={(e) => e.stopPropagation()}
          dir="rtl"
        >
          {/* Modal Header */}
          <div className="exec-modal-header">
            <div className="exec-modal-title-group">
              <div className="exec-modal-icon" style={{ background: `${sevColor}18`, color: sevColor }}>
                <AlertTriangle size={22} />
              </div>
              <div>
                <h3 className="exec-modal-title">{incident.title || 'تفاصيل الحادث الأمني'}</h3>
                <span className="exec-modal-subtitle" dir="ltr">معرف الحادث: #{incident.id}</span>
              </div>
            </div>
            <button className="exec-modal-close-btn" onClick={onClose} title="إغلاق">
              <X size={18} />
            </button>
          </div>

          {/* Modal Body */}
          <div className="exec-modal-body">
            {/* Quick Property Grid */}
            <div className="exec-modal-grid">
              <div className="exec-modal-field">
                <span className="exec-field-label">مستوى الخطورة</span>
                <span
                  className="exec-sev-badge"
                  style={{ color: sevColor, borderColor: `${sevColor}44`, background: `${sevColor}15` }}
                >
                  {SEV_LABELS[incident.severity] || incident.severity}
                </span>
              </div>

              <div className="exec-modal-field">
                <span className="exec-field-label">حالة الاستجابة</span>
                <span className="exec-status-badge">
                  {incident.status === 'open' ? 'نشط' : incident.status === 'investigating' ? 'قيد التحقيق' : incident.status === 'contained' ? 'تم الاحتواء' : 'مغلق'}
                </span>
              </div>

              <div className="exec-modal-field">
                <span className="exec-field-label">الوحدة الراصدة</span>
                <span className="exec-field-value">
                  <Server size={14} style={{ color: '#00c8ff' }} /> {incident.module || 'نظام التهديدات المركزية'}
                </span>
              </div>

              <div className="exec-modal-field">
                <span className="exec-field-label">التوقيت الزمني للرصد</span>
                <span className="exec-field-value">
                  <Clock size={14} style={{ color: '#818cf8' }} />
                  {incident.ts ? new Date(incident.ts).toLocaleString('ar-SA') : 'غير محدد'}
                </span>
              </div>
            </div>

            {/* Incident Forensic Overview */}
            <div className="exec-modal-section">
              <h4>التحليل الجنائي وسياق الحدث</h4>
              <p className="exec-modal-desc">
                تم رصد واعتراض هذا النشاط المشبوه آلياً بواسطة محرك الاستخبارات السيبرانية لوحدة{' '}
                <strong>{incident.module || 'منظومة bunyanx enterprise_ngfw'}</strong>. 
                تم تسجيل حزم البيانات ومطابقتها مع مؤشرات الاختراق (IoCs) وقواعد السلوك المشبوه لمنع أي تأثير على استقرار الشبكة والخدمات الحيوية.
              </p>
            </div>

            {/* Tactical Mitigation Steps */}
            <div className="exec-modal-section">
              <h4>إجراءات الاستجابة الموصى بها (CSIRT Actions)</h4>
              <ul className="exec-recommendations-list">
                <li>
                  <CheckCircle2 size={15} style={{ color: '#00e676', flexShrink: 0 }} />
                  <span>تأكيد تفعيل قواعد الحظر على مستوى الجدار الناري والمنافذ المعنية.</span>
                </li>
                <li>
                  <CheckCircle2 size={15} style={{ color: '#00e676', flexShrink: 0 }} />
                  <span>عزل عناوين الـ IP المرتبطة بالنشاط وفحص الاتصالات العكسية.</span>
                </li>
                <li>
                  <CheckCircle2 size={15} style={{ color: '#00e676', flexShrink: 0 }} />
                  <span>تحديث سجلات الاستجابة وتوثيق تقرير الحادث في نظام CERT المركزي.</span>
                </li>
              </ul>
            </div>
          </div>

          {/* Modal Footer */}
          <div className="exec-modal-footer">
            <button className="exec-btn exec-btn-secondary" onClick={onClose}>
              إغلاق النافذة
            </button>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}
