import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Printer, Shield, CheckCircle, AlertTriangle, Globe, Lock, FileText, CheckCircle2 } from 'lucide-react';

export default function ExecutiveReportModal({
  isOpen,
  onClose,
  securityScore = 88,
  uptimeStr = '12 يوم 4 ساعات',
  activeIncidents = [],
  blockRate = 99.4,
  radarData = [],
  scoreBreakdown = [],
  sysData = {},
}) {
  if (!isOpen) return null;

  const handlePrint = () => {
    window.print();
  };

  const today = new Date().toLocaleDateString('ar-SA', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });

  return (
    <AnimatePresence>
      <div className="exec-modal-backdrop" onClick={onClose}>
        <motion.div
          className="exec-modal-card exec-report-card"
          initial={{ opacity: 0, scale: 0.94 }}
          animate={{ opacity: 1, scale: 1 }}
          exit={{ opacity: 0, scale: 0.94 }}
          transition={{ duration: 0.2 }}
          onClick={(e) => e.stopPropagation()}
          dir="rtl"
        >
          {/* Header Actions (Excluded on Print) */}
          <div className="exec-report-header no-print">
            <div className="exec-report-header-info">
              <div className="exec-panel-icon-wrap" style={{ background: 'rgba(0, 200, 255, 0.15)', color: '#00c8ff' }}>
                <FileText size={20} />
              </div>
              <div>
                <h3>التقرير التنفيذي الشامل للأمن السيبراني</h3>
                <p>موجز رسمي للإدارة العليا ومجلس الإدارة — مستوى C-Suite / CISO</p>
              </div>
            </div>
            <div className="exec-report-actions">
              <button className="exec-btn exec-btn-primary" onClick={handlePrint}>
                <Printer size={16} /> طباعة / تصدير PDF
              </button>
              <button className="exec-modal-close-btn" onClick={onClose} title="إغلاق">
                <X size={18} />
              </button>
            </div>
          </div>

          {/* Printable Official Briefing Sheet */}
          <div className="exec-printable-report" id="exec-printable-area">
            {/* Brand Header */}
            <div className="report-brand-header">
              <div className="report-logo">
                <div className="report-logo-icon">
                  <Shield size={32} color="#00c8ff" />
                </div>
                <div>
                  <h2>منصة bunyanx enterprise_ngfw السيبرانية</h2>
                  <p>Executive Cybersecurity Intelligence & SOC Governance Report</p>
                </div>
              </div>
              <div className="report-meta">
                <div className="report-classification-badge">تصنيف أمني: وثيقة تنفيذية معتمدة</div>
                <div className="report-date-text">تاريخ الإصدار: <strong>{today}</strong></div>
                <div className="report-status-text">
                  حالة المنظومة: <strong>{sysData?.status === 'operational' ? 'تشغيلي ومستقر 🟢' : 'تحت المراقبة'}</strong>
                </div>
              </div>
            </div>

            <hr className="report-divider" />

            {/* Section 1: Security Score & Executive Posture */}
            <div className="report-section">
              <h3 className="report-section-title">
                <Lock size={16} /> مؤشر الوضع الأمني العام (Executive Security Score)
              </h3>
              <div className="report-score-box">
                <div className="report-score-val" style={{ color: securityScore >= 80 ? '#00e676' : '#ffab40' }}>
                  {securityScore} <span style={{ fontSize: '1rem', color: 'rgba(255,255,255,0.4)' }}>/ 100</span>
                </div>
                <div className="report-score-desc">
                  تم احتساب درجة التقييم استناداً إلى كفاءة 8 وحدات حماية مركزية، ومعدل الاستجابة اللحظية للتهديدات
                  ومنع محاولات الاختراق، مع تحقيق امتثال متقدم لضوابط الأمن السيبراني المؤسسية.
                </div>
              </div>
            </div>

            {/* Section 2: Executive KPI Matrix */}
            <div className="report-section">
              <h3 className="report-section-title">
                <Shield size={16} /> المؤشرات التنفيذية الرئيسية (Key Performance Indicators)
              </h3>
              <div className="report-grid">
                <div className="report-kpi-item">
                  <span className="report-kpi-label">زمن التشغيل المتواصل</span>
                  <span className="report-kpi-value">{uptimeStr}</span>
                </div>
                <div className="report-kpi-item">
                  <span className="report-kpi-label">معدل حجب التهديدات التلقائي</span>
                  <span className="report-kpi-value" style={{ color: '#00e676' }}>{blockRate}%</span>
                </div>
                <div className="report-kpi-item">
                  <span className="report-kpi-label">الحوادث الأمنية النشطة</span>
                  <span className="report-kpi-value" style={{ color: activeIncidents.length > 0 ? '#ff4d6a' : '#00e676' }}>
                    {activeIncidents.length}
                  </span>
                </div>
                <div className="report-kpi-item">
                  <span className="report-kpi-label">الاتصالات النشطة حالياً</span>
                  <span className="report-kpi-value">{(sysData?.active_connections || 0).toLocaleString()}</span>
                </div>
              </div>
            </div>

            {/* Section 3: Module Maturity & Preparedness Table */}
            <div className="report-section">
              <h3 className="report-section-title">
                <Globe size={16} /> جاهزية ونضج طبقات الحماية المركزية
              </h3>
              <table className="report-table">
                <thead>
                  <tr>
                    <th>الوحدة الأمنية</th>
                    <th>نسبة النضج التشغيلي</th>
                    <th>مستوى الحصانة</th>
                    <th>الحالة التشغيلية</th>
                  </tr>
                </thead>
                <tbody>
                  {radarData.map((item) => (
                    <tr key={item.subject}>
                      <td style={{ fontWeight: 600 }}>{item.subject}</td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                          <div className="report-progress-bar">
                            <div className="report-progress-fill" style={{ width: `${item.A}%` }} />
                          </div>
                          <span style={{ fontFamily: 'JetBrains Mono, monospace' }}>{item.A}%</span>
                        </div>
                      </td>
                      <td>
                        <span style={{ color: item.A >= 80 ? '#00e676' : '#00c8ff', fontWeight: 600 }}>
                          {item.A >= 85 ? 'ممتاز' : item.A >= 70 ? 'جيد جداً' : 'مقبول'}
                        </span>
                      </td>
                      <td>
                        <span style={{ color: '#00e676', display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                          <CheckCircle2 size={13} /> مُفعّل ويعمل
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Official Sign-off Footer */}
            <div className="report-footer-signoff">
              <div>
                <p>إعداد: <strong>نظام التحليل التنفيذي الآلي bunyanx SOC Intelligence</strong></p>
                <p>رمز التوثيق المعتمد: CERT-SOC-EXEC-2026-A1</p>
              </div>
              <div style={{ textAlign: 'left' }}>
                <p>الاعتماد: <strong>رئيس قطاع الأمن السيبراني (CISO)</strong></p>
                <p>التاريخ: {today}</p>
              </div>
            </div>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}
