import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { AlertCircle, Shield, User, HardDrive, ExternalLink, X, Ban, CheckCircle2, RefreshCw } from 'lucide-react';
import { responseApi } from '../../../services/api';
import { useToast } from '../../../components/Toast';

const SEV_AR = {
  critical: 'حرج',
  high: 'عالي',
  medium: 'متوسط',
  low: 'منخفض',
};

export default function ActiveIncidentsList({ incidents }) {
  const toast = useToast();
  const navigate = useNavigate();
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [isUpdating, setIsUpdating] = useState(false);

  const getSeverityBadgeClass = (sev) => {
    return {
      critical: 'critical',
      high: 'high',
      medium: 'medium',
      low: 'low'
    }[String(sev || '').toLowerCase()] || 'medium';
  };

  const list = Array.isArray(incidents) ? incidents : [];

  // Status Change Handler
  const handleUpdateStatus = async (statusVal) => {
    if (!selectedIncident) return;
    const incId = selectedIncident.id || 'INC-0001';
    setIsUpdating(true);
    try {
      await responseApi.updateStatus(incId, statusVal);
      toast.success(`تم تحديث حالة الحادثة ${incId} إلى ${statusVal}`, 'تحديث الحادثة');
      setSelectedIncident(null);
    } catch (err) {
      toast.error(`تعذر تحديث الحادثة: ${err.message || 'خطأ في النظام'}`);
    } finally {
      setIsUpdating(false);
    }
  };

  // Block Source IP Handler
  const handleBlockIp = async () => {
    if (!selectedIncident) return;
    const incId = selectedIncident.id || 'INC-0001';
    setIsUpdating(true);
    try {
      const targetIp = selectedIncident.source_ip || selectedIncident.src_ip || selectedIncident.ip;
      await responseApi.triggerAction(incId, { action: 'block_ip', ip: targetIp, label: `Block Source IP ${targetIp || incId}` });
      toast.success(`تم حظر IP المتسبب بالحادثة ${targetIp || incId} فوراً`, 'تم الحظر');
      setSelectedIncident(null);
    } catch (err) {
      toast.error(`تعذر حظر IP: ${err.message || 'خطأ في النظام'}`);
    } finally {
      setIsUpdating(false);
    }
  };

  return (
    <div className="pro-incidents-card">
      <div className="pro-incidents-header">
        <div className="title">
          <AlertCircle size={16} className="text-amber-500" />
          <span>الحوادث النشطة (SOC Queue)</span>
        </div>
        <Link to="/response" className="view-all-link">
          عرض الكل ←
        </Link>
      </div>

      {list.length === 0 ? (
        <div style={{ padding: '40px 16px', textAlign: 'center', color: 'rgba(255,255,255,0.2)', fontSize: '0.82rem' }}>
          لا توجد حوادث أمنية نشطة مسجلة حالياً
        </div>
      ) : (
        <div className="pro-incidents-list">
          {list.map((inc, i) => {
            const sevKey = String(inc.severity || 'medium').toLowerCase();
            return (
              <motion.div
                key={inc.id || i}
                className="incident-item"
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.04 }}
                style={{ cursor: 'pointer' }}
                onClick={() => setSelectedIncident(inc)}
              >
                <div className="incident-left">
                  <div className={`incident-icon-wrapper ${getSeverityBadgeClass(inc.severity)}`}>
                    <Shield size={15} />
                  </div>
                  <div className="incident-info">
                    <span className="title-text">{inc.title || inc.description}</span>
                    <div className="meta">
                      <span className="id">{inc.id}</span>
                      <span className="dot">•</span>
                      <span className="time">{inc.time || inc.ts || '—'}</span>
                    </div>
                  </div>
                </div>

                <div className="incident-right">
                  <div className="badge-wrapper">
                    <span className={`pro-badge ${getSeverityBadgeClass(inc.severity)}`}>
                      {SEV_AR[sevKey] || sevKey}
                    </span>
                  </div>
                  <div className="stats">
                    <div className="stat">
                      <HardDrive size={11} style={{ color: '#64748b' }} />
                      <span>{inc.assets || 1}</span>
                    </div>
                    <div className="stat">
                      <User size={11} style={{ color: '#64748b' }} />
                      <span>{inc.analyst || 'فريق SOC'}</span>
                    </div>
                  </div>
                </div>
              </motion.div>
            );
          })}
        </div>
      )}

      {/* ── Incident Action Modal ── */}
      <AnimatePresence>
        {selectedIncident && (
          <div className="map-modal-backdrop" onClick={() => setSelectedIncident(null)}>
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
                  <AlertCircle size={18} className="text-amber-500" />
                  <span style={{ color: '#fff', fontWeight: 800, fontSize: '0.95rem' }}>إدارة الحادثة الأمنية: {selectedIncident.id}</span>
                </div>
                <button className="close-btn" onClick={() => setSelectedIncident(null)}><X size={15} /></button>
              </div>

              <div className="modal-body" style={{ padding: '16px 20px' }}>
                <div className="threat-inspect-grid" style={{ marginBottom: 18 }}>
                  <div className="inspect-field">
                    <span className="lbl">وصف الحادثة:</span>
                    <span className="val" style={{ fontWeight: 700, color: '#fff' }}>{selectedIncident.title || selectedIncident.description}</span>
                  </div>
                  <div className="inspect-field">
                    <span className="lbl">مستوى الخطورة:</span>
                    <span className={`pro-badge ${getSeverityBadgeClass(selectedIncident.severity)}`}>
                      {SEV_AR[String(selectedIncident.severity || '').toLowerCase()] || String(selectedIncident.severity || '')}
                    </span>
                  </div>
                  <div className="inspect-field">
                    <span className="lbl">المحلل المسؤول:</span>
                    <span className="val">{selectedIncident.analyst || 'فريق الاستجابة'}</span>
                  </div>
                  <div className="inspect-field">
                    <span className="lbl">الأصول المتأثرة:</span>
                    <span className="val mono">{selectedIncident.assets || 1} أصل</span>
                  </div>
                  <div className="inspect-field">
                    <span className="lbl">الحالة الحالية:</span>
                    <span className="val" style={{ color: '#f59e0b', fontWeight: 700 }}>{selectedIncident.status || 'مفتوحة (Open)'}</span>
                  </div>
                </div>

                <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginBottom: 10, fontWeight: 700 }}>تحديث حالة الحادثة:</div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8, marginBottom: 18 }}>
                  <button
                    className="modal-btn-secondary"
                    disabled={isUpdating}
                    onClick={() => handleUpdateStatus('investigating')}
                  >
                    قيد التحقيق
                  </button>

                  <button
                    className="modal-btn-secondary"
                    disabled={isUpdating}
                    onClick={() => handleUpdateStatus('contained')}
                  >
                    تم الاحتواء
                  </button>

                  <button
                    className="modal-btn-secondary"
                    disabled={isUpdating}
                    onClick={() => handleUpdateStatus('closed')}
                  >
                    إغلاق الحادثة
                  </button>
                </div>

                <div style={{ display: 'flex', gap: 10, marginTop: 16 }}>
                  <button
                    className="modal-btn-danger"
                    disabled={isUpdating}
                    onClick={handleBlockIp}
                  >
                    <Ban size={15} />
                    حظر IP المتسبب
                  </button>

                  <button
                    className="modal-btn-primary"
                    onClick={() => {
                      setSelectedIncident(null);
                      navigate('/response');
                    }}
                  >
                    <ExternalLink size={15} />
                    فتح في مركز الاستجابة
                  </button>
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
