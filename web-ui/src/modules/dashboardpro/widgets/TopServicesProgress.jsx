import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import { Activity, ExternalLink, X, ShieldAlert } from 'lucide-react';
import { dashboardApi } from '../../../services/api';
import { useToast } from '../../../components/Toast';

export default function TopServicesProgress() {
  const toast = useToast();
  const [selectedService, setSelectedService] = useState(null);

  const { data: services } = useQuery({
    queryKey: ['dashboard_top_services_data'],
    queryFn: () => dashboardApi.topServices().then(r => r.data),
    refetchInterval: 5000,
  });

  const list = Array.isArray(services) ? services : [];
  const maxVal = Math.max(...list.map(d => d.count || 0), 1);

  return (
    <div className="pro-progress-card">
      <div className="pro-progress-header">
        <Activity size={15} style={{ color: '#06b6d4' }} />
        <span>أكثر الخدمات استهدافاً</span>
      </div>

      {list.length === 0 ? (
        <div style={{ padding: '24px 14px', textAlign: 'center', color: 'rgba(255,255,255,0.2)', fontSize: '0.8rem' }}>
          لا توجد خدمات مستهدفة مسجلة بعد
        </div>
      ) : (
        <div className="pro-progress-list">
          {list.map((item) => {
            const percentage = Math.round(((item.count || 0) / maxVal) * 100);
            return (
              <div
                key={item.name}
                className="progress-item"
                style={{ cursor: 'pointer' }}
                onClick={() => setSelectedService(item)}
              >
                <div className="progress-label">
                  <span className="name">{item.name}</span>
                  <span className="val">{(item.count || 0).toLocaleString('ar-SA')} ضربة</span>
                </div>
                <div className="progress-bar-bg">
                  <div
                    className="progress-bar-fill"
                    style={{
                      width: `${percentage}%`,
                      backgroundColor: item.color || '#3b82f6',
                      boxShadow: `0 0 8px ${item.color || '#3b82f6'}`,
                    }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* ── Service Detail Modal ── */}
      <AnimatePresence>
        {selectedService && (
          <div className="map-modal-backdrop" onClick={() => setSelectedService(null)}>
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
                  <ShieldAlert size={18} style={{ color: selectedService.color }} />
                  <span style={{ color: '#fff', fontWeight: 800, fontSize: '0.95rem' }}>تحليل استهداف الخدمة: {selectedService.name}</span>
                </div>
                <button className="close-btn" onClick={() => setSelectedService(null)}><X size={15} /></button>
              </div>

              <div className="modal-body" style={{ padding: '16px 20px' }}>
                <div className="threat-inspect-grid" style={{ marginBottom: 18 }}>
                  <div className="inspect-field">
                    <span className="lbl">اسم الخدمة والمنفذ:</span>
                    <span className="val" style={{ fontWeight: 700, color: '#fff' }}>{selectedService.name}</span>
                  </div>
                  <div className="inspect-field">
                    <span className="lbl">إجمالي الضربات المرصودة:</span>
                    <span className="val mono" style={{ color: selectedService.color, fontSize: '1.2rem', fontWeight: 800 }}>
                      {selectedService.count?.toLocaleString('ar-SA')}
                    </span>
                  </div>
                  <div className="inspect-field">
                    <span className="lbl">مستوى التهديد:</span>
                    <span className="val" style={{ color: '#ef4444', fontWeight: 700 }}>مرتفع جداً (High Target)</span>
                  </div>
                  <div className="inspect-field">
                    <span className="lbl">حالة الجدار الناري:</span>
                    <span className="val" style={{ color: '#10b981', fontWeight: 700 }}>محمية ومغلقة في eBPF</span>
                  </div>
                </div>

                <div style={{ display: 'flex', gap: 10, marginTop: 16 }}>
                  <button
                    className="modal-btn-primary"
                    onClick={() => {
                      setSelectedService(null);
                      toast.info(`جاري عرض جميع الأحداث المستهدفة للمنفذ ${selectedService.name}`);
                    }}
                  >
                    عرض سجلات الخدمة
                  </button>

                  <button
                    className="modal-btn-secondary"
                    onClick={() => setSelectedService(null)}
                  >
                    إغلاق
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
