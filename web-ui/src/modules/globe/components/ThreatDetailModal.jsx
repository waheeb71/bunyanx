import { X, Shield, Globe, MapPin, Cpu, Clock, AlertTriangle, CheckCircle2 } from 'lucide-react';
import { useGlobeStore } from '../stores/useGlobeStore';

export function ThreatDetailModal() {
  const selectedThreat = useGlobeStore((s) => s.selectedThreat);
  const setSelectedThreat = useGlobeStore((s) => s.setSelectedThreat);

  if (!selectedThreat) return null;

  const isBlocked = selectedThreat.blocked || selectedThreat.action === 'BLOCK';

  return (
    <div className="gtm-modal-overlay" onClick={() => setSelectedThreat(null)}>
      <div className="gtm-modal-card" onClick={(e) => e.stopPropagation()} dir="rtl">
        {/* Modal Header */}
        <div className="gtm-modal-header">
          <div className="gtm-modal-title-wrap">
            <Shield size={20} className="text-cyan" />
            <h3 className="gtm-modal-title">تفاصيل التهديد الأمني المحلل</h3>
          </div>
          <button
            type="button"
            className="gtm-modal-close-btn"
            onClick={() => setSelectedThreat(null)}
          >
            <X size={18} />
          </button>
        </div>

        {/* Modal Content */}
        <div className="gtm-modal-body">
          {/* Main Hero Card */}
          <div className="gtm-modal-hero">
            <div className="gtm-hero-left">
              <span className="gtm-hero-flag">{selectedThreat.flag || '🌐'}</span>
              <div>
                <h4 className="gtm-hero-ip">{selectedThreat.ip || '0.0.0.0'}</h4>
                <span className="gtm-hero-country">{selectedThreat.country || 'غير معروف'}</span>
              </div>
            </div>
            <div className="gtm-hero-right">
              <span className={`gtm-sev-badge large ${selectedThreat.sev || 'medium'}`}>
                {selectedThreat.sev === 'critical' ? 'حرج جداً' : selectedThreat.sev === 'high' ? 'خطورة مرتفعة' : 'متوسط'}
              </span>
            </div>
          </div>

          {/* Key Value Details Grid */}
          <div className="gtm-modal-grid">
            <div className="gtm-grid-item">
              <span className="gtm-grid-label">نوع التهديد:</span>
              <span className="gtm-grid-value">{selectedThreat.type || 'Intrusion'}</span>
            </div>

            <div className="gtm-grid-item">
              <span className="gtm-grid-label">الهدف المصاب:</span>
              <span className="gtm-grid-value">{selectedThreat.target_ip || '10.0.0.10'}</span>
            </div>

            <div className="gtm-grid-item">
              <span className="gtm-grid-label">إحداثيات المصدر:</span>
              <span className="gtm-grid-value">
                {typeof (selectedThreat.src_lat ?? selectedThreat.srcLat) === 'number'
                  ? `${(selectedThreat.src_lat ?? selectedThreat.srcLat).toFixed(4)}, ${(selectedThreat.src_lng ?? selectedThreat.srcLng)?.toFixed(4)}`
                  : '35.8617, 104.1954'}
              </span>
            </div>

            <div className="gtm-grid-item">
              <span className="gtm-grid-label">الإجراء المتخذ:</span>
              <span className={`gtm-grid-value ${isBlocked ? 'text-green' : 'text-red'}`}>
                {isBlocked ? 'تم الحظر في الجدار الناري' : 'سمح بالمرور — تحت المراقبة'}
              </span>
            </div>

            <div className="gtm-grid-item">
              <span className="gtm-grid-label">وقت الاكتشاف:</span>
              <span className="gtm-grid-value">
                {selectedThreat.time ? new Date(selectedThreat.time).toLocaleString('ar-SA') : 'الآن'}
              </span>
            </div>

            <div className="gtm-grid-item">
              <span className="gtm-grid-label">معرف الحدث:</span>
              <span className="gtm-grid-value font-mono">{selectedThreat.id || 'EVT-98124'}</span>
            </div>
          </div>

          {/* SOC Recommended Action */}
          <div className="gtm-modal-recommendation">
            <h5 className="gtm-rec-title">توصية المحلل الأمني SOC:</h5>
            <p className="gtm-rec-text">
              {isBlocked
                ? 'تم تحييد الخطر بنجاح عبر قاعدة المنع التلقائي. ينصح بمراجعة سجلات الاتصال المرتبطة بـ IP المصدر.'
                : 'تنبيه: التهديد لم يحظر تلقائياً. يُوصى بإضافة IP المصدر إلى قائمة المحظورات السوداء فوراً.'}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default ThreatDetailModal;
