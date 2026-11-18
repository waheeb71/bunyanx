import { motion } from 'framer-motion';
import { Key, RefreshCw, Trash2, X, FileCode, Calendar, ShieldCheck, Hash } from 'lucide-react';
import { usePKIStore } from '../store/usePKIStore';
import { useToast } from '../../../components/Toast';

export function PKICertificateDetail({ cert, daysUntil, onRenew, onRevoke, renewingId, revokingId }) {
  const { setSelectedCertId } = usePKIStore();
  const toast = useToast();

  if (!cert) return null;

  const days = daysUntil(cert.expiry);

  const handleRevoke = () => {
    toast.confirm(
      `هل أنت تأكد من رغبتك في إلغاء شهادة "${cert.cn}"؟ سيتم حذف ملف الشهادة تماماً.`,
      () => onRevoke(cert.id),
      'تأكيد الإلغاء'
    );
  };

  return (
    <motion.div
      className="pki-detail-card"
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: 12 }}
    >
      <div className="pki-detail-header">
        <div className="pki-detail-title-group">
          <Key size={18} style={{ color: '#00d4ff' }} />
          <span>تفاصيل الشهادة الرقمية</span>
          <span className="pki-detail-cn-badge" dir="ltr">{cert.cn}</span>
        </div>
        <button className="pki-detail-close" onClick={() => setSelectedCertId(null)}>
          <X size={16} />
        </button>
      </div>

      <div className="pki-detail-body">
        <div className="pki-detail-grid">
          <div className="pki-detail-item">
            <span className="pki-detail-label">Common Name (CN)</span>
            <span dir="ltr" className="pki-detail-val">{cert.cn}</span>
          </div>

          <div className="pki-detail-item">
            <span className="pki-detail-label">المُصدِر (Issuer)</span>
            <span className="pki-detail-val">{cert.issuer}</span>
          </div>

          <div className="pki-detail-item">
            <span className="pki-detail-label">النوع (Type)</span>
            <span className="pki-detail-val">{cert.type}</span>
          </div>

          <div className="pki-detail-item">
            <span className="pki-detail-label">الاستخدام (Key Usage)</span>
            <span className="pki-detail-val">{cert.usage}</span>
          </div>

          <div className="pki-detail-item">
            <span className="pki-detail-label">تاريخ الإصدار (Not Before)</span>
            <span dir="ltr" className="pki-detail-val">{cert.not_before || 'غير محدد'}</span>
          </div>

          <div className="pki-detail-item">
            <span className="pki-detail-label">تاريخ الانتهاء (Expiry)</span>
            <span dir="ltr" className="pki-detail-val">{cert.expiry}</span>
          </div>

          <div className="pki-detail-item">
            <span className="pki-detail-label">الأيام المتبقية</span>
            <span
              className="pki-detail-val"
              style={{
                color: days < 0 ? '#ff5f5f' : days < 30 ? '#ffc107' : '#28c76f',
                fontFamily: 'Fira Code, monospace',
                fontWeight: 700,
              }}
            >
              {days < 0 ? 'منتهية الصلاحية' : `${days} يوم`}
            </span>
          </div>

          <div className="pki-detail-item">
            <span className="pki-detail-label">الرقم التسلسلي (Serial Number)</span>
            <span dir="ltr" className="pki-detail-val pki-mono">{cert.serial || 'N/A'}</span>
          </div>

          <div className="pki-detail-item pki-detail-full">
            <span className="pki-detail-label">مسار الملف على الخادم (File Path)</span>
            <span dir="ltr" className="pki-detail-val pki-mono">{cert.path || 'N/A'}</span>
          </div>
        </div>
      </div>

      <div className="pki-detail-footer">
        <button
          className="pki-btn pki-btn-primary"
          onClick={() => onRenew(cert.id)}
          disabled={renewingId === cert.id}
        >
          <RefreshCw size={14} className={renewingId === cert.id ? 'animate-spin' : ''} />
          تجديد الشهادة
        </button>

        <button
          className="pki-btn pki-btn-danger"
          onClick={handleRevoke}
          disabled={revokingId === cert.id}
        >
          <Trash2 size={14} />
          إلغاء الشهادة
        </button>
      </div>
    </motion.div>
  );
}
