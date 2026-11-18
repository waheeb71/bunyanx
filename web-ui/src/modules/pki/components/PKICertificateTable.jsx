import { motion } from 'framer-motion';
import {
  ShieldCheck, AlertTriangle, XCircle, CheckCircle2,
  RefreshCw, Trash2, Eye, KeyRound
} from 'lucide-react';
import { ErrorState } from '../../../components/Shared';
import { usePKIStore } from '../store/usePKIStore';
import { useToast } from '../../../components/Toast';

function certStatus(days) {
  if (days < 0) return { label: 'منتهية الصلاحية', color: '#ff5f5f', icon: XCircle };
  if (days < 14) return { label: 'تنتهي قريباً جداً', color: '#ff5f5f', icon: AlertTriangle };
  if (days < 30) return { label: 'تنتهي قريباً', color: '#ffc107', icon: AlertTriangle };
  return { label: 'صالحة', color: '#28c76f', icon: CheckCircle2 };
}

export function PKICertificateTable({
  certs = [],
  isLoading,
  error,
  onRetry,
  onRenew,
  onRevoke,
  renewingId,
  revokingId,
  daysUntil,
}) {
  const toast = useToast();
  const { selectedCertId, setSelectedCertId } = usePKIStore();

  const handleRevokeClick = (cert, e) => {
    e.stopPropagation();
    toast.confirm(
      `هل أنت تأكد من رغبتك في إلغاء شهادة "${cert.cn}"؟ هذا الإجراء سيقوم بحذف ملف الشهادة من الخادم بشكل نهائي.`,
      () => onRevoke(cert.id),
      'تأكيد إلغاء الشهادة'
    );
  };

  const handleRenewClick = (cert, e) => {
    e.stopPropagation();
    onRenew(cert.id);
  };

  if (isLoading) {
    return (
      <div className="pki-loading-state">
        <RefreshCw className="animate-spin" size={24} style={{ color: '#00d4ff' }} />
        <span>جاري فحص وتدقيق مخزن الشهادات الرقمية...</span>
      </div>
    );
  }

  if (error) {
    return <ErrorState message="حدث خطأ أثناء تحميل مخزن الشهادات الرقمية من الخادم" onRetry={onRetry} />;
  }

  if (certs.length === 0) {
    return (
      <div className="pki-empty-state">
        <KeyRound size={36} style={{ color: 'rgba(255,255,255,0.2)', marginBottom: 12 }} />
        <div>لا توجد شهادات رقمية مسجلة تطابق محددات البحث الحالية.</div>
      </div>
    );
  }

  return (
    <div className="pki-table-container">
      <div className="pki-table-header">
        <span>الحالة</span>
        <span>Common Name (CN)</span>
        <span>المُصدِر (Issuer)</span>
        <span>النوع</span>
        <span>الاستخدام</span>
        <span>تاريخ الانتهاء</span>
        <span>الأيام المتبقية</span>
        <span style={{ textAlign: 'left' }}>إجراءات</span>
      </div>

      <div className="pki-cert-list">
        {certs.map((cert, i) => {
          const days = daysUntil(cert.expiry);
          const st = certStatus(days);
          const StatusIcon = st.icon;
          const isSelected = selectedCertId === cert.id;

          return (
            <motion.div
              key={cert.id}
              className={`pki-cert-row ${isSelected ? 'pki-selected' : ''}`}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.02 }}
              onClick={() => setSelectedCertId(isSelected ? null : cert.id)}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <StatusIcon size={16} style={{ color: st.color }} />
              </div>

              <span dir="ltr" className="pki-cn" title={cert.cn}>
                {cert.cn}
              </span>

              <span className="pki-issuer" title={cert.issuer}>
                {cert.issuer}
              </span>

              <div>
                <span className={`pki-type-badge pki-type-${(cert.type || '').toLowerCase().replace(/[^a-z0-9]/g, '')}`}>
                  {cert.type}
                </span>
              </div>

              <span className="pki-usage" title={cert.usage}>
                {cert.usage}
              </span>

              <span dir="ltr" className="pki-expiry">
                {cert.expiry}
              </span>

              <span
                style={{
                  color: st.color,
                  fontFamily: 'Fira Code, monospace',
                  fontSize: '0.8rem',
                  fontWeight: 700,
                }}
              >
                {days < 0 ? 'منتهية' : `${days} يوم`}
              </span>

              <div className="pki-row-actions" onClick={(e) => e.stopPropagation()}>
                <button
                  className="pki-icon-btn"
                  title="عرض التفاصيل الكاملة"
                  onClick={() => setSelectedCertId(isSelected ? null : cert.id)}
                >
                  <Eye size={13} />
                </button>

                <button
                  className="pki-icon-btn"
                  title="تجديد الشهادة"
                  onClick={(e) => handleRenewClick(cert, e)}
                  disabled={renewingId === cert.id}
                >
                  <RefreshCw size={13} className={renewingId === cert.id ? 'animate-spin' : ''} />
                </button>

                <button
                  className="pki-icon-btn pki-icon-danger"
                  title="إلغاء الشهادة"
                  onClick={(e) => handleRevokeClick(cert, e)}
                  disabled={revokingId === cert.id}
                >
                  <Trash2 size={13} />
                </button>
              </div>
            </motion.div>
          );
        })}
      </div>
    </div>
  );
}
