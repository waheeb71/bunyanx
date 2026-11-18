import { motion } from 'framer-motion';
import { ShieldCheck, Download, Plus, Loader2, X, AlertTriangle } from 'lucide-react';
import { useToast } from '../../../components/Toast';

export function PKICAModal({ onClose, caInfo, isCaLoading, onGenerateCa, isGeneratingCa, onDownloadCa }) {
  const toast = useToast();

  const handleGenerateCa = () => {
    toast.confirm(
      'تنبيه مهم جداً: توليد سلطة تصديق (Root CA) جديدة سيقوم باستبدال المفتاح الرئيسي وتغيير توقيع الشهادات القادمة. هل أنت متاكد من المتابعة؟',
      onGenerateCa,
      'توليد Root CA جديدة'
    );
  };

  const caCert = caInfo?.ca;

  return (
    <div className="pki-modal-overlay" onClick={onClose}>
      <motion.div
        className="pki-modal pki-modal-wide"
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0, scale: 0.95 }}
        onClick={(e) => e.stopPropagation()}
        dir="rtl"
      >
        <div className="pki-modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <ShieldCheck size={20} style={{ color: '#00d4ff' }} />
            <span>إدارة سلطة التصديق الرئيسية (Root CA Trust Store)</span>
          </div>
          <button className="pki-modal-close" onClick={onClose}>
            <X size={16} />
          </button>
        </div>

        <div className="pki-modal-body">
          {isCaLoading ? (
            <div className="pki-modal-loading">
              <Loader2 className="animate-spin" size={24} style={{ color: '#00d4ff' }} />
              <span>جاري الاستعلام عن حالة Root CA...</span>
            </div>
          ) : caInfo?.exists && caCert ? (
            <div className="pki-ca-details-box">
              <div className="pki-ca-badge-status">
                <ShieldCheck size={18} style={{ color: '#28c76f' }} />
                <span>سلطة التصديق نشطة ومثبتة بالنظام</span>
              </div>

              <div className="pki-detail-grid">
                <div className="pki-detail-item">
                  <span className="pki-detail-label">الاسم الشائع (Common Name)</span>
                  <span dir="ltr" className="pki-detail-val">{caCert.cn}</span>
                </div>

                <div className="pki-detail-item">
                  <span className="pki-detail-label">المُصدِر (Issuer)</span>
                  <span className="pki-detail-val">{caCert.issuer}</span>
                </div>

                <div className="pki-detail-item">
                  <span className="pki-detail-label">تاريخ الانتهاء</span>
                  <span dir="ltr" className="pki-detail-val">{caCert.expiry}</span>
                </div>

                <div className="pki-detail-item">
                  <span className="pki-detail-label">النوع</span>
                  <span className="pki-detail-val">{caCert.type}</span>
                </div>

                <div className="pki-detail-item">
                  <span className="pki-detail-label">الرقم التسلسلي</span>
                  <span dir="ltr" className="pki-detail-val pki-mono">{caCert.serial || 'N/A'}</span>
                </div>

                <div className="pki-detail-item">
                  <span className="pki-detail-label">مسار الملف</span>
                  <span dir="ltr" className="pki-detail-val pki-mono">{caCert.path || 'N/A'}</span>
                </div>
              </div>

              <div className="pki-download-section">
                <span className="pki-download-title">تحميل شهادة Root CA للعملاء والأنظمة:</span>
                <div className="pki-download-btns">
                  <button className="pki-btn pki-btn-ghost" onClick={() => onDownloadCa('pem')}>
                    <Download size={13} /> بصيغة PEM (.pem)
                  </button>
                  <button className="pki-btn pki-btn-ghost" onClick={() => onDownloadCa('der')}>
                    <Download size={13} /> بصيغة DER (.crt)
                  </button>
                  <button className="pki-btn pki-btn-ghost" onClick={() => onDownloadCa('p12')}>
                    <Download size={13} /> بصيغة PKCS#12 (.p12)
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <div className="pki-ca-empty-box">
              <AlertTriangle size={32} style={{ color: '#ffc107', marginBottom: 12 }} />
              <div className="pki-ca-empty-title">لم يتم العثور على سلطة تصديق (Root CA) مسبقة</div>
              <div className="pki-ca-empty-desc">
                يمكنك توليد سلطة تصديق رئيسية جديدة الآن بضغطة زر واحدة لتوقيع جميع شهادات الأجهزة وخدمات SSL.
              </div>
            </div>
          )}
        </div>

        <div className="pki-modal-footer">
          <button
            className="pki-btn pki-btn-primary"
            onClick={handleGenerateCa}
            disabled={isGeneratingCa}
          >
            {isGeneratingCa ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />}
            {caInfo?.exists ? 'إعادة توليد Root CA جديدة' : 'توليد سلطة Root CA جديدة'}
          </button>

          <button className="pki-btn pki-btn-ghost" onClick={onClose}>
            إغلاق
          </button>
        </div>
      </motion.div>
    </div>
  );
}
