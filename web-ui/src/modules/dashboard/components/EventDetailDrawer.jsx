import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, ShieldAlert, Copy, Search, Loader2 } from 'lucide-react';
import { responseApi, threatIntelApi } from '../../../services/api';
import { useToast } from '../../../components/Toast';
import './EventDetailDrawer.css';

const SEV_META = {
  critical: { badge: 'db-sev-badge--critical', label: 'حرج', color: '#ef4444' },
  high:     { badge: 'db-sev-badge--high',     label: 'عالٍ', color: '#f59e0b' },
  warning:  { badge: 'db-sev-badge--warning',  label: 'تحذير', color: '#eab308' },
  info:     { badge: 'db-sev-badge--info',     label: 'معلومة', color: '#3b82f6' },
};

export default function EventDetailDrawer({ event, alert, onClose }) {
  const toast = useToast();
  const [ctiInfo, setCtiInfo] = useState(null);
  const [isLoadingCti, setIsLoadingCti] = useState(false);
  const [isBlocking, setIsBlocking] = useState(false);

  const targetEvent = event || alert;

  if (!targetEvent) return null;

  // Extract source IP & info safely
  const srcIp = targetEvent.src_ip || targetEvent.source_ip || targetEvent.src || targetEvent.ip || '';
  const dstIp = targetEvent.dst_ip || targetEvent.destination_ip || targetEvent.dest_ip || '192.168.10.1';
  const proto = targetEvent.proto || targetEvent.protocol || 'TCP';
  const timestamp = targetEvent.full_timestamp || targetEvent.timestamp || targetEvent.time || new Date().toISOString();
  const severity = targetEvent.severity || targetEvent.sev || 'info';
  const meta = SEV_META[String(severity).toLowerCase()] || SEV_META.info;

  const handleCopyLog = () => {
    navigator.clipboard.writeText(JSON.stringify(targetEvent, null, 2));
    toast.success('تم نسخ بيانات السجل الخام إلى الحافظة.');
  };

  const handleCtiLookup = async () => {
    if (!srcIp) return;
    setIsLoadingCti(true);
    try {
      const res = await threatIntelApi.lookup(srcIp);
      setCtiInfo(res.data);
      toast.success('تم جلب تفاصيل السمعة الأمنية من خلاصة التهديدات.');
    } catch (err) {
      toast.error('فشل الاستعلام عن السمعة: ' + (err.response?.data?.detail || err.message));
    } finally {
      setIsLoadingCti(false);
    }
  };

  const handleBlockIp = async () => {
    if (!srcIp) return;
    setIsBlocking(true);
    try {
      await responseApi.addTtlEntry({
        action: 'BLOCK',
        target: srcIp,
        ttl: 3600,
        reason: `حظر تلقائي يدوي عبر تفاصيل الهجوم: ${targetEvent.title || targetEvent.category || 'تهديد شبكي'}`
      });
      toast.success(`تم حظر IP المصدر ${srcIp} بنجاح لمدة ساعة.`);
    } catch (err) {
      toast.error('فشل حظر الـ IP: ' + (err.response?.data?.detail || err.message));
    } finally {
      setIsBlocking(false);
    }
  };

  return (
    <motion.div
      className="db-drawer-overlay"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      onClick={onClose}
    >
      <motion.div
        className="db-drawer-panel"
        initial={{ x: 100, opacity: 0 }}
        animate={{ x: 0, opacity: 1 }}
        exit={{ x: 100, opacity: 0 }}
        transition={{ type: 'spring', damping: 25, stiffness: 220 }}
        onClick={e => e.stopPropagation()}
        dir="rtl"
      >
        {/* Header */}
        <div className="db-drawer-header">
          <div className="db-drawer-title-area">
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2 }}>
              <span className={`db-sev-badge ${meta.badge}`} style={{ fontSize: '0.72rem', padding: '2px 8px', borderRadius: 4, fontWeight: 800, background: `${meta.color}18`, color: meta.color, border: `1px solid ${meta.color}28` }}>
                {meta.label}
              </span>
              <span style={{ fontSize: '0.75rem', color: 'rgba(255,255,255,0.25)' }}>مستكشف الأحداث المتقدم</span>
            </div>
            <div className="db-drawer-title">{targetEvent.title || targetEvent.category || 'تهديد مكتشف'}</div>
            <div className="db-drawer-subtitle">{targetEvent.id || 'N/A'}</div>
          </div>
          <button className="db-drawer-close" onClick={onClose}><X size={18} /></button>
        </div>

        {/* Body */}
        <div className="db-drawer-body">
          {/* IP Traffic Section */}
          <div className="db-drawer-section">
            <div className="db-drawer-sec-title">مسار اتصال الشبكة</div>
            <div className="db-ip-grid">
              <div className="db-ip-box">
                <span style={{ fontSize: '0.68rem', color: 'rgba(255,255,255,0.35)' }}>عنوان المصدر (Source)</span>
                <span dir="ltr" style={{ fontFamily: 'Fira Code, monospace', color: '#ff5f5f', fontSize: '0.88rem', fontWeight: 800 }}>
                  {srcIp || 'داخلي'}
                </span>
                {targetEvent.country && (
                  <span style={{ fontSize: '0.7rem', color: 'rgba(255,255,255,0.5)' }}>
                    {targetEvent.flag || '🌐'} {targetEvent.country}
                  </span>
                )}
              </div>
              <div style={{ color: 'rgba(255,255,255,0.15)', alignSelf: 'center', fontWeight: 'bold' }}>←</div>
              <div className="db-ip-box">
                <span style={{ fontSize: '0.68rem', color: 'rgba(255,255,255,0.35)' }}>عنوان الوجهة (Destination)</span>
                <span dir="ltr" style={{ fontFamily: 'Fira Code, monospace', color: '#00d4ff', fontSize: '0.88rem', fontWeight: 800 }}>
                  {dstIp}
                </span>
              </div>
            </div>
          </div>

          {/* Details Section */}
          <div className="db-drawer-section">
            <div className="db-drawer-sec-title">تفاصيل الحدث الأمني</div>
            <div className="db-grid-2">
              <div className="db-meta-item">
                <span className="db-meta-label">البروتوكول المستخدم</span>
                <span className="db-meta-val" style={{ fontFamily: 'Fira Code, monospace', textTransform: 'uppercase' }}>{proto}</span>
              </div>
              <div className="db-meta-item">
                <span className="db-meta-label">وحدة الكشف</span>
                <span className="db-meta-val" style={{ textTransform: 'uppercase', color: '#a78bfa' }}>
                  {String(targetEvent.event_type || targetEvent.module || 'ids_ips').toUpperCase()}
                </span>
              </div>
              <div className="db-meta-item">
                <span className="db-meta-label">الطابع الزمني الكامل</span>
                <span className="db-meta-val" style={{ fontSize: '0.78rem' }}>
                  {new Date(timestamp).toLocaleString('ar-SA')}
                </span>
              </div>
              {targetEvent.risk !== undefined && (
                <div className="db-meta-item">
                  <span className="db-meta-label">مستوى الخطورة الرقمي</span>
                  <span className="db-meta-val" style={{ color: '#ff5f5f', fontFamily: 'Fira Code, monospace' }}>
                    {targetEvent.risk}
                  </span>
                </div>
              )}
            </div>

            {targetEvent.cause && (
              <div className="db-meta-item" style={{ marginTop: 8 }}>
                <span className="db-meta-label">السبب / المحفزات المكتشفة</span>
                <span className="db-meta-val" style={{ color: 'rgba(255,255,255,0.7)', fontSize: '0.8rem', fontWeight: 'normal', lineHeight: 1.4 }}>
                  {targetEvent.cause}
                </span>
              </div>
            )}
          </div>

          {/* CTI Lookup Info Panel */}
          <AnimatePresence>
            {ctiInfo && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="db-drawer-section"
                style={{
                  background: 'rgba(255,255,255,0.01)',
                  border: '1px solid rgba(255,255,255,0.05)',
                  borderRadius: 8,
                  padding: 12,
                  marginTop: 6
                }}
              >
                <div className="db-drawer-sec-title" style={{ color: '#28c76f' }}>السمعة الأمنية للـ IP (CTI Lookup)</div>
                <div className="db-grid-2">
                  <div className="db-meta-item">
                    <span className="db-meta-label">تصنيف الخلاصة</span>
                    <span className="db-meta-val" style={{ color: ctiInfo.is_malicious ? '#ff5f5f' : '#28c76f' }}>
                      {ctiInfo.is_malicious ? 'خبيث / مشبوه' : 'سليم / موثوق'}
                    </span>
                  </div>
                  <div className="db-meta-item">
                    <span className="db-meta-label">مستوى التهديد</span>
                    <span className="db-meta-val" style={{ color: '#ff5f5f', fontFamily: 'Fira Code, monospace' }}>
                      {Math.round(ctiInfo.score * 100)}%
                    </span>
                  </div>
                </div>
                <div className="db-meta-item" style={{ marginTop: 6 }}>
                  <span className="db-meta-label">تفاصيل المصدر</span>
                  <span className="db-meta-val" style={{ fontSize: '0.78rem', color: 'rgba(255,255,255,0.5)' }}>
                    {ctiInfo.reason || 'سليم في الخلاصة الحالية.'}
                  </span>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Raw Log Payload */}
          <div className="db-drawer-section">
            <div className="db-drawer-sec-title">بيانات السجل الخام (JSON Payload)</div>
            <pre className="db-code-block">
              {JSON.stringify(targetEvent, null, 2)}
            </pre>
          </div>
        </div>

        {/* Footer actions */}
        <div className="db-drawer-footer">
          <div style={{ display: 'flex', gap: 10 }}>
            <button
              className="db-btn db-btn-danger"
              style={{ flex: 1 }}
              onClick={handleBlockIp}
              disabled={isBlocking}
            >
              {isBlocking ? <Loader2 size={14} className="spin" /> : <ShieldAlert size={14} />}
              حظر الـ IP في النواة
            </button>

            <button
              className="db-btn db-btn-primary"
              style={{ flex: 1 }}
              onClick={handleCtiLookup}
              disabled={isLoadingCti}
            >
              {isLoadingCti ? <Loader2 size={14} className="spin" /> : <Search size={14} />}
              فحص السمعة CTI
            </button>
          </div>

          <button className="db-btn db-btn-ghost" onClick={handleCopyLog}>
            <Copy size={14} /> نسخ بيانات التهديد
          </button>
        </div>
      </motion.div>
    </motion.div>
  );
}
