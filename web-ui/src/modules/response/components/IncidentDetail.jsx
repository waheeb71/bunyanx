import { Ban, Globe, Eye, CheckCircle2, FileText, X } from 'lucide-react';
import { motion } from 'framer-motion';
import { useToast } from '../../../components/Toast';

const SEV_COLOR  = { critical: '#ff5f5f', high: '#ffc107', medium: '#00d4ff', low: '#28c76f', info: '#818cf8' };
const SEV_LABEL  = { critical: 'حرج', high: 'عالٍ', medium: 'متوسط', low: 'منخفض', info: 'معلومة' };
const STAT_COLOR = { open: '#ff5f5f', investigating: '#ffc107', contained: '#00d4ff', closed: '#28c76f' };
const STAT_LABEL = { open: 'مفتوح', investigating: 'قيد التحقيق', contained: 'محدود', closed: 'مغلق' };

export function IncidentDetail({ incident, onClose, onAction, onStatusUpdate, isLoading }) {
  const toast = useToast();

  const actions = [
    { label: 'حجب IP المصدر',     icon: Ban,           color: '#ff5f5f', action: 'block_ip' },
    { label: 'عزل الجهاز',        icon: Globe,          color: '#ffc107', action: 'isolate' },
    { label: 'بدء تحقيق رسمي',    icon: Eye,            color: '#00d4ff', action: 'investigate' },
    { label: 'إغلاق الحادثة',     icon: CheckCircle2,   color: '#28c76f', action: 'close' },
    { label: 'تصدير تقرير PDF',   icon: FileText,       color: '#818cf8', action: 'export' },
  ];

  const handleAction = (action, label) => {
    if (action === 'close') {
      toast.confirm(
        `هل تريد إغلاق الحادثة ${incident.id}؟`,
        () => onStatusUpdate(incident.id, 'closed'),
        'تأكيد إغلاق الحادثة'
      );
    } else if (action === 'investigate') {
      onStatusUpdate(incident.id, 'investigating');
    } else if (action === 'isolate') {
      toast.confirm(
        `هل تريد عزل الجهاز المستهدف للحادثة ${incident.id}؟`,
        () => onAction(incident.id, 'isolate', label),
        'تأكيد العزل'
      );
    } else if (action === 'block_ip') {
      toast.confirm(
        `هل تريد حجب عنوان IP المصدر (${incident.src_ip})؟`,
        () => onAction(incident.id, 'block_ip', label),
        'تأكيد حجب الـ IP'
      );
    } else {
      onAction(incident.id, action, label);
    }
  };

  return (
    <motion.div
      className="rc-detail-overlay"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      onClick={onClose}
    >
      <motion.div
        className="rc-detail-panel"
        initial={{ x: 80, opacity: 0 }}
        animate={{ x: 0, opacity: 1 }}
        exit={{ x: 80, opacity: 0 }}
        onClick={e => e.stopPropagation()}
        dir="rtl"
      >
        <div className="rc-detail-header">
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
              <span className="rc-detail-id" dir="ltr">{incident.id}</span>
              <span className="rc-sev-badge" style={{ color: SEV_COLOR[incident.severity], borderColor: SEV_COLOR[incident.severity] + '44', background: SEV_COLOR[incident.severity] + '11' }}>
                {SEV_LABEL[incident.severity]}
              </span>
              <span className="rc-status-badge" style={{ color: STAT_COLOR[incident.status], borderColor: STAT_COLOR[incident.status] + '44', background: STAT_COLOR[incident.status] + '11' }}>
                {STAT_LABEL[incident.status]}
              </span>
            </div>
            <div className="rc-detail-title">{incident.title}</div>
          </div>
          <button className="rc-detail-close" onClick={onClose}><X size={18} /></button>
        </div>

        <div className="rc-detail-body">
          <div className="rc-detail-section">
            <div className="rc-detail-sec-title">معلومات الشبكة</div>
            <div className="rc-ip-grid">
              <div className="rc-ip-box">
                <span style={{ fontSize: '0.7rem', color: 'rgba(255,255,255,0.4)' }}>IP المصدر</span>
                <span dir="ltr" style={{ fontFamily: 'Fira Code, monospace', color: '#ff5f5f', fontSize: '0.9rem', fontWeight: 700 }}>{incident.src_ip || 'غير متوفر'}</span>
              </div>
              <div style={{ color: 'rgba(255,255,255,0.2)', alignSelf: 'center' }}>→</div>
              <div className="rc-ip-box">
                <span style={{ fontSize: '0.7rem', color: 'rgba(255,255,255,0.4)' }}>IP الهدف</span>
                <span dir="ltr" style={{ fontFamily: 'Fira Code, monospace', color: '#00d4ff', fontSize: '0.9rem', fontWeight: 700 }}>{incident.dst_ip || 'غير متوفر'}</span>
              </div>
            </div>
          </div>

          <div className="rc-detail-section">
            <div className="rc-detail-sec-title">تفاصيل الحادثة</div>
            <div className="rc-meta-grid">
              {[
                { label: 'الوحدة المكتشفة', value: incident.module },
                { label: 'عدد الأحداث', value: String(incident.events || 1) },
                { label: 'وقت الكشف', value: incident.ts ? new Date(incident.ts).toLocaleString('ar-SA') : 'منذ قليل' },
              ].map(m => (
                <div key={m.label} className="rc-meta-item">
                  <span className="rc-meta-label">{m.label}</span>
                  <span className="rc-meta-val">{m.value}</span>
                </div>
              ))}
            </div>
          </div>

          {isLoading ? (
            <div className="rc-detail-section" style={{ textAlign: 'center', padding: '16px' }}>
              <div style={{ color: 'rgba(255,255,255,0.3)', fontSize: '0.85rem' }}>جاري تحميل خط الزمن...</div>
            </div>
          ) : incident.timeline && incident.timeline.length > 0 ? (
            <div className="rc-detail-section">
              <div className="rc-detail-sec-title">خط الزمن</div>
              <div className="rc-timeline">
                {incident.timeline.map((ev, i) => (
                  <div key={i} className="rc-timeline-item">
                    <div className="rc-tl-dot" style={{ background: ev.color || '#00d4ff' }} />
                    <div>
                      <div className="rc-tl-msg">{ev.msg}</div>
                      <div className="rc-tl-time" dir="ltr">{ev.t ? new Date(ev.t).toLocaleTimeString('ar-SA') : ''}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : null}
        </div>

        <div className="rc-detail-actions">
          {actions.map(a => (
            <button key={a.action} className="rc-action-btn" onClick={() => handleAction(a.action, a.label)}
              style={{ '--a-color': a.color }}>
              <a.icon size={14} /> {a.label}
            </button>
          ))}
        </div>
      </motion.div>
    </motion.div>
  );
}

export default IncidentDetail;
