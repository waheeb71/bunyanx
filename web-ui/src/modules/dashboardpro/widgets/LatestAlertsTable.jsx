import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { ShieldAlert, ExternalLink, Download, Ban, AlertCircle, X, Search, CheckCircle2 } from 'lucide-react';
import { responseApi } from '../../../services/api';
import { useToast } from '../../../components/Toast';

const SEV_AR = {
  critical: 'حرج',
  high: 'عالي',
  medium: 'متوسط',
  low: 'منخفض',
  info: 'معلومات',
};

const CAT_AR = {
  waf: 'جدار التطبيقات',
  ids: 'كشف التسلل',
  dlp: 'منع التسريب',
  malware: 'مكافح الفيروسات',
  dns: 'حماية DNS',
  web_filter: 'تصفية الويب',
  network: 'الشبكة',
  auth: 'المصادقة',
  Intrusion: 'اقتحام',
};

export default function LatestAlertsTable({ alerts }) {
  const toast = useToast();
  const navigate = useNavigate();
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [tableSearch, setTableSearch] = useState('');
  const [isProcessing, setIsProcessing] = useState(false);

  const getSeverityClass = (sev) => {
    return {
      critical: 'critical',
      high: 'high',
      medium: 'medium',
      low: 'low',
      info: 'low'
    }[String(sev || '').toLowerCase()] || 'low';
  };

  const getStatus = (alert) => {
    if (alert.status === 'closed') return { cls: 'closed', label: 'مغلق' };
    if (alert.status === 'in_progress') return { cls: 'in-progress', label: 'قيد المعالجة' };
    return { cls: 'new', label: 'جديد' };
  };

  const getAlertModuleInfo = (alert) => {
    if (!alert) return { route: '/ids-ips', label: 'مركز IDS/IPS' };

    const cat = String(alert.category || alert.moduleLabel || alert.categoryLabel || '').toLowerCase();
    const type = String(alert.type || alert.event_type || '').toLowerCase();
    const title = String(alert.title || alert.description || alert.reason || '').toLowerCase();

    if (cat.includes('waf') || type.includes('waf') || title.includes('waf') || title.includes('sql') || title.includes('xss') || title.includes('rce')) {
      return { route: '/waf', label: 'مركز WAF' };
    }
    if (cat.includes('malware') || cat.includes('virus') || type.includes('malware') || title.includes('malware') || title.includes('virus')) {
      return { route: '/malware', label: 'مركز حماية الفيروسات (Malware/AV)' };
    }
    if (cat.includes('dns') || type.includes('dns') || title.includes('dns')) {
      return { route: '/dns', label: 'مركز حماية DNS' };
    }
    if (cat.includes('firewall') || cat.includes('network') || type.includes('network') || title.includes('firewall') || title.includes('policy')) {
      return { route: '/firewall', label: 'مركز الجدار الناري' };
    }
    if (cat.includes('uba') || type.includes('uba') || title.includes('user')) {
      return { route: '/uba', label: 'مركز سلوك المستخدمين (UBA)' };
    }
    if (cat.includes('dlp') || type.includes('dlp')) {
      return { route: '/dlp', label: 'مركز منع تسريب البيانات (DLP)' };
    }
    if (cat.includes('response') || cat.includes('incident')) {
      return { route: '/response', label: 'مركز الاستجابة للحوادث' };
    }

    return { route: '/ids-ips', label: 'مركز IDS/IPS' };
  };

  // Filter list by table search input
  const filteredList = (alerts || []).filter(alert => {
    if (!tableSearch.trim()) return true;
    const q = tableSearch.toLowerCase();
    return (
      String(alert.title || alert.description || '').toLowerCase().includes(q) ||
      String(alert.src || alert.src_ip || '').includes(q) ||
      String(alert.dst_ip || '').includes(q) ||
      String(alert.severity || '').toLowerCase().includes(q)
    );
  });

  // Export CSV Action
  const handleExportCSV = () => {
    if (!alerts || alerts.length === 0) {
      toast.warning('لا توجد بيانات تنبيهات للتصدير');
      return;
    }
    const headers = 'ID,Timestamp,Severity,Title,Source_IP,Destination_IP,Category,Status\n';
    const rows = alerts.map(a =>
      `"${a.id || ''}","${a.time || a.timestamp || ''}","${a.severity || ''}","${String(a.title || a.description || '').replace(/"/g, '""')}","${a.src || a.src_ip || ''}","${a.dst_ip || ''}","${a.category || ''}","${a.status || 'new'}"`
    ).join('\n');

    const blob = new Blob([headers + rows], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `SOC_Alerts_Export_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    toast.success('تم تصدير ملف CSV للتنبيهات بنجاح');
  };

  // Block Source IP Action
  const handleBlockIp = async (ip) => {
    if (!ip || ip === '—') return;
    setIsProcessing(true);
    try {
      await responseApi.triggerAction('ALERT-TBL', { action: 'block_ip', ip: ip, label: `Block IP ${ip}` });
      toast.success(`تم إرسال أمر حظر IP (${ip}) إلى المحرك الفوري`, 'تم الحظر');
      setSelectedAlert(null);
    } catch (err) {
      toast.error(`تعذر حظر IP: ${err.message || 'خطأ في النظام'}`);
    } finally {
      setIsProcessing(false);
    }
  };

  return (
    <div className="pro-table-card">
      {/* Header with Search & Export */}
      <div className="pro-table-header">
        <div className="title">
          <ShieldAlert size={16} className="text-rose-500" />
          <span>أحدث التنبيهات الأمنية</span>
          {filteredList.length > 0 && (
            <span className="count">{filteredList.length} التنبيهات المفلترة</span>
          )}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ position: 'relative', width: 180 }}>
            <input
              type="text"
              placeholder="فلترة التنبيهات..."
              value={tableSearch}
              onChange={e => setTableSearch(e.target.value)}
              style={{
                width: '100%',
                background: 'rgba(15, 23, 42, 0.6)',
                border: '1px solid rgba(255, 255, 255, 0.08)',
                borderRadius: 6,
                padding: '4px 24px 4px 8px',
                color: '#fff',
                fontSize: '0.72rem',
                outline: 'none',
              }}
            />
            <Search size={12} style={{ position: 'absolute', right: 8, top: 7, color: '#64748b' }} />
          </div>

          <button
            className="map-btn"
            title="تصدير بيانات CSV"
            onClick={handleExportCSV}
          >
            <Download size={13} />
          </button>

          <Link to="/response" className="view-all-link">
            عرض الكل ←
          </Link>
        </div>
      </div>

      {/* Table Content */}
      <div className="pro-table-wrapper">
        <table className="pro-table">
          <thead>
            <tr>
              <th>الوقت</th>
              <th>الخطورة</th>
              <th>اسم التنبيه</th>
              <th>المصدر</th>
              <th>الوجهة</th>
              <th>التصنيف</th>
              <th>الحالة</th>
            </tr>
          </thead>
          <tbody>
            {filteredList.slice(0, 7).map((alert, i) => {
              const status = getStatus(alert);
              const sevKey = String(alert.severity || 'low').toLowerCase();
              const category = alert.moduleLabel || alert.categoryLabel || alert.category || 'Intrusion';
              const catAr = CAT_AR[String(category).toLowerCase()] || String(category);
              return (
                <motion.tr
                  key={alert.id || i}
                  initial={{ opacity: 0, x: 10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.03 }}
                  style={{ cursor: 'pointer' }}
                  onClick={() => setSelectedAlert(alert)}
                >
                  <td style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.7rem', direction: 'ltr', textAlign: 'right' }}>
                    {alert.time || (alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString('ar-SA', { hour12: false }) : '—')}
                  </td>
                  <td>
                    <span className={`pro-badge ${getSeverityClass(alert.severity)}`}>
                      {SEV_AR[sevKey] || sevKey}
                    </span>
                  </td>
                  <td className="bold-desc">{alert.title || alert.description || 'تنبيه أمني مشبوه'}</td>
                  <td style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.7rem', direction: 'ltr', textAlign: 'right' }}>
                    {alert.src || alert.src_ip || '—'}
                  </td>
                  <td style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.7rem', direction: 'ltr', textAlign: 'right' }}>
                    {alert.dst_ip || '—'}
                  </td>
                  <td>{catAr}</td>
                  <td>
                    <span className={`pro-status-badge ${status.cls}`}>
                      {status.label}
                    </span>
                  </td>
                </motion.tr>
              );
            })}
            {filteredList.length === 0 && (
              <tr>
                <td colSpan={7} style={{ textAlign: 'center', padding: 28, color: 'rgba(255,255,255,0.2)', fontSize: '0.82rem' }}>
                  لم يتم رصد تنبيهات أمنية مطابقة في خط المعالجة
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* ── Alert Investigation Modal ── */}
      <AnimatePresence>
        {selectedAlert && (
          <div className="map-modal-backdrop" onClick={() => setSelectedAlert(null)}>
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
                  <ShieldAlert size={18} className="text-rose-500" />
                  <span style={{ color: '#fff', fontWeight: 800, fontSize: '0.95rem' }}>تحقيق التنبيه الأمني: {selectedAlert.id || 'INC-EVT'}</span>
                </div>
                <button className="close-btn" onClick={() => setSelectedAlert(null)}><X size={15} /></button>
              </div>

              <div className="modal-body" style={{ padding: '16px 20px' }}>
                <div className="threat-inspect-grid" style={{ marginBottom: 18 }}>
                  <div className="inspect-field">
                    <span className="lbl">اسم التنبيه:</span>
                    <span className="val" style={{ fontWeight: 700, color: '#fff' }}>{selectedAlert.title || selectedAlert.description}</span>
                  </div>
                  <div className="inspect-field">
                    <span className="lbl">مستوى الخطورة:</span>
                    <span className={`pro-badge ${getSeverityClass(selectedAlert.severity)}`}>
                      {SEV_AR[String(selectedAlert.severity || '').toLowerCase()] || String(selectedAlert.severity || '')}
                    </span>
                  </div>
                  <div className="inspect-field">
                    <span className="lbl">عنوان المصدر (Source IP):</span>
                    <span className="val mono">{selectedAlert.src || selectedAlert.src_ip || '—'}</span>
                  </div>
                  <div className="inspect-field">
                    <span className="lbl">عنوان الوجهة (Dest IP):</span>
                    <span className="val mono">{selectedAlert.dst_ip || '—'}</span>
                  </div>
                  <div className="inspect-field">
                    <span className="lbl">وحدة المعالجة:</span>
                    <span className="val">{selectedAlert.category || 'IDS/IPS'}</span>
                  </div>
                  <div className="inspect-field">
                    <span className="lbl">التوقيت:</span>
                    <span className="val mono">{selectedAlert.time || new Date().toLocaleTimeString('ar-SA')}</span>
                  </div>
                </div>

                <div style={{ display: 'flex', gap: 10, marginTop: 20 }}>
                  <button
                    className="modal-btn-danger"
                    disabled={isProcessing}
                    onClick={() => handleBlockIp(selectedAlert.src || selectedAlert.src_ip)}
                  >
                    <Ban size={15} />
                    حظر IP المصدر
                  </button>

                  {(() => {
                    const mod = getAlertModuleInfo(selectedAlert);
                    return (
                      <button
                        className="modal-btn-primary"
                        onClick={() => {
                          setSelectedAlert(null);
                          navigate(mod.route);
                        }}
                      >
                        <ExternalLink size={15} />
                        فتح التنبيه في {mod.label}
                      </button>
                    );
                  })()}

                  <button
                    className="modal-btn-secondary"
                    onClick={() => setSelectedAlert(null)}
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
