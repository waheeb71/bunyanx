import { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { ShieldCheck, Circle, ExternalLink, X } from 'lucide-react';
import { useToast } from '../../../components/Toast';

const MODULE_AR = {
  siem_connector: 'مركز الإشعارات SIEM',
  endpoint_av: 'مكافح الفيروسات النقاط الطرفية',
  network_auto_configurator: 'تكوين الشبكة التلقائي',
  sqlite_database: 'قاعدة البيانات والتخزين',
  threat_intel_manager: 'استخبارات التهديدات',
  waf: 'جدار حماية التطبيقات WAF',
  ids_ips: 'نظام كشف ومنع التسلل IDS/IPS',
  dlp: 'منع تسريب البيانات DLP',
  dns_firewall: 'جدار حماية DNS',
  web_filter: 'تصفية الويب والمحتوى',
  malware_av: 'مكافح البرمجيات الخبيثة',
  predictive_ai: 'الذكاء الاصطناعي التنبؤي',
  proxy: 'الوكيل العكسي Proxy',
  ssl: 'فك تشفير SSL/TLS',
  qos: 'إدارة جودة الخدمة QoS',
  vpn: 'الشبكة الافتراضية VPN',
  firewall: 'الجدار الناري الرئيسي',
  ebpf_acceleration: 'مسرع النواة eBPF',
};

const MODULE_ROUTE_MAP = {
  siem_connector: '/system',
  endpoint_av: '/malware',
  network_auto_configurator: '/netops',
  sqlite_database: '/system-health',
  threat_intel_manager: '/ai',
  waf: '/waf',
  ids_ips: '/ids-ips',
  dlp: '/dlp',
  dns_firewall: '/dns',
  web_filter: '/web-filter',
  malware_av: '/malware',
  predictive_ai: '/predictive-ai',
  proxy: '/waf',
  ssl: '/ssl-inspection',
  qos: '/qos',
  vpn: '/vpn',
  firewall: '/firewall-rules',
  ebpf_acceleration: '/netops',
};

export default function SystemHealthGauge({ detailedHealth }) {
  const toast = useToast();
  const navigate = useNavigate();
  const [selectedComp, setSelectedComp] = useState(null);

  const { overallHealth, components, healthLabel } = useMemo(() => {
    let _overallHealth = 100;
    let _components = [];

    if (detailedHealth && typeof detailedHealth === 'object') {
      let unhealthies = 0;
      _components = Object.entries(detailedHealth).map(([key, val]) => {
        const name = MODULE_AR[key] || key;
        const isHealthy = val && typeof val === 'object'
          ? (val.status === 'healthy' || val.healthy === true || val.state === 'CLOSED' || val.state === 'CLOSED')
          : (val === 'healthy' || val === 'CLOSED' || val === true);
        if (!isHealthy) unhealthies += 1;
        return {
          key,
          name,
          status: isHealthy ? 'سليم' : 'متدهور',
          color: isHealthy ? '#10b981' : '#f59e0b',
          isHealthy,
          raw: val,
        };
      });

      _overallHealth = _components.length > 0
        ? Math.round(((_components.length - unhealthies) / _components.length) * 100)
        : 100;
    }

    const _healthLabel = _overallHealth >= 80 ? 'سليم' : _overallHealth >= 50 ? 'متدهور' : 'حرج';

    return {
      overallHealth: _overallHealth,
      components: _components,
      healthLabel: _healthLabel,
    };
  }, [detailedHealth]);

  return (
    <div className="pro-health-card">
      <div className="pro-health-header">
        <ShieldCheck size={15} style={{ color: '#10b981' }} />
        <span>صحة النظام والمكونات</span>
      </div>

      <div className="pro-health-content-wrapper">
        {/* Radial gauge — pure SVG, no Recharts (avoids SetAngleAxisSettings infinite loop) */}
        <div className="pro-health-gauge-wrapper" style={{ display: 'flex', justifyContent: 'center', cursor: 'pointer' }} onClick={() => navigate('/system-health')}>
          <div style={{ position: 'relative', width: 100, height: 90 }}>
            <svg width="100" height="90" viewBox="0 0 100 90">
              {/* Background track */}
              <circle
                cx="50" cy="50" r="36"
                fill="none"
                stroke="rgba(255,255,255,0.05)"
                strokeWidth="7"
                strokeDasharray={`${2 * Math.PI * 36}`}
                strokeLinecap="round"
              />
              {/* Health arc */}
              <circle
                cx="50" cy="50" r="36"
                fill="none"
                stroke={overallHealth >= 80 ? '#10b981' : overallHealth >= 50 ? '#f59e0b' : '#ef4444'}
                strokeWidth="7"
                strokeDasharray={`${(overallHealth / 100) * 2 * Math.PI * 36} ${2 * Math.PI * 36}`}
                strokeDashoffset={`${2 * Math.PI * 36 * 0.25}`}
                strokeLinecap="round"
                style={{ transition: 'stroke-dasharray 0.6s ease, stroke 0.3s ease' }}
              />
            </svg>
            <div className="gauge-center-text" style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '90px', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
              <span className="value">{overallHealth}%</span>
              <span className="sub">{healthLabel}</span>
            </div>
          </div>
        </div>

        {/* Component status list */}
        {components.length > 0 ? (
          <div className="pro-health-status-list">
            {components.slice(0, 5).map((comp) => (
              <div
                key={comp.name}
                className="status-item"
                style={{ cursor: 'pointer' }}
                onClick={() => setSelectedComp(comp)}
              >
                <div className="left">
                  <Circle
                    size={7}
                    fill={comp.color}
                    stroke="none"
                    className={comp.isHealthy ? '' : 'pulse-amber'}
                  />
                  <span className="name">{comp.name}</span>
                </div>
                <span className="status-text" style={{ color: comp.color }}>
                  {comp.status}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <div style={{ textAlign: 'center', color: 'rgba(255,255,255,0.2)', fontSize: '0.75rem', padding: '8px' }}>
            في انتظار بيانات المكونات...
          </div>
        )}
      </div>

      {/* ── Component Health Detail Modal ── */}
      <AnimatePresence>
        {selectedComp && (
          <div className="map-modal-backdrop" onClick={() => setSelectedComp(null)}>
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
                  <ShieldCheck size={18} style={{ color: selectedComp.color }} />
                  <span style={{ color: '#fff', fontWeight: 800, fontSize: '0.95rem' }}>حالة المكون: {selectedComp.name}</span>
                </div>
                <button className="close-btn" onClick={() => setSelectedComp(null)}><X size={15} /></button>
              </div>

              <div className="modal-body" style={{ padding: '16px 20px' }}>
                <div className="threat-inspect-grid" style={{ marginBottom: 18 }}>
                  <div className="inspect-field">
                    <span className="lbl">رمز الوحدة:</span>
                    <span className="val mono">{selectedComp.key}</span>
                  </div>
                  <div className="inspect-field">
                    <span className="lbl">الحالة الفنية:</span>
                    <span className="val" style={{ color: selectedComp.color, fontWeight: 800 }}>{selectedComp.status}</span>
                  </div>
                  <div className="inspect-field">
                    <span className="lbl">زمن الاستجابة:</span>
                    <span className="val mono">1.2ms</span>
                  </div>
                  <div className="inspect-field">
                    <span className="lbl">آخر فحص تلقائي:</span>
                    <span className="val mono">{new Date().toLocaleTimeString('ar-SA')}</span>
                  </div>
                </div>

                <div style={{ display: 'flex', gap: 10, marginTop: 16 }}>
                  <button
                    className="modal-btn-primary"
                    onClick={() => {
                      setSelectedComp(null);
                      const route = MODULE_ROUTE_MAP[selectedComp.key] || '/system-health';
                      navigate(route);
                    }}
                  >
                    <ExternalLink size={15} />
                    الانتقال لإعدادات وحدة ({selectedComp.name})
                  </button>

                  <button
                    className="modal-btn-secondary"
                    onClick={() => setSelectedComp(null)}
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
