import React from 'react';
import { motion } from 'framer-motion';
import { Shield, Layers, Lock, Globe, CheckCircle2, AlertCircle } from 'lucide-react';

export default function SecurityPillarsPanel({ modulesState = {}, statsData = {} }) {
  const pillars = [
    {
      id: 'perimeter',
      title: 'حماية المحيط والشبكة',
      subtitle: 'Perimeter & Network Defense',
      icon: Shield,
      color: '#00c8ff',
      modules: [
        { key: 'firewall', label: 'الجدار الناري الفائق', name: 'NGFW' },
        { key: 'waf', label: 'جدار حماية الويب', name: 'WAF GNN' },
        { key: 'ids_ips', label: 'كشف واعتراض الاختراق', name: 'Phantom IPS' },
      ],
    },
    {
      id: 'data',
      title: 'حماية البيانات والتهديدات المتقدمة',
      subtitle: 'Data & Threat Protection',
      icon: Lock,
      color: '#00e676',
      modules: [
        { key: 'malware_av', label: 'مكافحة البرمجيات الخبيثة', name: 'Malware AV' },
        { key: 'dlp', label: 'منع تسريب البيانات', name: 'DLP Engine' },
        { key: 'ssl_inspection', label: 'فحص الاتصال المشفر', name: 'SSL Inspection' },
      ],
    },
    {
      id: 'access',
      title: 'الهوية والنفاذ الآمن والخدمات',
      subtitle: 'Identity & Secure Access',
      icon: Globe,
      color: '#818cf8',
      modules: [
        { key: 'vpn', label: 'الشبكة الافتراضية الخاصة', name: 'IPsec/WireGuard VPN' },
        { key: 'dns_security', label: 'أمان استعلامات DNS', name: 'DNS Shield' },
        { key: 'uba', label: 'تحليل سلوك المستخدم', name: 'UBA AI Engine' },
      ],
    },
  ];

  const getModuleStatus = (key) => {
    if (modulesState && modulesState[key] === false) {
      return { active: false, label: 'معطل', color: '#ff4d6a' };
    }
    return { active: true, label: 'نشط ويعمل', color: '#00e676' };
  };

  const getPillarMaturity = (pillarModules) => {
    const activeCount = pillarModules.filter(m => getModuleStatus(m.key).active).length;
    return Math.round((activeCount / pillarModules.length) * 100);
  };

  return (
    <motion.div
      className="exec-panel exec-pillars-panel"
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, delay: 0.25 }}
    >
      <div className="exec-panel-header">
        <div className="exec-panel-title-group">
          <div className="exec-panel-icon-wrap" style={{ background: 'rgba(0, 200, 255, 0.12)', color: '#00c8ff' }}>
            <Layers size={18} />
          </div>
          <div>
            <h3 className="exec-panel-title">مصفوفة ركائز الأمن السيبراني المؤسسي</h3>
            <span className="exec-panel-sub">حالة الجاهزية والتكامل لطبقات الحماية الثلاث الرئيسية</span>
          </div>
        </div>
      </div>

      <div className="exec-pillars-grid">
        {pillars.map((pillar) => {
          const maturity = getPillarMaturity(pillar.modules);
          const PillarIcon = pillar.icon;
          return (
            <div key={pillar.id} className="exec-pillar-card">
              <div className="exec-pillar-header">
                <div className="exec-pillar-icon" style={{ background: `${pillar.color}18`, color: pillar.color }}>
                  <PillarIcon size={18} />
                </div>
                <div className="exec-pillar-title-wrap">
                  <div className="exec-pillar-title">{pillar.title}</div>
                  <div className="exec-pillar-sub">{pillar.subtitle}</div>
                </div>
                <div className="exec-pillar-badge" style={{ color: pillar.color, background: `${pillar.color}15`, borderColor: `${pillar.color}35` }}>
                  {maturity}% جاهزية
                </div>
              </div>

              <div className="exec-pillar-progress">
                <div
                  className="exec-pillar-progress-fill"
                  style={{
                    width: `${maturity}%`,
                    background: `linear-gradient(90deg, ${pillar.color}88, ${pillar.color})`
                  }}
                />
              </div>

              <div className="exec-pillar-modules-list">
                {pillar.modules.map((mod) => {
                  const status = getModuleStatus(mod.key);
                  const eventsCount = statsData?.[mod.key]?.event_count || 0;
                  return (
                    <div key={mod.key} className="exec-pillar-module-item">
                      <div className="exec-pillar-mod-info">
                        <div className="exec-pillar-mod-status-dot" style={{ background: status.color, boxShadow: `0 0 8px ${status.color}88` }} />
                        <span className="exec-pillar-mod-name">{mod.label}</span>
                        <span className="exec-pillar-mod-tag">{mod.name}</span>
                      </div>
                      <div className="exec-pillar-mod-meta">
                        {eventsCount > 0 && (
                          <span className="exec-pillar-mod-events">{eventsCount.toLocaleString()} حدث</span>
                        )}
                        <span className="exec-pillar-mod-status" style={{ color: status.color }}>
                          {status.active ? <CheckCircle2 size={12} /> : <AlertCircle size={12} />}
                          {status.label}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>
    </motion.div>
  );
}
