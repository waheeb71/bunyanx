import React, { useState, useEffect } from 'react';
import {
  Server, Shield, Layers, BrainCircuit, Key, Blocks, Globe, Database, Cpu,
  Settings2, ChevronRight, Activity, Lock, Network, Sliders, UserCheck, Terminal,
  Search, ShieldCheck, Zap, Sparkles, CheckCircle2, ChevronLeft
} from 'lucide-react';
import './Settings.css';

// Subcomponents
import MLCoreSettings from './MLCoreSettings';
import ActiveBlocks from './ActiveBlocks';
import PKISettings from './PKISettings';
import ModulesManager from './ModulesManager';
import StealthSettings from './StealthSettings';
import GenericYamlEditor from './yaml_views/GenericYamlEditor';
import SIEMSettings from './SIEMSettings';

const NAV_GROUPS = [
  {
    id: 'security',
    label: 'محركات الأمان والحماية',
    icon: <Shield size={14} />,
    items: [
      { id: 'modules', icon: <Blocks size={17} />, label: 'الوحدات وخط الأنابيب', badge: 'live', desc: 'تفعيل وإيقاف محركات التهديدات' },
      { id: 'ip_blocks', icon: <Shield size={17} />, label: 'الحظر الفوري (eBPF)', badge: 'ebpf', desc: 'جداول الحظر اللحظية على كرت الشبكة' },
      { id: 'stealth', icon: <Globe size={17} />, label: 'التخفي وتوجيه VIP/DNS', badge: null, desc: 'إخفاء الهوية وإعادة التوجيه' },
      { id: 'pki_ca', icon: <Key size={17} />, label: 'المرجع المصدق (PKI / CA)', badge: 'tls', desc: 'شهادات وهوية فحص SSL' },
      { id: 'siem', icon: <Database size={17} />, label: 'تكامل موصل SIEM', badge: 'logs', desc: 'تصدير السجلات إلى Splunk/Elastic' },
    ],
  },
  {
    id: 'intelligence',
    label: 'الذكاء الاصطناعي والاستدلال',
    icon: <BrainCircuit size={14} />,
    items: [
      { id: 'ml_core', icon: <BrainCircuit size={17} />, label: 'محرك التعلم الآلي (AI-Core)', badge: 'ai', desc: 'عتبات ونماذج الشبكات العصبية' },
    ],
  },
  {
    id: 'yaml_config',
    label: 'ملفات التهيئة الحية (YAML / Conf)',
    icon: <Database size={14} />,
    items: [
      { id: 'base.yaml', icon: <Server size={17} />, label: 'base.yaml', badge: 'yaml', desc: 'إعدادات المنافذ والوكيل والشبكة' },
      { id: 'settings.yaml', icon: <Sliders size={17} />, label: 'settings.yaml', badge: 'yaml', desc: 'سياسات الفحص والشبكات الموثوقة' },
      { id: 'features.yaml', icon: <Cpu size={17} />, label: 'features.yaml', badge: 'yaml', desc: 'مفاتيح الميزات والمكونات التجريبية' },
      { id: 'identity_correlation.yaml', icon: <UserCheck size={17} />, label: 'identity_correlation.yaml', badge: 'yaml', desc: 'ربط الهوية (LDAP, AD, Radius)' },
      { id: 'sysctl-optimization.conf', icon: <Terminal size={17} />, label: 'sysctl-optimization.conf', badge: 'conf', desc: 'معاملات تحسين النواة ومخازن الشبكة' },
    ],
  },
];

const BADGE_COLORS = {
  live: { bg: 'rgba(0, 200, 255, 0.15)', color: '#00c8ff', text: 'Live' },
  ebpf: { bg: 'rgba(255, 77, 106, 0.15)', color: '#ff4d6a', text: 'eBPF' },
  ai: { bg: 'rgba(129, 140, 248, 0.15)', color: '#818cf8', text: 'AI' },
  tls: { bg: 'rgba(251, 191, 36, 0.15)', color: '#fbbf24', text: 'TLS' },
  yaml: { bg: 'rgba(0, 230, 118, 0.15)', color: '#00e676', text: 'YAML' },
  conf: { bg: 'rgba(255, 171, 64, 0.15)', color: '#ffab40', text: 'CONF' },
  logs: { bg: 'rgba(0, 200, 255, 0.15)', color: '#00c8ff', text: 'LOGS' },
};

const RENDERERS = {
  modules: <ModulesManager />,
  stealth: <StealthSettings />,
  ip_blocks: <ActiveBlocks />,
  ml_core: <MLCoreSettings />,
  pki_ca: <PKISettings />,
  siem: <SIEMSettings />,
  'base.yaml': <GenericYamlEditor fileName="base.yaml" />,
  'settings.yaml': <GenericYamlEditor fileName="settings.yaml" />,
  'features.yaml': <GenericYamlEditor fileName="features.yaml" />,
  'identity_correlation.yaml': <GenericYamlEditor fileName="identity_correlation.yaml" />,
  'sysctl-optimization.conf': <GenericYamlEditor fileName="sysctl-optimization.conf" />,
};

const PAGE_META = {
  modules: { title: 'مدير وحدات الفحص والأمان', desc: 'تفعيل وإيقاف محركات التهديدات فورياً في خط الأنابيب الأمني.' },
  stealth: { title: 'إعدادات التخفي وخرائط VIP وDNS', desc: 'إدارة الهوية التمويهية، وتوجيه عناوين VIP الافتراضية، وقواعد DNS Steering.' },
  ip_blocks: { title: 'قائمة الحظر الفوري النشطة بالنواة', desc: 'مراقبة عناوين IP المحظورة فورياً عبر مسرع النواة eBPF / XDP.' },
  ml_core: { title: 'محرك التعلم الآلي والاستدلال التنبؤي', desc: 'ضبط عتبات الثقة والنوافذ الزمنية لتنبؤات الذكاء الاصطناعي.' },
  pki_ca: { title: 'المرجع المصدق والبنية التحتية للمفاتيح', desc: 'إدارة شهادة الـ Root CA الخاصة بفحص التشفير العميق TLS/SSL.' },
  siem: { title: 'موصل وتكامل سجلات SIEM', desc: 'إعداد ومراقبة تصدير الأحداث الأمنية إلى منصات Splunk وElastic.' },
  'base.yaml': { title: 'ملف التهيئة الأساسي (base.yaml)', desc: 'الإعدادات الأساسية للنظام ومنافذ الوكيل والمحركات المركزية.' },
  'settings.yaml': { title: 'ملف السياسات العامة (settings.yaml)', desc: 'إعدادات فحص الشبكة، والنطاقات الموثوقة، والسياسات المشتركة.' },
  'features.yaml': { title: 'ملف ميزات المنظومة (features.yaml)', desc: 'مفاتيح تفعيل الميزات المتقدمة والمكونات التجريبية.' },
  'identity_correlation.yaml': { title: 'ملف ربط الهوية (identity_correlation.yaml)', desc: 'إعدادات مزامنة الحسابات مع Active Directory وLDAP وRADIUS.' },
  'sysctl-optimization.conf': { title: 'ملف تحسين النواة (sysctl-optimization.conf)', desc: 'معاملات تسريع مكدس الشبكة Linux Kernel Socket Buffers.' },
};

export default function Settings() {
  const [activeTab, setActiveTab] = useState(() => {
    const hash = window.location.hash.replace('#', '');
    if (PAGE_META[hash]) return hash;
    const stored = sessionStorage.getItem('settings_active_tab');
    if (stored && PAGE_META[stored]) return stored;
    return 'modules';
  });

  const [sidebarSearch, setSidebarSearch] = useState('');

  const handleTabChange = (tabId) => {
    setActiveTab(tabId);
    sessionStorage.setItem('settings_active_tab', tabId);
    window.location.hash = tabId;
  };

  useEffect(() => {
    const handleHash = () => {
      const hash = window.location.hash.replace('#', '');
      if (PAGE_META[hash]) {
        setActiveTab(hash);
        sessionStorage.setItem('settings_active_tab', hash);
      }
    };
    window.addEventListener('hashchange', handleHash);
    return () => window.removeEventListener('hashchange', handleHash);
  }, []);

  const meta = PAGE_META[activeTab] || { title: activeTab, desc: '' };

  // Filter groups based on search
  const filteredNavGroups = NAV_GROUPS.map((group) => {
    const matchingItems = group.items.filter((item) => {
      if (!sidebarSearch) return true;
      const q = sidebarSearch.toLowerCase();
      return (
        item.label.toLowerCase().includes(q) ||
        item.id.toLowerCase().includes(q) ||
        (item.desc && item.desc.toLowerCase().includes(q))
      );
    });
    return { ...group, items: matchingItems };
  }).filter((group) => group.items.length > 0);

  return (
    <div className="settings-page" dir="rtl">
      {/* ── شريط الرأس العلوي ── */}
      <header className="settings-topbar">
        <div className="settings-topbar-left">
          <div className="settings-topbar-icon">
            <Settings2 size={22} />
          </div>
          <div>
            <div className="settings-topbar-title">لوحة إعدادات المنظومة والسياسات</div>
            <div className="settings-topbar-sub">bunyanx enterprise_ngfw · Central Configuration Console</div>
          </div>
        </div>

        <div className="settings-topbar-right">
          <div className="settings-status-pill">
            <span className="settings-status-dot active" />
            <span className="settings-status-label">محرك النواة يعمل ومستقر</span>
          </div>
        </div>
      </header>

      {/* ── هيكل الصفحة ── */}
      <div className="settings-layout">
        {/* ── الشريط الجانبي الفاخر ── */}
        <aside className="settings-sidebar">
          {/* شريط البحث في الإعدادات */}
          <div className="sidebar-search-wrap">
            <div className="sidebar-search-box">
              <Search size={14} style={{ color: 'var(--text-muted)' }} />
              <input
                type="text"
                className="sidebar-search-input"
                placeholder="بحث في الإعدادات..."
                value={sidebarSearch}
                onChange={(e) => setSidebarSearch(e.target.value)}
              />
            </div>
          </div>

          <div className="sidebar-inner">
            {filteredNavGroups.map((group) => (
              <div key={group.id} className="sidebar-group">
                <div className="sidebar-group-label">
                  {group.icon}
                  <span>{group.label}</span>
                </div>
                <ul className="sidebar-nav">
                  {group.items.map((item) => {
                    const badge = item.badge ? BADGE_COLORS[item.badge] : null;
                    const isActive = activeTab === item.id;
                    return (
                      <li
                        key={item.id}
                        className={`sidebar-nav-item ${isActive ? 'active' : ''}`}
                        onClick={() => handleTabChange(item.id)}
                      >
                        <span className="sidebar-nav-icon">{item.icon}</span>
                        <div className="sidebar-nav-text-group">
                          <span className="sidebar-nav-text">{item.label}</span>
                        </div>
                        {badge && (
                          <span
                            className="sidebar-badge"
                            style={{ background: badge.bg, color: badge.color }}
                          >
                            {badge.text}
                          </span>
                        )}
                        {isActive && <ChevronLeft size={14} className="sidebar-chevron" />}
                      </li>
                    );
                  })}
                </ul>
              </div>
            ))}
          </div>
        </aside>

        {/* ── المنطقة الرئيسية للمحتوى ── */}
        <main className="settings-main">
          {/* رأس المحتوى */}
          <div className="settings-content-header">
            <div>
              <h2 className="settings-content-title">{meta.title}</h2>
              <p className="settings-content-desc">{meta.desc}</p>
            </div>
          </div>

          {/* محتوى التبويب النشط */}
          <div className="settings-content-body">
            {RENDERERS[activeTab]}
          </div>
        </main>
      </div>
    </div>
  );
}
