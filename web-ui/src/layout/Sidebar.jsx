import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard, Shield, ShieldOff, Globe, Wifi, Lock, Mail,
  Search, Activity, Database, Network, LogOut, User, Zap,
  Bug, Gauge, Server, FileText, UserCheck, Volume2, ShieldAlert, Radio,
  FileCheck, Key, TrendingUp, Cpu, X,
} from 'lucide-react';
import { useAuth } from '../hooks/useAuth';

/* ══════════════════════════════════════════════════════════════
   Navigation Groups
   ══════════════════════════════════════════════════════════════ */
export const NAV_GROUPS = [
  {
    label: 'نظرة عامة',
    items: [
      { to: '/', icon: LayoutDashboard, label: 'Dashboard Pro 👑' },
      { to: '/dashboard-old', icon: LayoutDashboard, label: 'لوحة التحكم الكلاسيكية' },
      { to: '/executive', icon: TrendingUp, label: 'اللوحة التنفيذية' },
      { to: '/globe', icon: Globe, label: '🌍 خريطة التهديدات العالمية' },
      { to: '/netops', icon: Network, label: '⚙️ طرفية العمليات الشبكية', role: 'operator' },
    ]
  },
  {
    label: 'إدارة التهديدات',
    items: [
      { to: '/firewall', icon: Shield, label: 'قواعد الجدار الناري' },
      { to: '/ip-blocklist', icon: ShieldOff, label: 'قائمة حظر IP' },
      { to: '/waf', icon: Globe, label: 'WAF — حماية الويب' },
      { to: '/ids-ips', icon: Activity, label: 'كشف/منع الاختراق' },
      { to: '/malware', icon: Bug, label: 'مكافحة البرمجيات الخبيثة' },
      { to: '/response', icon: ShieldAlert, label: 'مركز الاستجابة للحوادث' },
    ]
  },
  {
    label: 'خدمات الشبكة',
    items: [
      { to: '/dns', icon: Network, label: 'أمان DNS' },
      { to: '/vpn', icon: Lock, label: 'بوابة VPN' },
      { to: '/proxy', icon: Server, label: 'الوكيل الأمامي' },
      { to: '/email', icon: Mail, label: 'أمان البريد' },
      { to: '/web-filter', icon: Globe, label: 'فلتر الويب' },
      { to: '/qos', icon: Gauge, label: 'جودة الخدمة QoS' },
    ]
  },
  {
    label: 'الفحص العميق',
    items: [
      { to: '/http', icon: Search, label: 'فحص HTTP' },
      { to: '/ssl', icon: Wifi, label: 'فحص SSL' },
      { to: '/dlp', icon: FileText, label: 'منع التسرب DLP' },
    ]
  },
  {
    label: 'الذكاء الأمني',
    items: [
      { to: '/ai', icon: Zap, label: 'الذكاء التنبؤي' },
      { to: '/uba', icon: UserCheck, label: 'تحليل السلوك' },
    ]
  },
  {
    label: 'التحكم المؤسسي',
    items: [
      { to: '/system-health', icon: Activity, label: 'صحة النظام' },
      { to: '/config-manager', icon: Server, label: 'مدير الإعدادات' },
      { to: '/pki', icon: Key, label: 'إدارة PKI والشهادات' },
    ]
  },
  {
    label: 'الإدارة',
    items: [
      { to: '/system', icon: Cpu, label: 'النظام' },
      { to: '/settings', icon: Database, label: 'الإعدادات العامة' },
      { to: '/users', icon: User, label: 'المستخدمون والصلاحيات' },
      { to: '/audit', icon: FileCheck, label: 'سجل مراجعة الأحداث' },
      { to: '/cvas', icon: Radio, label: 'التنبيهات الصوتية (CVAS)' },
      { to: '/audio-settings', icon: Volume2, label: 'نظام النغمات الصوتية' },
    ]
  }
];

export default function Sidebar({ onOpenSearch, mobileOpen, onCloseMobile }) {
  const { user, logout } = useAuth();

  return (
    <>
      {/* خلفية معتمة للهاتف عند فتح القائمة */}
      {mobileOpen && (
        <div className="mobile-drawer-backdrop" onClick={onCloseMobile} />
      )}

      <aside className={`sidebar ${mobileOpen ? 'mobile-open' : ''}`}>
        <div className="sidebar-header-row">
          <NavLink to="/" className="sidebar-logo" onClick={() => onCloseMobile && onCloseMobile()}>
            <div className="sidebar-logo-ring">
              <img className="sidebar-logo-img" src="/logo-dark.png" alt="bunyanx NGFW" />
            </div>
            <span className="sidebar-logo-text">bunyanx</span>
          </NavLink>

          {/* زر إغلاق القائمة الجانبية في الهاتف */}
          <button
            type="button"
            className="sidebar-mobile-close"
            onClick={onCloseMobile}
            title="إغلاق القائمة"
          >
            <X size={18} />
          </button>
        </div>

        <div className="sidebar-cyber-strip">
          <div className="sidebar-cyber-cell">
            <span className="cyber-cell-val">NGFW</span>
            <span className="cyber-cell-lbl">الوضع</span>
          </div>
          <div className="sidebar-cyber-cell">
            <span className="cyber-cell-val" style={{ color: '#00d4ff' }}>v4</span>
            <span className="cyber-cell-lbl">الإصدار</span>
          </div>
          <div className="sidebar-cyber-cell">
            <span className="cyber-cell-val" style={{ color: '#ffc107' }}>مباشر</span>
            <span className="cyber-cell-lbl">الحالة</span>
          </div>
        </div>

        <div className="sidebar-logo-sep" />

        {/* Search shortcut button */}
        <button
          className="sidebar-search-btn"
          onClick={() => {
            onCloseMobile && onCloseMobile();
            onOpenSearch && onOpenSearch();
          }}
          title="بحث سريع (Ctrl+K)"
        >
          <Search size={17} style={{ flexShrink: 0 }} />
          <span className="sidebar-search-text">
            بحث سريع <kbd>Ctrl+K</kbd>
          </span>
        </button>

        <nav className="sidebar-nav" style={{ paddingBottom: '120px' }}>
          {NAV_GROUPS.map((group) => (
            <div key={group.label} className="nav-group">
              <div className="nav-group-label">{group.label}</div>
              {group.items.map(({ to, icon: Icon, label }) => (
                <NavLink
                  key={to}
                  to={to}
                  end={to === '/'}
                  onClick={() => onCloseMobile && onCloseMobile()}
                  className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
                >
                  <Icon className="nav-item-icon" size={19} />
                  <span className="nav-item-label">{label}</span>
                </NavLink>
              ))}
            </div>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="sidebar-user-row">
            <div className="sidebar-user-avatar">
              {user?.username?.[0]?.toUpperCase() || 'A'}
            </div>
            <div className="sidebar-user-info">
              <div className="sidebar-user-name">{user?.username || 'المسؤول'}</div>
              <div className="sidebar-user-role">{user?.role || 'admin'}</div>
            </div>
          </div>
          <button
            className="nav-item sidebar-logout"
            onClick={() => {
              onCloseMobile && onCloseMobile();
              logout();
            }}
          >
            <LogOut className="nav-item-icon" size={18} />
            <span className="nav-item-label">تسجيل الخروج</span>
          </button>
        </div>
      </aside>
    </>
  );
}
