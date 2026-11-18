import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard, Shield, Globe, ShieldAlert, Grid,
} from 'lucide-react';

export default function BottomNav({ onOpenMobileMenu }) {
  const navItems = [
    { to: '/', icon: LayoutDashboard, label: 'الرئيسية', exact: true },
    { to: '/firewall', icon: Shield, label: 'الحماية' },
    { to: '/globe', icon: Globe, label: 'الخريطة' },
    { to: '/response', icon: ShieldAlert, label: 'الاستجابة' },
  ];

  return (
    <nav className="bottom-nav" dir="rtl">
      {navItems.map(({ to, icon: Icon, label, exact }) => (
        <NavLink
          key={to}
          to={to}
          end={exact}
          className={({ isActive }) => `bottom-nav-item${isActive ? ' active' : ''}`}
        >
          <div className="bottom-nav-icon-wrap">
            <Icon size={20} />
            <span className="bottom-nav-glow" />
          </div>
          <span className="bottom-nav-label">{label}</span>
        </NavLink>
      ))}

      {/* زر القائمة لفتح جميع الأقسام (Drawer) */}
      <button
        type="button"
        className="bottom-nav-item bottom-nav-menu-btn"
        onClick={onOpenMobileMenu}
      >
        <div className="bottom-nav-icon-wrap">
          <Grid size={20} />
        </div>
        <span className="bottom-nav-label">القائمة</span>
      </button>
    </nav>
  );
}
