import { useState, useEffect, useRef } from 'react';
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import { Search, Bell, X } from 'lucide-react';
import { useLiveSockets } from '../hooks/useLiveSockets';
import { useAlertStore } from '../stores/alertStore';
import Sidebar, { NAV_GROUPS } from './Sidebar';
import Topbar from './Topbar';
import BottomNav from './BottomNav';
import './Shell.css';

/* ══════════════════════════════════════════════════════════════
   Global Search
   ══════════════════════════════════════════════════════════════ */
const SEARCH_INDEX = NAV_GROUPS.flatMap(g => g.items.map(i => ({ ...i, group: g.label })));

function GlobalSearch({ onClose }) {
  const [query, setQuery] = useState('');
  const navigate = useNavigate();
  const inputRef = useRef(null);

  useEffect(() => { inputRef.current?.focus(); }, []);

  const results = query.trim()
    ? SEARCH_INDEX.filter(item =>
      item.label.includes(query) ||
      item.to.includes(query.toLowerCase())
    ).slice(0, 8)
    : SEARCH_INDEX.slice(0, 6);

  const go = (to) => { navigate(to); onClose(); };

  return (
    <div className="gs-overlay" onClick={onClose}>
      <div className="gs-panel" onClick={e => e.stopPropagation()} dir="rtl">
        <div className="gs-header">
          <Search size={16} style={{ color: '#00d4ff', flexShrink: 0 }} />
          <input
            ref={inputRef}
            className="gs-input"
            placeholder="ابحث عن صفحة أو وحدة..."
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Escape') onClose();
              if (e.key === 'Enter' && results.length > 0) go(results[0].to);
            }}
          />
          <button className="gs-close" onClick={onClose}><X size={15} /></button>
        </div>
        <div className="gs-results">
          {results.map(item => {
            const Icon = item.icon;
            return (
              <button key={item.to} className="gs-result-item" onClick={() => go(item.to)}>
                <div className="gs-result-icon">
                  <Icon size={15} style={{ color: '#00d4ff' }} />
                </div>
                <div>
                  <div className="gs-result-label">{item.label}</div>
                  <div className="gs-result-group">{item.group}</div>
                </div>
                <div className="gs-result-path" dir="ltr">{item.to}</div>
              </button>
            );
          })}
          {results.length === 0 && (
            <div style={{ padding: '24px', textAlign: 'center', color: 'rgba(255,255,255,0.2)', fontSize: '0.85rem' }}>
              لا توجد نتائج لـ "{query}"
            </div>
          )}
        </div>
        <div className="gs-footer">
          <span><kbd>↑↓</kbd> للتنقل</span>
          <span><kbd>Enter</kbd> للانتقال</span>
          <span><kbd>Esc</kbd> للإغلاق</span>
        </div>
      </div>
    </div>
  );
}

/* ══════════════════════════════════════════════════════════════
   Notifications Panel
   ══════════════════════════════════════════════════════════════ */
function NotificationsPanel({ onClose }) {
  const { alerts, unreadCount, markAllRead, clearAll } = useAlertStore();
  const recent = alerts.slice(0, 20);

  useEffect(() => {
    markAllRead();
    return () => { };
  }, [markAllRead]);

  const sevColor = sev => ({
    critical: '#ff5f5f', high: '#ffc107', medium: '#00d4ff', low: '#28c76f', info: '#818cf8',
  }[sev] || '#818cf8');

  return (
    <div className="notif-overlay" onClick={onClose}>
      <div className="notif-panel" onClick={e => e.stopPropagation()} dir="rtl">
        <div className="notif-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Bell size={16} style={{ color: '#00d4ff' }} />
            <span style={{ fontWeight: 700 }}>الإشعارات</span>
            {unreadCount > 0 && (
              <span className="notif-badge">{unreadCount}</span>
            )}
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            {recent.length > 0 && (
              <button className="notif-clear-btn" onClick={clearAll}>مسح الكل</button>
            )}
            <button className="notif-close-btn" onClick={onClose}><X size={14} /></button>
          </div>
        </div>

        <div className="notif-body">
          {recent.length === 0 ? (
            <div style={{ padding: '32px', textAlign: 'center', color: 'rgba(255,255,255,0.2)', fontSize: '0.85rem' }}>
              <Bell size={28} style={{ opacity: 0.15, marginBottom: 10 }} />
              <div>لا توجد إشعارات</div>
            </div>
          ) : (
            recent.map(alert => (
              <div key={alert.id} className="notif-item">
                <div className="notif-dot" style={{ background: sevColor(alert.severity) }} />
                <div className="notif-item-body">
                  <div className="notif-item-title">{alert.title || alert.alert_type || 'تنبيه أمني'}</div>
                  <div className="notif-item-sub">
                    {alert.src && <span dir="ltr">{alert.src}</span>}
                    <span style={{ color: 'rgba(255,255,255,0.2)' }}>
                      {new Date(alert.timestamp).toLocaleTimeString('ar-SA')}
                    </span>
                  </div>
                </div>
                <span className="notif-sev" style={{ color: sevColor(alert.severity), borderColor: sevColor(alert.severity) + '33', background: sevColor(alert.severity) + '11' }}>
                  {alert.severity}
                </span>
              </div>
            ))
          )}
        </div>

        <div className="notif-footer">
          <NavLink to="/response" onClick={onClose} className="notif-view-all">
            عرض مركز الاستجابة ←
          </NavLink>
        </div>
      </div>
    </div>
  );
}

/* ══════════════════════════════════════════════════════════════
   Main Shell
   ══════════════════════════════════════════════════════════════ */
export default function Shell() {
  useLiveSockets();
  const location = useLocation();
  const isFullscreen = new URLSearchParams(location.search).get('fs') === '1';

  const [showSearch, setShowSearch] = useState(false);
  const [showNotifs, setShowNotifs] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  // Global keyboard shortcut: Ctrl+K or Cmd+K for search
  useEffect(() => {
    const handler = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        setShowSearch(true);
      }
      if (e.key === 'Escape') {
        setShowSearch(false);
        setShowNotifs(false);
        setMobileMenuOpen(false);
      }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, []);

  if (isFullscreen) {
    return (
      <div style={{ width: '100vw', height: '100vh', overflow: 'hidden', backgroundColor: '#060b19' }} dir="rtl">
        <Outlet />
      </div>
    );
  }

  const handleOpenFullscreen = () => {
    window.open(`${location.pathname}?fs=1`, '_blank', 'noopener,noreferrer');
  };

  return (
    <>
      {/* الشريط الجانبي — RTL من اليمين (ويدعم وضع القائمة للهواتف) */}
      <Sidebar
        onOpenSearch={() => setShowSearch(true)}
        mobileOpen={mobileMenuOpen}
        onCloseMobile={() => setMobileMenuOpen(false)}
      />

      {/* شريط الرأس العلوي */}
      <Topbar
        onOpenSearch={() => setShowSearch(true)}
        onOpenFullscreen={handleOpenFullscreen}
        onToggleNotifs={() => setShowNotifs(v => !v)}
        onOpenMobileMenu={() => setMobileMenuOpen(true)}
      />

      {/* Main Content */}
      <main className="main-content">
        <Outlet />
      </main>

      {/* شريط التنقل السفلي للهواتف */}
      <BottomNav onOpenMobileMenu={() => setMobileMenuOpen(true)} />

      {/* Overlays */}
      {showSearch && <GlobalSearch onClose={() => setShowSearch(false)} />}
      {showNotifs && <NotificationsPanel onClose={() => setShowNotifs(false)} />}
    </>
  );
}
