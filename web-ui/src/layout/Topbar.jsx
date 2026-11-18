import { useState, useEffect, useRef } from 'react';
import { NavLink } from 'react-router-dom';
import {
  Search, ExternalLink, Bell, ChevronLeft,
  Volume2, VolumeX, Volume1, Menu,
} from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { useAudioAlerts } from '../hooks/useAudioAlerts';
import { useAlertStore } from '../stores/alertStore';

/* ══════════════════════════════════════════════════════════════
   Audio Control Widget
   ══════════════════════════════════════════════════════════════ */
function AudioControlWidget() {
  const {
    muted, volume,
    toggleMute, setVolume,
    activeEmergency, acknowledgeEmergency,
    muteFor, connected,
  } = useAudioAlerts();

  const [open, setOpen] = useState(false);
  const popoverRef = useRef(null);

  const VolumeIcon = muted ? VolumeX : volume > 0.5 ? Volume2 : Volume1;

  useEffect(() => {
    if (!open) return;
    const handler = (e) => {
      if (popoverRef.current && !popoverRef.current.contains(e.target)) {
        setOpen(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  return (
    <div style={{ position: 'relative' }} ref={popoverRef}>
      {activeEmergency && (
        <button
          id="audio-emergency-ack"
          onClick={acknowledgeEmergency}
          style={{
            position: 'absolute', top: -6, right: -6,
            width: 14, height: 14, borderRadius: '50%',
            background: '#ff0000', border: 'none', cursor: 'pointer',
            animation: 'emergency-pulse 0.8s ease-in-out infinite', zIndex: 10,
          }}
          title="انقر للإقرار بالتنبيه الطارئ"
        />
      )}

      <button
        id="audio-topbar-btn"
        className="topbar-icon-btn"
        onClick={() => setOpen(!open)}
        title="التنبيهات الصوتية"
        style={{
          color: muted ? 'var(--danger)' : connected ? 'var(--accent)' : 'var(--text-muted)',
          backgroundColor: muted ? 'rgba(255,77,106,0.1)' : activeEmergency ? 'rgba(255,0,0,0.15)' : 'rgba(0,200,255,0.08)',
          position: 'relative',
        }}
      >
        <VolumeIcon size={17} />
      </button>

      {open && (
        <div style={{
          position: 'absolute', top: 'calc(100% + 10px)', left: '50%',
          transform: 'translateX(-50%)', width: 260,
          background: 'rgba(10,14,26,0.97)',
          border: '1px solid rgba(0,200,255,0.2)',
          borderRadius: 14, backdropFilter: 'blur(18px)',
          boxShadow: '0 8px 40px rgba(0,0,0,0.6)',
          padding: '16px', zIndex: 9999, direction: 'rtl',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
            <span style={{ fontWeight: 700, color: 'var(--text-primary)', fontSize: 13 }}>
              🔊 التنبيهات الصوتية
            </span>
            <span style={{
              fontSize: 10, fontWeight: 600, padding: '2px 8px', borderRadius: 999,
              background: connected ? 'rgba(0,230,118,0.12)' : 'rgba(255,77,106,0.12)',
              color: connected ? 'var(--success)' : 'var(--danger)',
              border: `1px solid ${connected ? 'rgba(0,230,118,0.25)' : 'rgba(255,77,106,0.25)'}`,
            }}>
              {connected ? '● متصل' : '○ غير متصل'}
            </span>
          </div>

          {activeEmergency && (
            <div style={{
              padding: '8px 10px', marginBottom: 12,
              background: 'rgba(255,0,0,0.12)', border: '1px solid rgba(255,60,80,0.35)',
              borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            }}>
              <span style={{ color: '#ff4d6a', fontSize: 12, fontWeight: 600 }}>🚨 تنبيه طارئ نشط</span>
              <button
                id="audio-popover-ack"
                onClick={() => { acknowledgeEmergency(); setOpen(false); }}
                style={{ background: 'var(--danger)', color: '#fff', border: 'none', borderRadius: 6, padding: '2px 10px', fontSize: 11, fontWeight: 700, cursor: 'pointer' }}
              >إقرار</button>
            </div>
          )}

          <div style={{ marginBottom: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
              <span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>مستوى الصوت</span>
              <span style={{ color: 'var(--accent)', fontWeight: 700, fontSize: 13, fontFamily: 'monospace' }}>
                {Math.round(volume * 100)}%
              </span>
            </div>
            <input
              id="audio-popover-volume"
              type="range" min="0" max="1" step="0.01"
              value={muted ? 0 : volume}
              onChange={(e) => setVolume(parseFloat(e.target.value))}
              style={{ width: '100%', accentColor: 'var(--accent)' }}
            />
          </div>

          <button
            id="audio-popover-mute"
            onClick={() => { toggleMute(); }}
            style={{
              width: '100%', padding: '8px', borderRadius: 8,
              border: `1px solid ${muted ? 'rgba(0,230,118,0.35)' : 'rgba(255,77,106,0.35)'}`,
              background: muted ? 'rgba(0,230,118,0.08)' : 'rgba(255,77,106,0.08)',
              color: muted ? 'var(--success)' : 'var(--danger)',
              cursor: 'pointer', fontWeight: 600, fontSize: 13,
              display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, marginBottom: 10,
            }}
          >
            {muted ? <Volume2 size={14} /> : <VolumeX size={14} />}
            {muted ? 'إلغاء الكتم' : 'كتم الصوت'}
          </button>

          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {[15, 60, 240].map(m => (
              <button
                key={m}
                id={`audio-popover-mute-${m}`}
                onClick={() => { muteFor(m); setOpen(false); }}
                style={{
                  flex: 1, padding: '5px 4px', borderRadius: 6,
                  border: '1px solid var(--border)', background: 'var(--bg-overlay)',
                  color: 'var(--text-secondary)', cursor: 'pointer', fontSize: 11,
                }}
              >{m < 60 ? `${m}د` : `${m / 60}س`}</button>
            ))}
          </div>

          <NavLink
            id="audio-popover-settings"
            to="/audio-settings"
            onClick={() => setOpen(false)}
            style={{ display: 'block', textAlign: 'center', marginTop: 12, color: 'var(--accent)', fontSize: 12, textDecoration: 'none' }}
          >
            إعدادات الصوت المتقدمة ←
          </NavLink>
        </div>
      )}
    </div>
  );
}

/* ══════════════════════════════════════════════════════════════
   Topbar Component
   ══════════════════════════════════════════════════════════════ */
export default function Topbar({ onOpenSearch, onOpenFullscreen, onToggleNotifs, onOpenMobileMenu }) {
  const { user } = useAuth();
  const unreadCount = useAlertStore(s => s.unreadCount);

  return (
    <header className="topbar">
      <div className="topbar-brand">
        <button
          type="button"
          className="topbar-mobile-menu-btn"
          onClick={onOpenMobileMenu}
          title="القائمة"
        >
          <Menu size={20} />
        </button>
        <img
          src="/logo-light.png" alt="bunyanx"
          className="topbar-brand-img"
          onError={(e) => { e.target.style.display = 'none'; }}
        />
        <div className="topbar-brand-text">
          <span className="topbar-brand-name">bunyanx NGFW</span>
          <span className="topbar-brand-sub">منصة الأمان المؤسسية</span>
        </div>
      </div>

      {/* Center: Global search bar */}
      <button className="topbar-search-bar" onClick={() => onOpenSearch && onOpenSearch()}>
        <Search size={14} style={{ color: 'rgba(255,255,255,0.3)' }} />
        <span className="topbar-search-label" style={{ color: 'rgba(255,255,255,0.3)', fontSize: '0.82rem' }}>ابحث عن صفحة أو وحدة...</span>
        <kbd className="topbar-search-kbd">Ctrl+K</kbd>
      </button>

      <div className="topbar-right">
        <button
          className="topbar-icon-btn topbar-desktop-only"
          title="فتح القسم في نافذة مستقلة"
          onClick={() => onOpenFullscreen && onOpenFullscreen()}
          style={{ color: '#818cf8', backgroundColor: 'rgba(99,102,241,0.1)' }}
        >
          <ExternalLink size={17} />
        </button>

        <div className="topbar-live-badge topbar-desktop-only">
          <span className="topbar-live-dot pulse" />
          <span>مباشر</span>
        </div>

        {/* Notifications — functional */}
        <button
          id="topbar-notif-btn"
          className="topbar-icon-btn"
          title="الإشعارات"
          onClick={() => onToggleNotifs && onToggleNotifs()}
          style={{
            position: 'relative',
            color: unreadCount > 0 ? '#ffc107' : undefined,
            backgroundColor: unreadCount > 0 ? 'rgba(255,193,7,0.1)' : undefined,
          }}
        >
          <Bell size={17} />
          {unreadCount > 0 && (
            <span style={{
              position: 'absolute', top: -4, right: -4,
              width: 16, height: 16, borderRadius: '50%',
              background: '#ff5f5f', color: '#fff',
              fontSize: '0.6rem', fontWeight: 800,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              border: '2px solid #090b12',
            }}>
              {Math.min(unreadCount, 99)}
            </span>
          )}
        </button>

        {/* Audio Control Widget */}
        <AudioControlWidget />

        {/* User Chip */}
        <div className="topbar-user-chip">
          <div className="topbar-user-avatar">
            {user?.username?.[0]?.toUpperCase() || 'A'}
          </div>
          <div className="topbar-user-details topbar-desktop-only">
            <span className="topbar-user-name">{user?.username || 'المسؤول'}</span>
            <span className="topbar-user-role">{user?.role || 'admin'}</span>
          </div>
          <ChevronLeft size={14} className="topbar-desktop-only" style={{ opacity: 0.4 }} />
        </div>
      </div>
    </header>
  );
}
