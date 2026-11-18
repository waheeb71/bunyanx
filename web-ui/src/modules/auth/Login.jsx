import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Wifi, Globe, Cpu } from 'lucide-react';
import { useAuth } from '../../hooks/useAuth';
import useAuthStatus from './hooks/useAuthStatus';
import SecurityBanner from './components/SecurityBanner';
import LoginPanel from './components/LoginPanel';
import MfaModal from './components/MfaModal';
import PasswordResetModal from './components/PasswordResetModal';
import './Login.css';

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();

  const {
    form,
    setForm,
    error,
    loading,
    showPass,
    setShowPass,
    capsLockOn,
    mounted,
    sysStats,
    showMfa,
    setShowMfa,
    showResetModal,
    setShowResetModal,
    handleKeyDown,
    handleSubmit,
    handleMfaVerify,
  } = useAuthStatus(login, navigate);

  return (
    <div className={`lp-root${mounted ? ' lp-root--in' : ''}`} dir="rtl">
      {/* Background Video */}
      <video autoPlay loop muted playsInline className="lp-bg-video">
        <source src="/Futuristic_shield_login_page_bac…_202607061743.mp4" type="video/mp4" />
      </video>
      <div className="lp-video-overlay" />

      {/* ══════════════════════ LEFT — FORM PANEL ══════════════════════ */}
      <div className="lp-left">
        <div className="lp-blob lp-blob-1" />
        <div className="lp-blob lp-blob-2" />
        <div className="lp-grid-overlay" />

        <div className="lp-form-wrapper">
          {/* Brand Header */}
          <div className="lp-brand">
            <div className="lp-logo-ring">
              <div className="lp-logo-ring-orbit" />
              <div className="lp-logo-ring-orbit lp-logo-ring-orbit--2" />
              <img src="/logo-dark.png" alt="bunyanx NGFW" className="lp-logo-img" />
            </div>
           
          </div>

          {/* Realtime Cyber Security Strip */}
          <SecurityBanner sysStats={sysStats} />

          {/* Login Form */}
          <LoginPanel
            form={form}
            setForm={setForm}
            error={error}
            loading={loading}
            showPass={showPass}
            setShowPass={setShowPass}
            capsLockOn={capsLockOn}
            handleKeyDown={handleKeyDown}
            handleSubmit={handleSubmit}
            onOpenReset={() => setShowResetModal(true)}
          />

          {/* Security Footer */}
          <div className="lp-footer">
            <span className="lp-status-dot" />
            <span className="lp-footer-text">
              قناة مشفرة TLS 1.3 · جميع الجلسات النشطة مراقبة ومسجلة أمنياً
            </span>
          </div>
        </div>
      </div>

      {/* ══════════════════════ RIGHT — VISUAL PANEL ══════════════════════ */}
      <div className="lp-right">
        <div className="lp-right-overlay" />

        {/* Floating Live Telemetry Cards */}
        <div className="lp-float-card lp-float-top">
          <Wifi size={14} className="lp-float-icon" />
          <div>
            <div
              className="lp-float-value"
              style={{
                color: sysStats.status === 'connected' ? '#28c76f' : '#ff5f5f',
              }}
            >
              {sysStats.status === 'connected' ? 'متصل' : 'غير متصل'}
            </div>
            <div className="lp-float-label">حالة محرك الحماية</div>
          </div>
        </div>

        <div className="lp-float-card lp-float-mid">
          <Globe size={14} className="lp-float-icon" />
          <div>
            <div className="lp-float-value">{sysStats.blocked_threats}</div>
            <div className="lp-float-label">التهديدات المحظورة</div>
          </div>
        </div>

        <div className="lp-float-card lp-float-bot">
          <Cpu size={14} className="lp-float-icon" />
          <div>
            <div className="lp-float-value">{sysStats.ai_core}</div>
            <div className="lp-float-label">استخبارات التهديدات بالذكاء الاصطناعي</div>
          </div>
        </div>

        {/* Brand Watermark */}
        <div className="lp-watermark">
          <img
            src="/logo-dark.png"
            alt=""
            style={{
              height: '16px',
              width: 'auto',
              objectFit: 'contain',
              filter: 'brightness(0) invert(1)',
              opacity: 0.7,
            }}
          />
          {sysStats.build}
        </div>
      </div>

      {/* MFA Verification Modal */}
      <MfaModal
        isOpen={showMfa}
        onClose={() => setShowMfa(false)}
        onVerify={handleMfaVerify}
        loading={loading}
      />

      {/* Password Reset Modal */}
      <PasswordResetModal
        isOpen={showResetModal}
        onClose={() => setShowResetModal(false)}
      />
    </div>
  );
}