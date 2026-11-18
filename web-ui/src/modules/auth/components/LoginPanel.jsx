import React from 'react';
import { User, Lock, AlertCircle, LogIn, Eye, EyeOff, ShieldAlert } from 'lucide-react';

export default function LoginPanel({
  form,
  setForm,
  error,
  loading,
  showPass,
  setShowPass,
  capsLockOn,
  handleKeyDown,
  handleSubmit,
  onOpenReset,
}) {
  return (
    <form className="lp-form" onSubmit={handleSubmit} autoComplete="on" dir="rtl">
      {/* Error Banner */}
      {error && (
        <div className="lp-error">
          <AlertCircle size={16} className="flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Caps Lock Warning */}
      {capsLockOn && (
        <div className="lp-caps-warning">
          <ShieldAlert size={14} />
          <span>زر الحروف الكبيرة (Caps Lock) مفعّل</span>
        </div>
      )}

      {/* Username Field */}
      <div className="lp-field">
        <label className="lp-label" htmlFor="lp-username">
          حساب المشغل / المسؤول
        </label>
        <div className="lp-input-wrap">
          <User size={15} className="lp-input-icon" />
          <input
            id="lp-username"
            className="lp-input"
            type="text"
            placeholder="اسم المستخدم أو المعرف الأمني"
            autoComplete="username"
            value={form.username}
            onChange={(e) => setForm((f) => ({ ...f, username: e.target.value }))}
            onKeyDown={handleKeyDown}
            required
            autoFocus
            dir="rtl"
          />
        </div>
      </div>

      {/* Password Field */}
      <div className="lp-field">
        <div className="flex justify-between items-center mb-1">
          <label className="lp-label mb-0" htmlFor="lp-password">
            رمز المرور الأمني
          </label>
          <button
            type="button"
            className="lp-forgot-btn"
            onClick={onOpenReset}
            tabIndex={-1}
          >
            نسيت كلمة المرور؟
          </button>
        </div>

        <div className="lp-input-wrap">
          <Lock size={15} className="lp-input-icon" />
          <input
            id="lp-password"
            className="lp-input"
            type={showPass ? 'text' : 'password'}
            placeholder="••••••••••••"
            autoComplete="current-password"
            value={form.password}
            onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))}
            onKeyDown={handleKeyDown}
            required
            dir="rtl"
          />
          <button
            type="button"
            className="lp-eye-btn"
            onClick={() => setShowPass((v) => !v)}
            tabIndex={-1}
            aria-label="إظهار/إخفاء كلمة المرور"
          >
            {showPass ? <EyeOff size={15} /> : <Eye size={15} />}
          </button>
        </div>
      </div>

      {/* Submit Button */}
      <button
        className={`lp-submit${loading ? ' lp-submit--loading' : ''}`}
        type="submit"
        disabled={loading}
      >
        {loading ? (
          <>
            <span className="lp-spinner" />
            جاري المصادقة والتحقق...
          </>
        ) : (
          <>
            <LogIn size={18} />
            تسجيل الدخول والتحقق
          </>
        )}
      </button>
    </form>
  );
}
