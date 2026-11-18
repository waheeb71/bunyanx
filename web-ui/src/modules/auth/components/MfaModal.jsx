import React, { useState } from 'react';
import { ShieldCheck, Lock, X, ArrowLeft } from 'lucide-react';

export default function MfaModal({ isOpen, onClose, onVerify, loading }) {
  const [code, setCode] = useState('');

  if (!isOpen) return null;

  const handleSubmit = (e) => {
    e.preventDefault();
    if (code.trim().length === 6) {
      onVerify(code);
    }
  };

  return (
    <div className="lp-modal-overlay" dir="rtl">
      <div className="lp-modal-content">
        <div className="lp-modal-header">
          <div className="flex items-center gap-2 text-cyan-400 font-bold">
            <ShieldCheck size={20} />
            <span>المصادقة متناظرة العوامل (MFA)</span>
          </div>
          <button onClick={onClose} className="lp-modal-close" aria-label="إغلاق">
            <X size={16} />
          </button>
        </div>

        <div className="lp-modal-body">
          <p className="text-slate-300 text-sm mb-4">
            أدخل رمز التحقق المكون من 6 أرقام من تطبيق المصادقة (TOTP) أو المفتاح الأمني الخاص بك.
          </p>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="lp-input-wrap">
              <Lock size={15} className="lp-input-icon" />
              <input
                type="text"
                className="lp-input tracking-widest text-center text-lg font-mono"
                placeholder="000000"
                maxLength={6}
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
                autoFocus
                required
                dir="ltr"
              />
            </div>

            <div className="flex gap-3 justify-end mt-4">
              <button
                type="button"
                className="px-4 py-2 text-xs rounded font-semibold text-slate-400 hover:text-white"
                onClick={onClose}
              >
                إلغاء
              </button>
              <button
                type="submit"
                disabled={loading || code.length !== 6}
                className="lp-submit !w-auto !py-2 !px-6 !mt-0 text-sm flex items-center gap-2"
              >
                {loading ? 'جاري التحقق...' : 'تأكيد الرمز'}
                <ArrowLeft size={14} />
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}
