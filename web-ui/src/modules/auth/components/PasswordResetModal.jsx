import React, { useState } from 'react';
import { KeyRound, Mail, X, CheckCircle, AlertCircle } from 'lucide-react';
import authApi from '../api/authApi';

export default function PasswordResetModal({ isOpen, onClose }) {
  const [target, setTarget] = useState('');
  const [status, setStatus] = useState({ loading: false, msg: '', isError: false });

  if (!isOpen) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!target.trim()) return;

    setStatus({ loading: true, msg: '', isError: false });
    try {
      const res = await authApi.requestPasswordReset({ username_or_email: target });
      setStatus({
        loading: false,
        msg: res.data?.message || 'تم إرسال طلب استعادة كلمة المرور إلى قناة التدقيق الخاصة بالمسؤولين.',
        isError: false,
      });
    } catch (err) {
      setStatus({
        loading: false,
        msg: err.response?.data?.detail || 'فشل إرسال طلب الاستعادة. يُرجى التواصل مع مسؤول مركز العمليات الأمنية (SOC).',
        isError: true,
      });
    }
  };

  return (
    <div className="lp-modal-overlay" dir="rtl">
      <div className="lp-modal-content">
        <div className="lp-modal-header">
          <div className="flex items-center gap-2 text-cyan-400 font-bold">
            <KeyRound size={20} />
            <span>طلب استعادة كلمة المرور</span>
          </div>
          <button onClick={onClose} className="lp-modal-close" aria-label="إغلاق">
            <X size={16} />
          </button>
        </div>

        <div className="lp-modal-body">
          {status.msg ? (
            <div className={`p-3 rounded text-xs flex items-center gap-2 mb-4 ${status.isError ? 'bg-red-500/20 text-red-300 border border-red-500/30' : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'}`}>
              {status.isError ? <AlertCircle size={16} /> : <CheckCircle size={16} />}
              <span>{status.msg}</span>
            </div>
          ) : (
            <p className="text-slate-300 text-sm mb-4">
              أدخل اسم المستخدم المسؤول أو البريد الإلكتروني الأمني المسجل لبدء إجراءات استعادة رمز المرور.
            </p>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="lp-input-wrap">
              <Mail size={15} className="lp-input-icon" />
              <input
                type="text"
                className="lp-input"
                placeholder="اسم المستخدم أو admin@company.com"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                autoFocus
                required
                dir="rtl"
              />
            </div>

            <div className="flex gap-3 justify-end mt-4">
              <button
                type="button"
                className="px-4 py-2 text-xs rounded font-semibold text-slate-400 hover:text-white"
                onClick={onClose}
              >
                إغلاق
              </button>
              {!status.msg && (
                <button
                  type="submit"
                  disabled={status.loading || !target.trim()}
                  className="lp-submit !w-auto !py-2 !px-6 !mt-0 text-sm"
                >
                  {status.loading ? 'جاري الإرسال...' : 'إرسال طلب الاستعادة'}
                </button>
              )}
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}
