import React from 'react';
import { AlertTriangle, X } from 'lucide-react';

export function ConfirmModal({ isOpen, title, message, confirmText = 'تأكيد', cancelText = 'إلغاء', variant = 'danger', onConfirm, onCancel, loading = false }) {
  if (!isOpen) return null;

  const isDanger = variant === 'danger';

  return (
    <div className="vpn-modal-overlay" onClick={onCancel}>
      <div className="vpn-modal vpn-confirm-modal" onClick={e => e.stopPropagation()}>
        <div className="vpn-modal-header">
          <div className="vpn-modal-title">
            <div className={`vpn-modal-icon ${isDanger ? 'danger' : 'warn'}`}>
              <AlertTriangle size={18} style={{ color: isDanger ? '#ff5f5f' : '#ffc107' }} />
            </div>
            {title}
          </div>
          <button className="vpn-modal-close" onClick={onCancel} disabled={loading}>
            <X size={16} />
          </button>
        </div>

        <div className="vpn-modal-body">
          <p className="vpn-confirm-msg">{message}</p>
        </div>

        <div className="vpn-modal-footer">
          <button type="button" className="vpn-btn vpn-btn--ghost" onClick={onCancel} disabled={loading}>
            {cancelText}
          </button>
          <button
            type="button"
            className={`vpn-btn ${isDanger ? 'vpn-btn--stop' : 'vpn-btn--primary'}`}
            onClick={onConfirm}
            disabled={loading}
          >
            {loading ? 'جاري المعالجة...' : confirmText}
          </button>
        </div>
      </div>
    </div>
  );
}

export default ConfirmModal;
