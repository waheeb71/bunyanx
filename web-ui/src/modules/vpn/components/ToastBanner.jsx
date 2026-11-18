import React from 'react';
import { CheckCircle2, AlertCircle, Info, X } from 'lucide-react';

export function ToastBanner({ toast, onClose }) {
  if (!toast || !toast.message) return null;

  const { type = 'info', message } = toast;

  const icons = {
    success: <CheckCircle2 size={16} style={{ color: '#28c76f' }} />,
    error: <AlertCircle size={16} style={{ color: '#ff5f5f' }} />,
    info: <Info size={16} style={{ color: '#00d4ff' }} />,
  };

  return (
    <div className={`vpn-toast vpn-toast--${type}`}>
      <div className="vpn-toast-icon">{icons[type] || icons.info}</div>
      <div className="vpn-toast-msg">{message}</div>
      <button className="vpn-toast-close" onClick={onClose}>
        <X size={14} />
      </button>
    </div>
  );
}

export default ToastBanner;
