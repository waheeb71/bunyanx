import { createContext, useContext, useState, useCallback, useEffect } from 'react';
import { CheckCircle2, AlertTriangle, XCircle, Info, X } from 'lucide-react';
import './Toast.css';

const ToastContext = createContext(null);

const ICONS = { success: CheckCircle2, warning: AlertTriangle, error: XCircle, info: Info };

const COLORS = {
  success: { color: '#28c76f', bg: 'rgba(40,199,111,0.08)',  border: 'rgba(40,199,111,0.25)' },
  warning: { color: '#ffc107', bg: 'rgba(255,193,7,0.08)',   border: 'rgba(255,193,7,0.25)'  },
  error:   { color: '#ff5f5f', bg: 'rgba(255,95,95,0.08)',   border: 'rgba(255,95,95,0.25)'  },
  info:    { color: '#00d4ff', bg: 'rgba(0,212,255,0.08)',   border: 'rgba(0,212,255,0.25)'  },
};

function ToastItem({ toast, onRemove }) {
  const Icon = ICONS[toast.type] || Info;
  const c = COLORS[toast.type] || COLORS.info;

  useEffect(() => {
    if (toast.duration === 0) return; // confirm toasts don't auto-close
    const t = setTimeout(() => onRemove(toast.id), toast.duration || 4500);
    return () => clearTimeout(t);
  }, [toast.id, toast.duration, onRemove]);

  return (
    <div className="toast-item" style={{ '--tc': c.color, background: c.bg, border: `1px solid ${c.border}` }}>
      <div className="toast-icon" style={{ color: c.color }}>
        <Icon size={16} />
      </div>
      <div className="toast-body">
        {toast.title && <div className="toast-title" style={{ color: c.color }}>{toast.title}</div>}
        <div className="toast-msg">{toast.message}</div>
      </div>
      <button className="toast-close" onClick={() => onRemove(toast.id)}>
        <X size={13} />
      </button>
    </div>
  );
}

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);

  const remove = useCallback((id) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  const add = useCallback((type, message, title, duration) => {
    const id = crypto.randomUUID();
    setToasts(prev => [...prev.slice(-4), { id, type, message, title, duration }]);
    return id;
  }, []);

  const toast = {
    success: (msg, title, duration) => add('success', msg, title, duration),
    error:   (msg, title, duration) => add('error',   msg, title, duration),
    warning: (msg, title, duration) => add('warning', msg, title, duration),
    info:    (msg, title, duration) => add('info',    msg, title, duration),
    confirm: (msg, onConfirm, title) => {
      const id = crypto.randomUUID();
      setToasts(prev => [...prev.slice(-4), {
        id, type: 'confirm', message: msg,
        title: title || 'تأكيد', onConfirm, duration: 0,
      }]);
    },
  };

  return (
    <ToastContext.Provider value={toast}>
      {children}
      <div className="toast-container" dir="rtl">
        {toasts.map(t =>
          t.type === 'confirm' ? (
            <div key={t.id} className="toast-item toast-confirm"
              style={{ background: 'rgba(255,193,7,0.08)', border: '1px solid rgba(255,193,7,0.3)' }}>
              <AlertTriangle size={16} style={{ color: '#ffc107', flexShrink: 0 }} />
              <div className="toast-body">
                {t.title && <div className="toast-title" style={{ color: '#ffc107' }}>{t.title}</div>}
                <div className="toast-msg">{t.message}</div>
                <div className="toast-confirm-btns">
                  <button className="toast-confirm-yes"
                    onClick={() => { t.onConfirm(); remove(t.id); }}>تأكيد</button>
                  <button className="toast-confirm-no" onClick={() => remove(t.id)}>إلغاء</button>
                </div>
              </div>
            </div>
          ) : (
            <ToastItem key={t.id} toast={t} onRemove={remove} />
          )
        )}
      </div>
    </ToastContext.Provider>
  );
}

export const useToast = () => {
  const ctx = useContext(ToastContext);
  if (!ctx) {
    return {
      success: (m) => console.log('[Toast Success]', m),
      error:   (m) => console.error('[Toast Error]', m),
      warning: (m) => console.warn('[Toast Warning]', m),
      info:    (m) => console.log('[Toast Info]', m),
      confirm: (m, fn) => fn && fn(),
    };
  }
  return ctx;
};
