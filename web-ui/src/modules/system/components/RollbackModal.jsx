import React from 'react';
import { X, RotateCcw, AlertTriangle } from 'lucide-react';

export default function RollbackModal({
  isOpen,
  targetVersion,
  onClose,
  onConfirmRollback,
  isRollingBack,
}) {
  if (!isOpen) return null;

  return (
    <div className="sys-modal-overlay" dir="rtl">
      <div className="sys-modal-content" style={{ maxWidth: 480 }}>
        <div className="sys-modal-header" style={{ borderColor: 'rgba(245,158,11,0.3)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <AlertTriangle size={20} className="text-warning" />
            <h3 style={{ margin: 0, fontSize: '1.05rem', color: '#fff' }}>تأكيد إجراء التراجع (Rollback)</h3>
          </div>
          <button className="sys-icon-btn" onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        <div className="sys-modal-body">
          <p style={{ fontSize: '0.88rem', color: 'rgba(255,255,255,0.8)', lineHeight: 1.6 }}>
            ⚠️ <strong>تحذير حرج:</strong> أنت على وشك العودة بإعدادات المنصة إلى اللقطة:
          </p>

          <div
            className="mono text-warning"
            style={{
              padding: '10px 14px',
              background: 'rgba(245,158,11,0.08)',
              border: '1px solid rgba(245,158,11,0.25)',
              borderRadius: 8,
              fontSize: '0.85rem',
              textAlign: 'center',
              margin: '12px 0',
              fontWeight: 700,
            }}
            dir="ltr"
          >
            {targetVersion}
          </div>

          <p style={{ fontSize: '0.8rem', color: 'rgba(255,255,255,0.5)' }}>
            سيتم كتابة الملفات وإعادة تحميل وحدات تصفية الحزم فوراً. هل ترغب بالتأكيد؟
          </p>
        </div>

        <div className="sys-modal-footer">
          <button className="sys-btn sys-btn-secondary" onClick={onClose} disabled={isRollingBack}>
            إلغاء
          </button>
          <button
            className="sys-btn sys-btn-warning"
            onClick={() => onConfirmRollback(targetVersion)}
            disabled={isRollingBack}
          >
            <RotateCcw size={14} className={isRollingBack ? 'sys-spin' : ''} />
            {isRollingBack ? 'جاري التراجع...' : 'تأكيد التراجع الآن'}
          </button>
        </div>
      </div>
    </div>
  );
}
