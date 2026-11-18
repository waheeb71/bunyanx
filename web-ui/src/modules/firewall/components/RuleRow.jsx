import { useState } from 'react';
import { Edit2, Trash2, ToggleLeft, ToggleRight, AlertTriangle, X } from 'lucide-react';
import ActionBadge from './ActionBadge';

export function RuleRow({ rule, isSelected, onSelectToggle, onDelete, onEdit, onToggle }) {
  const [showConfirmDelete, setShowConfirmDelete] = useState(false);

  return (
    <>
      <tr style={{ opacity: rule.enabled ? 1 : 0.5, background: isSelected ? 'rgba(0, 200, 255, 0.05)' : undefined }}>
        <td style={{ width: 40, textAlign: 'center' }}>
          <input
            type="checkbox"
            checked={!!isSelected}
            onChange={() => onSelectToggle(rule.id)}
            style={{ cursor: 'pointer', accentColor: 'var(--accent)' }}
          />
        </td>
        <td>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span className="badge badge-accent mono" style={{ minWidth: 30, textAlign: 'center' }}>{rule.priority}</span>
            <span className="mono" style={{ fontWeight: 600, direction: 'ltr' }}>{rule.name}</span>
          </div>
        </td>
        <td><ActionBadge action={rule.action} /></td>
        <td><span className="badge" style={{ background: 'var(--bg-overlay)' }}>{(rule.protocol || 'ANY').toUpperCase()}</span></td>
        <td><span className="mono" style={{ direction: 'ltr' }}>{rule.source_ip}</span></td>
        <td><span className="mono" style={{ direction: 'ltr' }}>{rule.destination_ip}</span></td>
        <td><span className="mono" style={{ direction: 'ltr', color: 'var(--accent)' }}>{rule.destination_port}</span></td>
        <td>
          <span
            className={`badge ${rule.enabled ? 'badge-success' : 'badge-info'}`}
            onClick={(e) => { e.stopPropagation(); onToggle(rule); }}
            style={{ cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: 4 }}
          >
            {rule.enabled ? <ToggleRight size={12} /> : <ToggleLeft size={12} />}
            {rule.enabled ? 'نشط' : 'معطّل'}
          </span>
        </td>
        <td>
          <div style={{ display: 'flex', gap: 6 }}>
            <button className="fw-icon-btn" title="تعديل" onClick={() => onEdit(rule)}><Edit2 size={13} /></button>
            <button className="fw-icon-btn danger" title="حذف" onClick={() => setShowConfirmDelete(true)}><Trash2 size={13} /></button>
          </div>
        </td>
      </tr>

      {/* Row level inline confirmation modal */}
      {showConfirmDelete && (
        <tr style={{ background: 'rgba(255, 77, 106, 0.08)' }}>
          <td colSpan={9} style={{ padding: '10px 16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--danger)', fontSize: '0.85rem' }}>
                <AlertTriangle size={15} />
                <span>هل أنت متأكد من حذف القاعدة <strong>"{rule.name}"</strong>؟</span>
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <button
                  className="fw-btn-primary"
                  style={{ background: 'var(--danger)', color: '#fff', padding: '4px 12px', fontSize: '0.78rem' }}
                  onClick={() => { setShowConfirmDelete(false); onDelete(rule.id); }}
                >
                  حذف القاعدة
                </button>
                <button
                  className="fw-btn-ghost"
                  style={{ padding: '4px 10px', fontSize: '0.78rem' }}
                  onClick={() => setShowConfirmDelete(false)}
                >
                  إلغاء
                </button>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

export default RuleRow;
