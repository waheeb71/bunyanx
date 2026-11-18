import React, { useState } from 'react';
import { Shield, Settings2, Trash2, Plus } from 'lucide-react';
import { SectionCard, SkeletonLines, EmptyState } from '../../../components/Shared';

export function RulesView({ rules, rulesLoading, createRule, deleteRule }) {
  const [newSid, setNewSid] = useState('');
  const [newRule, setNewRule] = useState('');
  const [deleteConfirmId, setDeleteConfirmId] = useState(null);

  const handleAdd = (e) => {
    e.preventDefault();
    if (!newSid || !newRule) return;
    createRule.mutate({ sid: Number(newSid), raw_rule: newRule, enabled: true }, {
      onSuccess: () => {
        setNewSid('');
        setNewRule('');
      }
    });
  };

  const handleDelete = (id) => {
    deleteRule.mutate(id, {
      onSuccess: () => setDeleteConfirmId(null)
    });
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
      {/* Add Signature Form */}
      <SectionCard title="إضافة توقيع IPS جديد (Snort Rule)" icon={Shield}>
        <form onSubmit={handleAdd} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-3)' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            <label style={{ fontSize: '0.85rem', fontWeight: 600 }}>معرف القاعدة (SID)</label>
            <input
              type="number"
              placeholder="مثال: 1000001"
              value={newSid}
              onChange={e => setNewSid(e.target.value)}
              required
              style={{
                background: 'var(--bg-overlay)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--text-primary)',
                padding: '8px 12px',
                width: '100%',
                maxWidth: '240px',
                outline: 'none',
              }}
            />
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            <label style={{ fontSize: '0.85rem', fontWeight: 600 }}>نص القاعدة الخام (Raw Rule)</label>
            <textarea
              placeholder='مثال: alert tcp any any -> any any (msg:"Malicious Payload Detected"; content:"|90 90 90|"; sid:1000001;)'
              value={newRule}
              onChange={e => setNewRule(e.target.value)}
              required
              rows={3}
              style={{
                background: 'var(--bg-overlay)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--text-primary)',
                fontFamily: 'monospace',
                fontSize: '0.8rem',
                padding: '8px 12px',
                width: '100%',
                resize: 'vertical',
                outline: 'none',
              }}
            />
          </div>
          <button
            type="submit"
            disabled={createRule.isPending}
            style={{
              background: 'var(--accent)',
              border: 'none',
              borderRadius: 'var(--radius-sm)',
              color: '#050810',
              fontWeight: 700,
              padding: '10px 20px',
              cursor: 'pointer',
              alignSelf: 'flex-start',
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              transition: 'opacity 0.2s',
            }}
            onMouseOver={e => e.currentTarget.style.opacity = '0.9'}
            onMouseOut={e => e.currentTarget.style.opacity = '1'}
          >
            <Plus size={15} />
            {createRule.isPending ? 'جاري الحفظ...' : 'إضافة التوقيع'}
          </button>
        </form>
      </SectionCard>

      {/* Signatures List Table */}
      <SectionCard title="قائمة التواقيع النشطة" icon={Settings2}>
        {rulesLoading && <SkeletonLines count={3} />}
        {!rulesLoading && rules.length === 0 && (
          <EmptyState message="لا توجد تواقيع مضافة حالياً في قاعدة البيانات" icon={Shield} />
        )}
        {!rulesLoading && rules.length > 0 && (
          <div style={{ overflowX: 'auto', maxHeight: 480 }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th style={{ width: 100 }}>SID</th>
                  <th>قاعدة Snort الثنائية (Raw Rule)</th>
                  <th style={{ width: 120, textAlign: 'center' }}>إجراءات</th>
                </tr>
              </thead>
              <tbody>
                {rules.map(r => (
                  <tr key={r.id}>
                    <td><span className="badge badge-accent mono">{r.sid}</span></td>
                    <td className="mono" style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{r.raw_rule}</td>
                    <td style={{ textAlign: 'center' }}>
                      {deleteConfirmId === r.id ? (
                        <div style={{ display: 'flex', gap: 6, justifyContent: 'center' }}>
                          <button
                            className="ids-block-btn"
                            onClick={() => handleDelete(r.id)}
                            disabled={deleteRule.isPending}
                            style={{ background: 'var(--danger)', color: '#fff', fontSize: '0.72rem', padding: '3px 8px' }}
                          >
                            تأكيد
                          </button>
                          <button
                            className="ids-tab"
                            onClick={() => setDeleteConfirmId(null)}
                            style={{ fontSize: '0.72rem', padding: '3px 6px' }}
                          >
                            إلغاء
                          </button>
                        </div>
                      ) : (
                        <button
                          className="ids-block-btn"
                          onClick={() => setDeleteConfirmId(r.id)}
                          disabled={deleteRule.isPending}
                          title="حذف التوقيع"
                          style={{ margin: '0 auto' }}
                        >
                          <Trash2 size={13} />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </SectionCard>
    </div>
  );
}

export default RulesView;

