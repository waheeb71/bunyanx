import React, { useState } from 'react';
import { Shield, Plus, Edit2, Trash2, Save, X, AlertOctagon, Filter } from 'lucide-react';
import { SectionCard, FilterBar, EmptyState, Pagination } from '../../../components/Shared';
import Toggle from './Toggle';
import ActionBadge from './ActionBadge';

const EMPTY_RULE = { domain_pattern: '', filter_type: 'EXACT', action: 'BLOCK', description: '', enabled: true };
const FILTER_TYPES = ['EXACT', 'WILDCARD', 'REGEX'];

export function DNSRulesView({ rules, createRule, updateRule, deleteRule }) {
  const [search, setSearch] = useState('');
  const [actionFilter, setActionFilter] = useState('ALL');
  const [newRule, setNewRule] = useState(EMPTY_RULE);
  const [editId, setEditId] = useState(null);
  const [editBuf, setEditBuf] = useState({});
  const [page, setPage] = useState(1);
  const [confirmDeleteRule, setConfirmDeleteRule] = useState(null);
  const [toast, setToast] = useState(null);

  const PAGE_SIZE = 10;

  const showToast = (message, type = 'success') => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 4000);
  };

  const filtered = rules.filter(r => {
    const matchesSearch = r.domain_pattern.toLowerCase().includes(search.toLowerCase()) ||
                          (r.description || '').toLowerCase().includes(search.toLowerCase());
    const matchesAction = actionFilter === 'ALL' || r.action === actionFilter;
    return matchesSearch && matchesAction;
  });

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE) || 1;
  const paginatedRules = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  const handleAdd = () => {
    if (!newRule.domain_pattern.trim()) {
      showToast('يرجى إدخال نمط النطاق أولاً', 'error');
      return;
    }
    createRule.mutate(newRule, {
      onSuccess: () => {
        setNewRule(EMPTY_RULE);
        showToast('تم إضافة القاعدة بنجاح!', 'success');
      },
      onError: (err) => showToast('فشل إضافة القاعدة: ' + (err.response?.data?.detail || err.message), 'error')
    });
  };

  const startEdit = (rule) => {
    setEditId(rule.id);
    setEditBuf({ domain_pattern: rule.domain_pattern, filter_type: rule.filter_type, action: rule.action, enabled: rule.enabled });
  };

  const saveEdit = () => {
    updateRule.mutate({ id: editId, d: editBuf }, {
      onSuccess: () => {
        setEditId(null);
        showToast('تم تعديل القاعدة بنجاح!', 'success');
      },
      onError: (err) => showToast('فشل تعديل القاعدة: ' + (err.response?.data?.detail || err.message), 'error')
    });
  };

  const executeDelete = () => {
    if (!confirmDeleteRule) return;
    deleteRule.mutate(confirmDeleteRule.id, {
      onSuccess: () => {
        showToast('تم حذف القاعدة بنجاح!', 'warning');
        setConfirmDeleteRule(null);
      },
      onError: (err) => {
        showToast('فشل حذف القاعدة: ' + (err.response?.data?.detail || err.message), 'error');
        setConfirmDeleteRule(null);
      }
    });
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
      {toast && (
        <div className={`dns-toast dns-toast-${toast.type}`}>
          {toast.message}
        </div>
      )}

      {/* Delete Modal Confirmation */}
      {confirmDeleteRule && (
        <div className="dns-modal-overlay">
          <div className="dns-modal">
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: 'var(--danger)', fontWeight: 700, fontSize: '1.1rem', marginBottom: 12 }}>
              <AlertOctagon size={22} />
              تأكيد حذف قاعدة الفلترة
            </div>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', marginBottom: 20 }}>
              هل أنت متأكد من رغبتك في حذف قاعدة النطاق: <strong style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>{confirmDeleteRule.domain_pattern}</strong>؟ لا يمكن التراجع عن هذا الإجراء.
            </p>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
              <button className="dns-btn-primary" style={{ background: 'var(--bg-hover)', color: 'var(--text-primary)' }} onClick={() => setConfirmDeleteRule(null)}>
                إلغاء
              </button>
              <button className="dns-btn-primary" style={{ background: 'var(--danger)', color: '#fff' }} onClick={executeDelete} disabled={deleteRule.isPending}>
                تأكيد الحذف
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Add Rule Form */}
      <SectionCard title="إضافة قاعدة فلترة جديدة" icon={Plus}>
        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1fr 2fr auto', gap: 'var(--sp-3)', alignItems: 'center' }}>
          <input
            className="dns-input" dir="auto"
            placeholder="نمط النطاق (مثال: *.tk, bad.*\.io)"
            value={newRule.domain_pattern}
            onChange={e => setNewRule(p => ({ ...p, domain_pattern: e.target.value }))}
            onKeyDown={e => e.key === 'Enter' && handleAdd()}
          />
          <select className="dns-input" dir="ltr" value={newRule.filter_type} onChange={e => setNewRule(p => ({ ...p, filter_type: e.target.value }))}>
            {FILTER_TYPES.map(t => <option key={t}>{t}</option>)}
          </select>
          <select className="dns-input" value={newRule.action} onChange={e => setNewRule(p => ({ ...p, action: e.target.value }))}>
            <option value="BLOCK">حظر</option>
            <option value="ALLOW">سماح</option>
            <option value="REDIRECT">توجيه</option>
            <option value="MONITOR">مراقبة</option>
          </select>
          <input className="dns-input" placeholder="الوصف (اختياري)" value={newRule.description} onChange={e => setNewRule(p => ({ ...p, description: e.target.value }))} />
          <button className="dns-btn-primary" onClick={handleAdd} disabled={createRule.isPending}>
            <Plus size={15} /> إضافة
          </button>
        </div>
      </SectionCard>

      {/* Rules Table */}
      <SectionCard title={`قواعد الفلترة النشطة (${filtered.length})`} icon={Shield}>
        <div style={{ display: 'flex', gap: 'var(--sp-3)', marginBottom: 'var(--sp-3)', flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: 240 }}>
            <FilterBar placeholder="البحث في القواعد..." value={search} onChange={(val) => { setSearch(val); setPage(1); }} />
          </div>
          <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
            <Filter size={15} style={{ color: 'var(--text-muted)' }} />
            {['ALL', 'BLOCK', 'ALLOW', 'REDIRECT', 'MONITOR'].map(act => (
              <button
                key={act}
                className={`dns-tab ${actionFilter === act ? 'active' : ''}`}
                style={{ padding: '6px 12px', fontSize: '0.8rem' }}
                onClick={() => { setActionFilter(act); setPage(1); }}
              >
                {act === 'ALL' ? 'الكل' : act}
              </button>
            ))}
          </div>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>نمط النطاق</th>
                <th>النوع</th>
                <th>الإجراء</th>
                <th>الإصابات</th>
                <th>آخر نشاط</th>
                <th>مُفعّلة</th>
                <th>أوامر</th>
              </tr>
            </thead>
            <tbody>
              {paginatedRules.length === 0 ? (
                <tr><td colSpan={7} style={{ textAlign: 'center' }}><EmptyState message="لا توجد قواعد فلترة مطابقة" /></td></tr>
              ) : (
                paginatedRules.map(rule => (
                  <tr key={rule.id}>
                    {editId === rule.id ? (
                      <>
                        <td><input className="dns-input" dir="ltr" value={editBuf.domain_pattern} onChange={e => setEditBuf(p => ({ ...p, domain_pattern: e.target.value }))} /></td>
                        <td>
                          <select className="dns-input" dir="ltr" value={editBuf.filter_type} onChange={e => setEditBuf(p => ({ ...p, filter_type: e.target.value }))}>
                            {FILTER_TYPES.map(t => <option key={t}>{t}</option>)}
                          </select>
                        </td>
                        <td>
                          <select className="dns-input" value={editBuf.action} onChange={e => setEditBuf(p => ({ ...p, action: e.target.value }))}>
                            <option value="BLOCK">حظر</option>
                            <option value="ALLOW">سماح</option>
                            <option value="REDIRECT">توجيه</option>
                            <option value="MONITOR">مراقبة</option>
                          </select>
                        </td>
                        <td>{rule.blocked_count ?? 0}</td>
                        <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>—</td>
                        <td><Toggle checked={editBuf.enabled} onChange={() => setEditBuf(p => ({ ...p, enabled: !p.enabled }))} /></td>
                        <td>
                          <div style={{ display: 'flex', gap: 8 }}>
                            <button className="dns-icon-btn" style={{ color: 'var(--success)' }} onClick={saveEdit}><Save size={15} /></button>
                            <button className="dns-icon-btn" style={{ color: 'var(--text-muted)' }} onClick={() => setEditId(null)}><X size={15} /></button>
                          </div>
                        </td>
                      </>
                    ) : (
                      <>
                        <td className="mono" style={{ direction: 'ltr', textAlign: 'right' }}>{rule.domain_pattern}</td>
                        <td><span className="badge badge-accent">{rule.filter_type}</span></td>
                        <td><ActionBadge action={rule.action} /></td>
                        <td style={{ fontWeight: 700, color: rule.blocked_count > 0 ? 'var(--danger)' : 'var(--text-muted)' }}>{rule.blocked_count ?? 0}</td>
                        <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                          {rule.last_triggered ? new Date(rule.last_triggered).toLocaleString('ar-SA') : '—'}
                        </td>
                        <td><Toggle checked={rule.enabled} onChange={() => updateRule.mutate({ id: rule.id, d: { enabled: !rule.enabled } })} /></td>
                        <td>
                          <div style={{ display: 'flex', gap: 8 }}>
                            <button className="dns-icon-btn" style={{ color: 'var(--accent)' }} onClick={() => startEdit(rule)}><Edit2 size={15} /></button>
                            <button className="dns-icon-btn" style={{ color: 'var(--danger)' }} onClick={() => setConfirmDeleteRule(rule)}><Trash2 size={15} /></button>
                          </div>
                        </td>
                      </>
                    )}
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <Pagination page={page} totalPages={totalPages} onPageChange={setPage} />
      </SectionCard>
    </div>
  );
}

export default DNSRulesView;
