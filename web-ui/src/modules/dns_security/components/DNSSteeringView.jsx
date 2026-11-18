import React, { useState } from 'react';
import { Plus, Globe2, Trash2, AlertOctagon } from 'lucide-react';
import { SectionCard, EmptyState, FilterBar, Pagination } from '../../../components/Shared';

export function DNSSteeringView({ rules, createSteering, deleteSteering }) {
  const [newRule, setNewRule] = useState({ name: '', domain_pattern: '', redirect_ip: '', source_ips_str: '' });
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const [confirmDeleteName, setConfirmDeleteName] = useState(null);
  const [toast, setToast] = useState(null);

  const PAGE_SIZE = 10;

  const showToast = (message, type = 'success') => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 4000);
  };

  const handleAdd = () => {
    if (!newRule.name.trim() || !newRule.domain_pattern.trim() || !newRule.redirect_ip.trim()) {
      showToast('يرجى ملء جميع الحقول المطلوبة (الاسم، النطاق، IP)', 'error');
      return;
    }
    const source_ips = newRule.source_ips_str.split(',')
      .map(s => s.trim())
      .filter(Boolean);
    
    createSteering.mutate({
      name: newRule.name.trim(),
      domain_pattern: newRule.domain_pattern.trim(),
      redirect_ip: newRule.redirect_ip.trim(),
      source_ips: source_ips.length > 0 ? source_ips : null
    }, {
      onSuccess: () => {
        setNewRule({ name: '', domain_pattern: '', redirect_ip: '', source_ips_str: '' });
        showToast('تم إضافة قاعدة التوجيه بنجاح!', 'success');
      },
      onError: (err) => showToast('فشل إضافة قاعدة التوجيه: ' + (err.response?.data?.detail || err.message), 'error')
    });
  };

  const executeDelete = () => {
    if (!confirmDeleteName) return;
    deleteSteering.mutate(confirmDeleteName, {
      onSuccess: () => {
        showToast('تم حذف قاعدة التوجيه بنجاح!', 'warning');
        setConfirmDeleteName(null);
      },
      onError: (err) => {
        showToast('فشل حذف قاعدة التوجيه: ' + (err.response?.data?.detail || err.message), 'error');
        setConfirmDeleteName(null);
      }
    });
  };

  const filteredRules = rules.filter(r =>
    r.name.toLowerCase().includes(search.toLowerCase()) ||
    r.domain_pattern.toLowerCase().includes(search.toLowerCase()) ||
    r.redirect_ip.toLowerCase().includes(search.toLowerCase())
  );

  const totalPages = Math.ceil(filteredRules.length / PAGE_SIZE) || 1;
  const paginatedRules = filteredRules.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
      {toast && (
        <div className={`dns-toast dns-toast-${toast.type}`}>
          {toast.message}
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {confirmDeleteName && (
        <div className="dns-modal-overlay">
          <div className="dns-modal">
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: 'var(--danger)', fontWeight: 700, fontSize: '1.1rem', marginBottom: 12 }}>
              <AlertOctagon size={22} />
              تأكيد حذف قاعدة توجيه DNS
            </div>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', marginBottom: 20 }}>
              هل أنت متأكد من رغبتك في حذف قاعدة التوجيه: <strong style={{ color: 'var(--text-primary)' }}>{confirmDeleteName}</strong>؟
            </p>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
              <button className="dns-btn-primary" style={{ background: 'var(--bg-hover)', color: 'var(--text-primary)' }} onClick={() => setConfirmDeleteName(null)}>
                إلغاء
              </button>
              <button className="dns-btn-primary" style={{ background: 'var(--danger)', color: '#fff' }} onClick={executeDelete} disabled={deleteSteering.isPending}>
                تأكيد الحذف
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Add Steering Rule Form */}
      <SectionCard title="إضافة قاعدة توجيه DNS جديدة" icon={Plus}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.5fr 1fr 1.5fr auto', gap: 'var(--sp-3)', alignItems: 'center' }}>
          <input
            className="dns-input"
            placeholder="اسم القاعدة (مثال: البوابة الداخلية)"
            value={newRule.name}
            onChange={e => setNewRule(p => ({ ...p, name: e.target.value }))}
          />
          <input
            className="dns-input mono" dir="ltr"
            placeholder="نمط النطاق (مثال: portal.nexus)"
            value={newRule.domain_pattern}
            onChange={e => setNewRule(p => ({ ...p, domain_pattern: e.target.value }))}
          />
          <input
            className="dns-input mono" dir="ltr"
            placeholder="IP التوجيه (مثال: 10.10.0.1)"
            value={newRule.redirect_ip}
            onChange={e => setNewRule(p => ({ ...p, redirect_ip: e.target.value }))}
          />
          <input
            className="dns-input mono" dir="ltr"
            placeholder="شبكات العملاء (CIDR مفصولة بفواصل)"
            value={newRule.source_ips_str}
            onChange={e => setNewRule(p => ({ ...p, source_ips_str: e.target.value }))}
          />
          <button className="dns-btn-primary" onClick={handleAdd} disabled={createSteering.isPending}>
            <Plus size={15} /> إضافة
          </button>
        </div>
      </SectionCard>

      {/* Steering Rules List */}
      <SectionCard title={`قواعد التوجيه الفعالة (${filteredRules.length})`} icon={Globe2}>
        <div style={{ marginBottom: 'var(--sp-3)' }}>
          <FilterBar placeholder="البحث في قواعد التوجيه..." value={search} onChange={(val) => { setSearch(val); setPage(1); }} />
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>اسم القاعدة</th>
                <th>نمط النطاق</th>
                <th>عنوان IP المستهدف</th>
                <th>نطاق أجهزة العملاء (CIDR)</th>
                <th>أوامر</th>
              </tr>
            </thead>
            <tbody>
              {paginatedRules.length === 0 ? (
                <tr><td colSpan={5} style={{ textAlign: 'center' }}><EmptyState message="لا توجد قواعد توجيه معرفة حالياً" /></td></tr>
              ) : (
                paginatedRules.map((rule, idx) => (
                  <tr key={idx}>
                    <td style={{ fontWeight: 600 }}>{rule.name}</td>
                    <td className="mono" style={{ direction: 'ltr', textAlign: 'right' }}>{rule.domain_pattern}</td>
                    <td className="mono">{rule.redirect_ip}</td>
                    <td>
                      {rule.source_ips && rule.source_ips.length > 0 ? (
                        rule.source_ips.map((cidr, i) => (
                          <span key={i} className="badge badge-accent" style={{ marginRight: 4, fontFamily: 'var(--font-mono)' }}>{cidr}</span>
                        ))
                      ) : (
                        <span style={{ color: 'var(--text-muted)' }}>الجميع (عام)</span>
                      )}
                    </td>
                    <td>
                      <button
                        className="dns-icon-btn" style={{ color: 'var(--danger)' }}
                        onClick={() => setConfirmDeleteName(rule.name)}
                        disabled={deleteSteering.isPending}
                      >
                        <Trash2 size={15} />
                      </button>
                    </td>
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

export default DNSSteeringView;
