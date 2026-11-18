import React, { useState } from 'react';
import { Zap, CheckCircle, Eye, AlertTriangle, Search, Filter } from 'lucide-react';
import { SectionCard, EmptyState, Pagination, FilterBar } from '../../../components/Shared';

export function DNSDartAlertsView({ alerts, reviewAlert, flagFalsePositive }) {
  const [expandedId, setExpandedId] = useState(null);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL'); // ALL, PENDING, REVIEWED, FP
  const [page, setPage] = useState(1);
  const [toast, setToast] = useState(null);

  const PAGE_SIZE = 10;

  const showToast = (message, type = 'success') => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 4000);
  };

  const toggleExpand = (id) => {
    setExpandedId(expandedId === id ? null : id);
  };

  const handleReview = (id) => {
    reviewAlert.mutate(id, {
      onSuccess: () => showToast('تم تأكيد مراجعة التنبيه بنجاح!', 'success'),
      onError: (err) => showToast('فشلت عملية المراجعة: ' + (err.message || 'خطأ غير معروف'), 'error'),
    });
  };

  const handleFlagFalsePositive = (id) => {
    flagFalsePositive.mutate(id, {
      onSuccess: () => showToast('تم وضع علامة إيجابي زائف!', 'warning'),
      onError: (err) => showToast('فشلت العملية: ' + (err.message || 'خطأ غير معروف'), 'error'),
    });
  };

  const filteredAlerts = alerts.filter(item => {
    const matchesSearch = (item.domain || '').toLowerCase().includes(search.toLowerCase()) ||
                          (item.src_ip || '').toLowerCase().includes(search.toLowerCase());
    
    let matchesStatus = true;
    if (statusFilter === 'PENDING') matchesStatus = !item.reviewed;
    else if (statusFilter === 'REVIEWED') matchesStatus = item.reviewed && !item.false_positive;
    else if (statusFilter === 'FP') matchesStatus = item.reviewed && item.false_positive;

    return matchesSearch && matchesStatus;
  });

  const totalPages = Math.ceil(filteredAlerts.length / PAGE_SIZE) || 1;
  const paginatedAlerts = filteredAlerts.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
      {toast && (
        <div className={`dns-toast dns-toast-${toast.type}`}>
          {toast.message}
        </div>
      )}

      <SectionCard title={`تحليلات التهديدات الذكية DART AI (${filteredAlerts.length})`} icon={Zap}>
        <div style={{ display: 'flex', gap: 'var(--sp-3)', marginBottom: 'var(--sp-3)', flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: 240 }}>
            <FilterBar placeholder="البحث بالنطاق أو عنوان IP..." value={search} onChange={(val) => { setSearch(val); setPage(1); }} />
          </div>
          <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
            <Filter size={15} style={{ color: 'var(--text-muted)' }} />
            {[
              { id: 'ALL', label: 'الكل' },
              { id: 'PENDING', label: 'قيد المراجعة' },
              { id: 'REVIEWED', label: 'تمت المراجعة' },
              { id: 'FP', label: 'إيجابي زائف' },
            ].map(f => (
              <button
                key={f.id}
                className={`dns-tab ${statusFilter === f.id ? 'active' : ''}`}
                style={{ padding: '6px 12px', fontSize: '0.8rem' }}
                onClick={() => { setStatusFilter(f.id); setPage(1); }}
              >
                {f.label}
              </button>
            ))}
          </div>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>النطاق المستهدف</th>
                <th>مصدر الطلب (IP)</th>
                <th>معدل التوافق (Resonance)</th>
                <th>المحركات المفعلة</th>
                <th>الحالة / الإجراءات</th>
                <th>تفاصيل XAI</th>
              </tr>
            </thead>
            <tbody>
              {paginatedAlerts.length === 0 ? (
                <tr><td colSpan={6} style={{ textAlign: 'center' }}><EmptyState message="لا توجد تنبيهات تطابق خيارات التصفية" /></td></tr>
              ) : (
                paginatedAlerts.map(alert => (
                  <React.Fragment key={alert.id}>
                    <tr style={{ background: alert.reviewed ? 'rgba(255,255,255,0.02)' : 'none' }}>
                      <td className="mono" style={{ direction: 'ltr', textAlign: 'right' }}>{alert.domain}</td>
                      <td className="mono">{alert.src_ip}</td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <span style={{
                            fontWeight: 700,
                            color: alert.resonance_score >= 0.8 ? 'var(--danger)' : 'var(--warning)'
                          }}>
                            {(alert.resonance_score * 100).toFixed(1)}%
                          </span>
                          <div style={{
                            width: 60, height: 6, background: 'var(--bg-hover)', borderRadius: 3, overflow: 'hidden'
                          }}>
                            <div style={{
                              width: `${alert.resonance_score * 100}%`,
                              height: '100%',
                              background: alert.resonance_score >= 0.8 ? 'var(--danger)' : 'var(--warning)'
                            }} />
                          </div>
                        </div>
                      </td>
                      <td>
                        <span className="badge badge-accent">
                          {alert.layers_fired} / 3 طبقات
                        </span>
                      </td>
                      <td>
                        {alert.reviewed ? (
                          <span style={{ color: alert.false_positive ? 'var(--warning)' : 'var(--success)', display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                            <CheckCircle size={14} /> {alert.false_positive ? 'إيجابي زائف' : 'تمت المراجعة'}
                          </span>
                        ) : (
                          <div style={{ display: 'flex', gap: 8 }}>
                            <button
                              className="dns-btn-primary" style={{ padding: '3px 10px', fontSize: '0.75rem', background: 'var(--success)', color: '#000' }}
                              onClick={() => handleReview(alert.id)}
                              disabled={reviewAlert.isPending}
                            >
                              تأكيد المراجعة
                            </button>
                            <button
                              className="dns-btn-primary" style={{ padding: '3px 10px', fontSize: '0.75rem', background: 'var(--warning)', color: '#000' }}
                              onClick={() => handleFlagFalsePositive(alert.id)}
                              disabled={flagFalsePositive.isPending}
                            >
                              إيجابي زائف
                            </button>
                          </div>
                        )}
                      </td>
                      <td>
                        <button
                          className="dns-icon-btn" style={{ color: 'var(--accent)' }}
                          onClick={() => toggleExpand(alert.id)}
                          title="عرض أدلة XAI"
                        >
                          <Eye size={15} />
                        </button>
                      </td>
                    </tr>
                    {expandedId === alert.id && (
                      <tr>
                        <td colSpan={6} style={{ background: 'var(--bg-hover)', padding: 'var(--sp-4)' }}>
                          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 'var(--sp-4)' }}>
                            {/* Layer 1: Lexical */}
                            <div style={{ background: 'var(--bg-card)', padding: 'var(--sp-3)', borderRadius: 8, border: '1px solid var(--border)' }}>
                              <div style={{ fontWeight: 700, color: 'var(--accent)', marginBottom: 6, display: 'flex', justifyContent: 'space-between' }}>
                                <span>الطبقة الأولى: التحليل اللغوي</span>
                                <span>{(alert.evidence?.lexical?.score * 100 || 0).toFixed(0)}%</span>
                              </div>
                              <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                                <strong>السبب:</strong> {alert.evidence?.lexical?.reason || 'طبيعي'}<br />
                                <strong>الإنتروبيا:</strong> {alert.evidence?.lexical?.details?.entropy_norm?.toFixed(2) || '—'}<br />
                                <strong>Markov Surprise:</strong> {alert.evidence?.lexical?.details?.markov_surprise?.toFixed(2) || '—'}
                              </div>
                            </div>
                            {/* Layer 2: Temporal */}
                            <div style={{ background: 'var(--bg-card)', padding: 'var(--sp-3)', borderRadius: 8, border: '1px solid var(--border)' }}>
                              <div style={{ fontWeight: 700, color: 'var(--accent)', marginBottom: 6, display: 'flex', justifyContent: 'space-between' }}>
                                <span>الطبقة الثانية: السلوك الزمني</span>
                                <span>{(alert.evidence?.temporal?.score * 100 || 0).toFixed(0)}%</span>
                              </div>
                              <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                                <strong>السبب:</strong> {alert.evidence?.temporal?.reason || 'طبيعي'}<br />
                                <strong>عدد الطلبات:</strong> {alert.evidence?.temporal?.query_count || '—'}<br />
                                <strong>معامل الاختلاف (CV):</strong> {alert.evidence?.temporal?.cv?.toFixed(4) || '—'}
                              </div>
                            </div>
                            {/* Layer 3: Graph */}
                            <div style={{ background: 'var(--bg-card)', padding: 'var(--sp-3)', borderRadius: 8, border: '1px solid var(--border)' }}>
                              <div style={{ fontWeight: 700, color: 'var(--accent)', marginBottom: 6, display: 'flex', justifyContent: 'space-between' }}>
                                <span>الطبقة الثالثة: الارتباط الشبكي</span>
                                <span>{(alert.evidence?.graph?.score * 100 || 0).toFixed(0)}%</span>
                              </div>
                              <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                                <strong>السبب:</strong> {alert.evidence?.graph?.reason || 'طبيعي'}<br />
                                <strong>الأجهزة المرتبطة:</strong> {alert.evidence?.graph?.unique_hosts || '—'} أجهزة
                              </div>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
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

export default DNSDartAlertsView;
