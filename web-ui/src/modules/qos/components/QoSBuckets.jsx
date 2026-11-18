import React, { useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { RotateCcw, Shield, Download, ArrowUpDown, RefreshCw, AlertCircle } from 'lucide-react';
import { SectionCard, FilterBar, SkeletonLines, EmptyState, ProgressBar } from '../../../components/Shared';

export function QoSBuckets({
  buckets = [],
  search,
  setSearch,
  statsLoading,
  resetBucket,
  resettingBucket,
  fmtBits,
  fmtBytes
}) {
  const [tierFilter, setTierFilter] = useState('all'); // 'all' | 'critical' (>80) | 'moderate' (>50)
  const [sortField, setSortField] = useState('utilization_pct');
  const [sortOrder, setSortOrder] = useState('desc');
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 15;

  const handleSort = (field) => {
    if (sortField === field) {
      setSortOrder(prev => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortOrder('desc');
    }
  };

  const filtered = useMemo(() => {
    return buckets.filter(b => {
      const matchesSearch = !search || b.ip?.toLowerCase().includes(search.toLowerCase());
      if (!matchesSearch) return false;

      if (tierFilter === 'critical') return b.utilization_pct >= 80;
      if (tierFilter === 'moderate') return b.utilization_pct >= 50 && b.utilization_pct < 80;
      if (tierFilter === 'normal') return b.utilization_pct < 50;
      return true;
    });
  }, [buckets, search, tierFilter]);

  const sorted = useMemo(() => {
    return [...filtered].sort((a, b) => {
      let valA = a[sortField];
      let valB = b[sortField];

      if (typeof valA === 'string') {
        valA = valA.toLowerCase();
        valB = valB.toLowerCase();
      }

      if (valA < valB) return sortOrder === 'asc' ? -1 : 1;
      if (valA > valB) return sortOrder === 'asc' ? 1 : -1;
      return 0;
    });
  }, [filtered, sortField, sortOrder]);

  const totalPages = Math.ceil(sorted.length / pageSize) || 1;
  const paginated = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return sorted.slice(start, start + pageSize);
  }, [sorted, currentPage, pageSize]);

  const exportCSV = () => {
    if (sorted.length === 0) return;
    const headers = ['IP Address', 'Tokens Remaining', 'Capacity', 'Rate Limit (bps)', 'Utilization (%)'];
    const rows = sorted.map(b => [
      b.ip,
      b.tokens_remaining,
      b.capacity,
      b.fill_rate_bps,
      b.utilization_pct
    ]);
    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `qos_ip_buckets_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const handleResetAllOverloaded = async () => {
    const overloaded = buckets.filter(b => b.utilization_pct >= 80);
    if (overloaded.length === 0) return;
    if (window.confirm(`هل أنت تأكد من إعادة تعبئة الرموز لـ ${overloaded.length} عميل يتجاوزون السعة؟`)) {
      for (const b of overloaded) {
        await resetBucket(b.ip);
      }
    }
  };

  return (
    <SectionCard
      title={`حاويات IP النشطة (${filtered.length})`}
      icon={Shield}
      actions={
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <button
            className="btn btn-ghost btn-xs"
            onClick={exportCSV}
            disabled={sorted.length === 0}
            title="تصدير البيانات إلى ملف CSV"
            style={{ fontSize: '0.72rem' }}
          >
            <Download size={13} style={{ marginLeft: 4 }} /> تصدير CSV
          </button>
          <span className="badge badge-accent" style={{ fontSize: '0.65rem' }}>
            تحديث كل 5 ث
          </span>
        </div>
      }
    >
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
        <FilterBar
          placeholder="بحث بعنوان IP..."
          value={search}
          onChange={setSearch}
        />

        {/* Tier Filter Chips */}
        <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
          <button
            type="button"
            className={`btn btn-xs ${tierFilter === 'all' ? 'btn-accent' : 'btn-ghost'}`}
            onClick={() => { setTierFilter('all'); setCurrentPage(1); }}
            style={{ fontSize: '0.72rem' }}
          >
            الكل ({buckets.length})
          </button>
          <button
            type="button"
            className={`btn btn-xs ${tierFilter === 'critical' ? 'btn-danger' : 'btn-ghost'}`}
            onClick={() => { setTierFilter('critical'); setCurrentPage(1); }}
            style={{ fontSize: '0.72rem', color: tierFilter === 'critical' ? '#fff' : '#ff4d6a' }}
          >
            حرج ≥80% ({buckets.filter(b => b.utilization_pct >= 80).length})
          </button>
          <button
            type="button"
            className={`btn btn-xs ${tierFilter === 'moderate' ? 'btn-warning' : 'btn-ghost'}`}
            onClick={() => { setTierFilter('moderate'); setCurrentPage(1); }}
            style={{ fontSize: '0.72rem', color: tierFilter === 'moderate' ? '#fff' : '#ffab40' }}
          >
            متوسط 50-80% ({buckets.filter(b => b.utilization_pct >= 50 && b.utilization_pct < 80).length})
          </button>
          {buckets.some(b => b.utilization_pct >= 80) && (
            <button
              type="button"
              className="btn btn-ghost btn-xs"
              style={{ fontSize: '0.7rem', color: '#ff4d6a', borderColor: 'rgba(255,77,106,0.3)' }}
              onClick={handleResetAllOverloaded}
              disabled={resettingBucket}
            >
              <RotateCcw size={12} style={{ marginLeft: 3 }} /> إعادة تعبئة الحرج
            </button>
          )}
        </div>
      </div>

      {statsLoading ? (
        <SkeletonLines count={6} />
      ) : paginated.length === 0 ? (
        <EmptyState message={search || tierFilter !== 'all' ? 'لا توجد نتائج تطابق خيارات التصفية' : 'لا توجد حاويات نشطة حالياً'} />
      ) : (
        <>
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th onClick={() => handleSort('ip')} style={{ cursor: 'pointer' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                      عنوان IP <ArrowUpDown size={12} />
                    </div>
                  </th>
                  <th onClick={() => handleSort('tokens_remaining')} style={{ cursor: 'pointer' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                      الرموز المتبقية <ArrowUpDown size={12} />
                    </div>
                  </th>
                  <th onClick={() => handleSort('capacity')} style={{ cursor: 'pointer' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                      السعة <ArrowUpDown size={12} />
                    </div>
                  </th>
                  <th onClick={() => handleSort('fill_rate_bps')} style={{ cursor: 'pointer' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                      المعدل <ArrowUpDown size={12} />
                    </div>
                  </th>
                  <th onClick={() => handleSort('utilization_pct')} style={{ cursor: 'pointer' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                      الاستخدام <ArrowUpDown size={12} />
                    </div>
                  </th>
                  <th>إجراء</th>
                </tr>
              </thead>
              <tbody>
                <AnimatePresence mode="wait">
                  {paginated.map((b, i) => (
                    <motion.tr
                      key={b.ip}
                      initial={{ opacity: 0, x: -6 }}
                      animate={{ opacity: 1, x: 0 }}
                      exit={{ opacity: 0 }}
                      transition={{ delay: i * 0.02 }}
                    >
                      <td className="mono" style={{ fontWeight: 600, color: 'var(--info)' }}>{b.ip}</td>
                      <td className="mono">{Number(b.tokens_remaining).toLocaleString()}</td>
                      <td className="mono">{Number(b.capacity).toLocaleString()}</td>
                      <td className="mono">{fmtBits(b.fill_rate_bps)}</td>
                      <td style={{ minWidth: 160 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <ProgressBar
                            percent={b.utilization_pct}
                            color={
                              b.utilization_pct > 80 ? 'var(--danger)' :
                                b.utilization_pct > 50 ? 'var(--warning)' :
                                  'var(--accent)'
                            }
                          />
                          <span className="mono" style={{ fontSize: '0.72rem', minWidth: 42, textAlign: 'left', fontWeight: 600, color: b.utilization_pct > 80 ? '#ff4d6a' : 'inherit' }}>
                            {b.utilization_pct}%
                          </span>
                        </div>
                      </td>
                      <td>
                        <button
                          className="btn btn-ghost"
                          style={{ padding: '4px 10px', fontSize: '0.72rem' }}
                          onClick={() => resetBucket(b.ip)}
                          disabled={resettingBucket}
                          title="إعادة تعبئة الرموز لهذا IP"
                        >
                          <RotateCcw size={13} />
                        </button>
                      </td>
                    </motion.tr>
                  ))}
                </AnimatePresence>
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '14px', paddingTop: '10px', borderTop: '1px solid var(--border-color)' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                عرض الصفحة {currentPage} من {totalPages} ({sorted.length} عنصر)
              </span>
              <div style={{ display: 'flex', gap: '6px' }}>
                <button
                  type="button"
                  className="btn btn-ghost btn-xs"
                  onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                  disabled={currentPage === 1}
                >
                  السابق
                </button>
                <button
                  type="button"
                  className="btn btn-ghost btn-xs"
                  onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                  disabled={currentPage === totalPages}
                >
                  التالي
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </SectionCard>
  );
}

