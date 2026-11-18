import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { emailApi } from '../api/emailApi';
import { RefreshCw, Filter, List, Mail, Search, Download, X, Shield, Eye, Brain, Link2, Paperclip, AlertTriangle } from 'lucide-react';
import { useEmailSecurityStore } from '../../../stores/emailSecurityStore';

const DECISION_META = {
  allow:      { label: 'سماح', cls: 'em-dec-badge--allow'      },
  quarantine: { label: 'عزل',  cls: 'em-dec-badge--quarantine' },
  block:      { label: 'حظر',  cls: 'em-dec-badge--block'      },
};

const THREAT_TAGS = [
  { key: 'is_phishing',       label: 'تصيّد',     color: '#ff5f5f', bg: 'rgba(255,95,95,0.12)',   border: 'rgba(255,95,95,0.22)'   },
  { key: 'is_spam',           label: 'مزعج',      color: '#fbbf24', bg: 'rgba(251,191,36,0.1)',   border: 'rgba(251,191,36,0.22)'  },
  { key: 'has_malicious_url', label: 'روابط خبيثة', color: '#ff5f5f', bg: 'rgba(255,95,95,0.12)',  border: 'rgba(255,95,95,0.22)'   },
];

export default function EmailLogs() {
  const store = useEmailSecurityStore();
  const filter = store.logsFilter;
  const setFilter = store.setLogsFilter;
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedLog, setSelectedLog] = useState(null);

  const cachedLogs = store.cachedLogs;
  const { data: logs = cachedLogs, isFetching, refetch } = useQuery({
    queryKey:        ['email_logs', filter],
    queryFn:         () => emailApi.logs(filter ? { decision: filter } : {}).then(r => {
      store.setCachedLogs(r.data);
      return r.data;
    }),
    refetchInterval: 15000,
    placeholderData: cachedLogs,
    staleTime: 5 * 60 * 1000,
    gcTime: 10 * 60 * 1000,
  });

  const filteredLogs = logs.filter(log => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    const sender = (log.sender || '').toLowerCase();
    const subject = (log.subject || '').toLowerCase();
    const ip = (log.src_ip || '').toLowerCase();
    return sender.includes(q) || subject.includes(q) || ip.includes(q);
  });

  const exportJSON = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(filteredLogs, null, 2));
    const a = document.createElement('a');
    a.setAttribute("href", dataStr);
    a.setAttribute("download", `email_security_logs_${new Date().toISOString().slice(0,10)}.json`);
    document.body.appendChild(a);
    a.click();
    a.remove();
  };

  const exportCSV = () => {
    if (!filteredLogs.length) return;
    const headers = ["Time", "Sender", "Subject", "Source IP", "Risk Score", "Decision", "Phishing", "Spam", "AI Mimicry", "Visual Desync"];
    const rows = filteredLogs.map(l => [
      l.inspected_at || '',
      `"${(l.sender || '').replace(/"/g, '""')}"`,
      `"${(l.subject || '').replace(/"/g, '""')}"`,
      l.src_ip || '',
      l.risk_score || 0,
      l.decision || '',
      l.is_phishing ? 'Yes' : 'No',
      l.is_spam ? 'Yes' : 'No',
      l.is_ai_mimicry ? 'Yes' : 'No',
      l.has_visual_desync ? 'Yes' : 'No',
    ]);
    const csvContent = "data:text/csv;charset=utf-8,\uFEFF" + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const a = document.createElement('a');
    a.setAttribute("href", encodeURI(csvContent));
    a.setAttribute("download", `email_security_logs_${new Date().toISOString().slice(0,10)}.csv`);
    document.body.appendChild(a);
    a.click();
    a.remove();
  };

  return (
    <div className="em-panel">
      <div className="em-panel-header">
        <div className="em-panel-title"><List size={14} /> سجلات الفحص العميق</div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          {/* Search bar */}
          <div className="em-filter-bar" style={{ padding: '4px 8px' }}>
            <Search size={12} style={{ color: 'rgba(255,255,255,0.35)' }} />
            <input
              type="text"
              placeholder="بحث بالمرسل، الموضوع، أو IP..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              style={{
                background: 'none', border: 'none', outline: 'none', color: '#f0f0f5',
                fontSize: '.78rem', fontFamily: 'Cairo, sans-serif', width: '160px'
              }}
            />
            {searchQuery && (
              <X size={12} style={{ cursor: 'pointer', color: 'rgba(255,255,255,0.4)' }} onClick={() => setSearchQuery('')} />
            )}
          </div>

          {/* Decision Filter */}
          <div className="em-filter-bar">
            <Filter size={12} style={{ color: 'rgba(255,255,255,0.25)' }} />
            <select className="em-filter-select" value={filter} onChange={e => setFilter(e.target.value)}>
              <option value="">جميع القرارات</option>
              <option value="allow">مسموح</option>
              <option value="quarantine">معزول</option>
              <option value="block">محظور</option>
            </select>
          </div>

          {/* Export button */}
          <button className="em-refresh-btn" onClick={exportCSV} title="تصدير CSV" style={{ width: 'auto', padding: '0 8px', gap: 4, fontSize: '.72rem' }}>
            <Download size={12} /> CSV
          </button>
          <button className="em-refresh-btn" onClick={exportJSON} title="تصدير JSON" style={{ width: 'auto', padding: '0 8px', gap: 4, fontSize: '.72rem' }}>
            <Download size={12} /> JSON
          </button>

          {/* Refresh */}
          <button className="em-refresh-btn" onClick={() => refetch()} title="تحديث">
            <RefreshCw size={14} className={isFetching ? 'em-spin' : ''} />
          </button>
        </div>
      </div>

      <div className="em-table-wrap">
        <table className="em-table">
          <thead>
            <tr>
              <th>الوقت</th>
              <th>المُرسل / IP</th>
              <th>الموضوع</th>
              <th>عامل الخطر</th>
              <th>الاكتشافات</th>
              <th>القرار</th>
              <th style={{ textAlign: 'center' }}>التفاصيل</th>
            </tr>
          </thead>
          <tbody>
            {filteredLogs.length === 0 && (
              <tr><td colSpan={7}>
                <div className="em-empty">
                  <Mail size={28} style={{ opacity: 0.09 }} />
                  <span>لا توجد سجلات تطابق خيارات الفلترة.</span>
                </div>
              </td></tr>
            )}
            {filteredLogs.map(log => {
              const riskScore = log.risk_score ?? 0;
              const riskCls   = riskScore > 0.7 ? 'em-risk--hi' : riskScore > 0.4 ? 'em-risk--mid' : 'em-risk--lo';
              const dec       = DECISION_META[log.decision] || { label: log.decision, cls: '' };
              return (
                <tr key={log.id} className="em-row" style={{ cursor: 'pointer' }} onClick={() => setSelectedLog(log)}>
                  {/* Time */}
                  <td>
                    <span className="em-mono" style={{ fontSize: '.74rem', color: 'rgba(255,255,255,0.3)', whiteSpace: 'nowrap' }}>
                      {new Date(log.inspected_at).toLocaleString('ar-SA')}
                    </span>
                  </td>
                  {/* Sender */}
                  <td>
                    <div className="em-mono" style={{ color: 'rgba(255,255,255,0.6)', fontSize: '.78rem' }} dir="ltr">
                      {log.sender || '<غير معروف>'}
                    </div>
                    {log.src_ip && (
                      <div className="em-mono" style={{ fontSize: '.68rem', color: 'rgba(255,255,255,0.2)', marginTop: 2 }} dir="ltr">
                        {log.src_ip}
                      </div>
                    )}
                  </td>
                  {/* Subject */}
                  <td style={{ maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: '.82rem', color: 'rgba(255,255,255,0.65)' }}>
                    {log.subject || '(بدون موضوع)'}
                  </td>
                  {/* Risk score */}
                  <td>
                    <span className={`em-risk-score ${riskCls}`}>{riskScore.toFixed(2)}</span>
                  </td>
                  {/* Tags */}
                  <td>
                    <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                      {THREAT_TAGS.map(tt => log[tt.key] && (
                        <span key={tt.key} className="em-tag" style={{ color: tt.color, background: tt.bg, borderColor: tt.border }}>
                          {tt.label}
                        </span>
                      ))}
                      {log.brand_spoof && (
                        <span className="em-tag" style={{ color: '#c084fc', background: 'rgba(192,132,252,0.1)', borderColor: 'rgba(192,132,252,0.22)' }}>
                          انتحال: {log.brand_spoof}
                        </span>
                      )}
                    </div>
                  </td>
                  {/* Decision */}
                  <td>
                    <span className={`em-dec-badge ${dec.cls}`}>{dec.label}</span>
                  </td>
                  {/* Action */}
                  <td style={{ textAlign: 'center' }}>
                    <button
                      className="em-del-btn"
                      style={{ color: '#818cf8', borderColor: 'rgba(129,140,248,0.2)' }}
                      onClick={(e) => { e.stopPropagation(); setSelectedLog(log); }}
                      title="عرض تقرير الفحص التفصيلي"
                    >
                      <Eye size={12} />
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Detail Modal */}
      {selectedLog && (
        <div className="em-modal-overlay" onClick={() => setSelectedLog(null)}>
          <div className="em-modal-card" onClick={e => e.stopPropagation()}>
            <div className="em-modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Shield size={18} style={{ color: '#818cf8' }} />
                <span style={{ fontWeight: 800, fontSize: '1rem', color: '#f0f0f5' }}>تقرير الفحص الأمني للرسالة</span>
              </div>
              <button className="em-del-btn" onClick={() => setSelectedLog(null)}>
                <X size={14} />
              </button>
            </div>

            <div className="em-modal-body">
              {/* Top Summary */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 16 }}>
                <div style={{ background: 'rgba(255,255,255,0.02)', padding: 12, borderRadius: 8, border: '1px solid rgba(255,255,255,0.05)' }}>
                  <div style={{ fontSize: '.7rem', color: 'rgba(255,255,255,0.35)', marginBottom: 4 }}>المُرسل</div>
                  <div style={{ fontFamily: 'Fira Code, monospace', fontSize: '.85rem', color: '#f0f0f5' }} dir="ltr">{selectedLog.sender || 'غير محدد'}</div>
                  <div style={{ fontSize: '.7rem', color: 'rgba(255,255,255,0.25)', marginTop: 4 }}>IP: {selectedLog.src_ip || 'N/A'} Port: {selectedLog.dst_port || 25}</div>
                </div>
                <div style={{ background: 'rgba(255,255,255,0.02)', padding: 12, borderRadius: 8, border: '1px solid rgba(255,255,255,0.05)' }}>
                  <div style={{ fontSize: '.7rem', color: 'rgba(255,255,255,0.35)', marginBottom: 4 }}>القرار الكلي للـ NGFW</div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 4 }}>
                    <span className={`em-dec-badge ${DECISION_META[selectedLog.decision]?.cls || ''}`}>
                      {DECISION_META[selectedLog.decision]?.label || selectedLog.decision}
                    </span>
                    <span style={{ fontFamily: 'Fira Code', fontWeight: 800, fontSize: '1rem', color: selectedLog.risk_score > 0.7 ? '#ff5f5f' : '#28c76f' }}>
                      الخطر: {Math.round((selectedLog.risk_score || 0) * 100)}%
                    </span>
                  </div>
                </div>
              </div>

              {/* Subject */}
              <div style={{ background: 'rgba(255,255,255,0.02)', padding: 12, borderRadius: 8, border: '1px solid rgba(255,255,255,0.05)', marginBottom: 16 }}>
                <div style={{ fontSize: '.7rem', color: 'rgba(255,255,255,0.35)', marginBottom: 4 }}>موضوع الرسالة (Subject)</div>
                <div style={{ fontSize: '.88rem', color: '#f0f0f5', fontWeight: 600 }}>{selectedLog.subject || '(بدون موضوع)'}</div>
              </div>

              {/* 6 Sub-scores breakdown */}
              <div style={{ fontSize: '.8rem', fontWeight: 700, color: 'rgba(255,255,255,0.5)', marginBottom: 8 }}>درجات محركات التقييم السباعية (Inspection Breakdown)</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10, marginBottom: 16 }}>
                {[
                  { name: 'التصيد (Phishing)', val: selectedLog.phishing_score, color: '#ff5f5f', icon: AlertTriangle },
                  { name: 'الروابط (URL)', val: selectedLog.url_score, color: '#fb923c', icon: Link2 },
                  { name: 'المرفقات', val: selectedLog.attachment_score, color: '#ef4444', icon: Paperclip },
                  { name: 'السمعة (Sender)', val: selectedLog.sender_score, color: '#fbbf24', icon: Shield },
                  { name: 'PLSF (BEC/AI)', val: selectedLog.linguistic_anomaly, color: '#a78bfa', icon: Brain },
                  { name: 'VSDE (CSS Evasion)', val: selectedLog.visual_desync, color: '#fb923c', icon: Eye },
                ].map(s => (
                  <div key={s.name} style={{ background: 'rgba(255,255,255,0.02)', padding: 10, borderRadius: 8, border: '1px solid rgba(255,255,255,0.04)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyBetween: 'space-between', fontSize: '.68rem', color: 'rgba(255,255,255,0.35)', marginBottom: 4 }}>
                      <span style={{ display: 'flex', alignItems: 'center', gap: 3 }}><s.icon size={11} />{s.name}</span>
                    </div>
                    <div style={{ fontSize: '1rem', fontWeight: 800, color: s.color, fontFamily: 'Fira Code' }}>
                      {Math.round((s.val || 0) * 100)}%
                    </div>
                  </div>
                ))}
              </div>

              {/* Keywords and URLs */}
              {selectedLog.matched_keywords?.length > 0 && (
                <div style={{ marginBottom: 12 }}>
                  <div style={{ fontSize: '.72rem', color: 'rgba(255,255,255,0.35)', marginBottom: 6 }}>الكلمات المفتاحية المكتشفة:</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                    {selectedLog.matched_keywords.map(kw => (
                      <span key={kw} style={{ fontSize: '.7rem', padding: '3px 8px', borderRadius: 6, background: 'rgba(255,95,95,0.12)', color: '#ff8a80', border: '1px solid rgba(255,95,95,0.25)' }}>
                        {kw}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {selectedLog.flagged_urls?.length > 0 && (
                <div style={{ marginBottom: 12 }}>
                  <div style={{ fontSize: '.72rem', color: 'rgba(255,255,255,0.35)', marginBottom: 6 }}>الروابط المشبوهة/المحظورة:</div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    {selectedLog.flagged_urls.map(url => (
                      <div key={url} style={{ fontSize: '.72rem', fontFamily: 'Fira Code', color: '#fb923c', background: 'rgba(251,146,60,0.08)', padding: '4px 8px', borderRadius: 4, border: '1px solid rgba(251,146,60,0.15)' }} dir="ltr">
                        {url}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Technical Latency */}
              <div style={{ marginTop: 16, paddingTop: 12, borderTop: '1px solid rgba(255,255,255,0.05)', fontSize: '.72rem', color: 'rgba(255,255,255,0.25)', display: 'flex', justifyContent: 'space-between' }}>
                <span>زمن الفحص: <strong style={{ color: 'rgba(255,255,255,0.5)', fontFamily: 'Fira Code' }}>{selectedLog.latency_ms ? `${selectedLog.latency_ms.toFixed(1)} ms` : '—'}</strong></span>
                <span>تاريخ الفحص: <strong style={{ color: 'rgba(255,255,255,0.5)' }}>{selectedLog.inspected_at ? new Date(selectedLog.inspected_at).toLocaleString('ar-SA') : '—'}</strong></span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

