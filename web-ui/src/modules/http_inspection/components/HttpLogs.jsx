import React, { useState, useMemo } from 'react';
import { AlertTriangle, RefreshCw, Shield, Search, Download, Filter } from 'lucide-react';

export function HttpLogs({ logs, logsLoading }) {
  const [expandedLogId, setExpandedLogId] = useState(null);
  const [search, setSearch] = useState('');
  const [methodFilter, setMethodFilter] = useState('ALL');

  const toggleExpandLog = (id) => setExpandedLogId(expandedLogId === id ? null : id);

  const filteredLogs = useMemo(() => {
    return (logs || []).filter(L => {
      if (methodFilter !== 'ALL' && (L.request_method || 'GET').toUpperCase() !== methodFilter) {
        return false;
      }
      if (search.trim()) {
        const q = search.toLowerCase();
        const matchIp = L.source_ip?.toLowerCase().includes(q);
        const matchHost = L.target_host?.toLowerCase().includes(q);
        const matchPath = L.url_path?.toLowerCase().includes(q);
        const matchPattern = L.pattern_matched?.toLowerCase().includes(q);
        const matchFlow = L.flow_id?.toLowerCase().includes(q);
        if (!matchIp && !matchHost && !matchPath && !matchPattern && !matchFlow) return false;
      }
      return true;
    });
  }, [logs, search, methodFilter]);

  const exportLogs = (format) => {
    if (!logs || !logs.length) return;
    let dataStr = '';
    let fileName = `http_attack_logs_${new Date().toISOString().slice(0, 10)}`;
    
    if (format === 'json') {
      dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(logs, null, 2));
      fileName += '.json';
    } else {
      const headers = ['Timestamp', 'Source IP', 'Method', 'Host', 'URL Path', 'Matched Pattern', 'Action', 'Flow ID'];
      const rows = logs.map(l => [
        l.timestamp,
        l.source_ip,
        l.request_method || 'GET',
        l.target_host || '',
        l.url_path || '',
        `"${(l.pattern_matched || '').replace(/"/g, '""')}"`,
        l.action,
        l.flow_id || ''
      ]);
      const csvContent = [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
      dataStr = "data:text/csv;charset=utf-8," + encodeURIComponent(csvContent);
      fileName += '.csv';
    }

    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", fileName);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="http-panel">
      <div className="http-panel-header" style={{ flexWrap: 'wrap', gap: 12 }}>
        <div className="http-panel-title">
          <AlertTriangle size={14} style={{color: '#ff5f5f'}}/> سجل صد الهجمات (منفصل)
          <span className="http-count-pill" style={{color: '#ff5f5f', borderColor: '#ff5f5f22', background: '#ff5f5f11', marginRight: 6}}>
            {filteredLogs.length} / {logs?.length || 0} هجمة
          </span>
        </div>

        {/* Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <div className="http-search-box">
            <Search size={13} style={{ color: 'rgba(255,255,255,0.3)' }} />
            <input
              className="http-search-input"
              type="text"
              placeholder="البحث بالـ IP، المسار، أو النمط..."
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
          </div>

          <select className="http-filter-select" value={methodFilter} onChange={e => setMethodFilter(e.target.value)}>
            <option value="ALL">جميع الطرق (Methods)</option>
            <option value="GET">GET</option>
            <option value="POST">POST</option>
            <option value="PUT">PUT</option>
            <option value="DELETE">DELETE</option>
          </select>

          <button className="http-export-btn" title="تصدير السجلات JSON" onClick={() => exportLogs('json')}>
            <Download size={12} /> JSON
          </button>
          <button className="http-export-btn" title="تصدير السجلات CSV" onClick={() => exportLogs('csv')}>
            <Download size={12} /> CSV
          </button>
        </div>
      </div>

      <div className="http-table-wrap">
        <table className="http-table">
          <thead>
            <tr>
              <th>وقت الهجوم</th>
              <th>الـ IP المهاجم</th>
              <th>طريقة الطلب</th>
              <th>الهدف (Host)</th>
              <th>المسار المصاب</th>
              <th>النمط المكتشف</th>
              <th>الحالة</th>
            </tr>
          </thead>
          <tbody>
            {logsLoading && (
              <tr><td colSpan={7}><div className="http-loading"><RefreshCw size={14} className="http-spin" /> جاري التحميل...</div></td></tr>
            )}
            {!logsLoading && (!logs || !logs.length) && (
              <tr><td colSpan={7}>
                <div className="http-empty"><Shield size={26} style={{opacity:.15, color: '#28c76f'}}/><span>النظام آمن. لم يتم رصد هجمات HTTP مؤخراً.</span></div>
              </td></tr>
            )}
            {!logsLoading && logs && logs.length > 0 && filteredLogs.length === 0 && (
              <tr><td colSpan={7}>
                <div className="http-empty"><Filter size={24} style={{opacity:.15}}/><span>لا توجد سجلات هجوم تطابق شروط التصفية الحالية.</span></div>
              </td></tr>
            )}
            {filteredLogs.map(L => {
              const isExpanded = expandedLogId === L.id;
              let parsedDetails = 'لا توجد تفاصيل إضافية';
              if (L.details) {
                try {
                  const formatted = L.details.replace(/'/g, '"').replace(/True/g, 'true').replace(/False/g, 'false').replace(/None/g, 'null');
                  parsedDetails = JSON.stringify(JSON.parse(formatted), null, 2);
                } catch (e) {
                  parsedDetails = L.details;
                }
              }
              return (
                <React.Fragment key={L.id}>
                  <tr className="http-row" style={{background: 'rgba(255,95,95,.03)', cursor: 'pointer'}} onClick={() => toggleExpandLog(L.id)}>
                    <td style={{fontFamily: 'Fira Code, monospace', fontSize: '0.8rem', color: '#aaa'}}>
                      {new Date(L.timestamp).toLocaleString('ar-EG', {hour: '2-digit', minute: '2-digit', second: '2-digit'})}
                    </td>
                    <td style={{color: '#ff5f5f', fontFamily: 'Fira Code, monospace'}}>{L.source_ip}</td>
                    <td>
                      <span className="badge" style={{ background: 'var(--bg-overlay)', color: 'var(--accent)', fontFamily: 'Fira Code, monospace', fontSize: '0.72rem', padding: '2px 6px', borderRadius: 3 }}>
                        {(L.request_method || 'GET').toUpperCase()}
                      </span>
                    </td>
                    <td style={{color: '#818cf8'}}>{L.target_host || '-'}</td>
                    <td>
                      <div style={{maxWidth: '180px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', fontFamily: 'Fira Code, monospace', direction: 'ltr', textAlign: 'left'}} title={L.url_path}>
                        {L.url_path || '-'}
                      </div>
                    </td>
                    <td style={{fontSize: '0.85rem'}}>{L.pattern_matched}</td>
                    <td>
                      <span className="http-state-badge http-state-badge--off" style={{background: 'rgba(255,95,95,.15)', color: '#ff5f5f', borderColor: 'rgba(255,95,95,.3)'}}>
                        {L.action === 'BLOCK' ? 'بلوك 🚫' : L.action}
                      </span>
                    </td>
                  </tr>
                  {isExpanded && (
                    <tr style={{ background: 'var(--bg-overlay)' }}>
                      <td colSpan={7} style={{ padding: '16px', borderTop: '1px solid rgba(255,255,255,0.05)', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px', marginBottom: '12px' }}>
                          <div>
                            <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>مُعرف التدفق (Flow ID)</span>
                            <p style={{ margin: '4px 0 0 0', fontFamily: 'var(--font-mono)', fontSize: '0.82rem', color: 'var(--accent)' }}>{L.flow_id || 'غير متوفر'}</p>
                          </div>
                          <div>
                            <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>بصمة متصفح العميل (User-Agent Hash)</span>
                            <p style={{ margin: '4px 0 0 0', fontFamily: 'var(--font-mono)', fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                              {L.user_agent_hash ? `${L.user_agent_hash.substring(0, 16)}...` : '-'}
                            </p>
                          </div>
                          <div>
                            <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>الترويسة الكاملة للمتصفح (User-Agent)</span>
                            <p style={{ margin: '4px 0 0 0', fontSize: '0.8rem', wordBreak: 'break-all', color: '#c0ccff' }}>{L.user_agent_raw || 'غير متوفر'}</p>
                          </div>
                        </div>
                        <div style={{ marginTop: '8px' }}>
                          <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>أدلة الهجوم (Attack Evidence)</span>
                          <pre style={{ margin: '4px 0 0 0', background: 'var(--bg-card)', padding: '10px', borderRadius: 6, fontSize: '0.78rem', color: '#10b981', overflowX: 'auto', fontFamily: 'var(--font-mono)' }}>
                            {parsedDetails}
                          </pre>
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

