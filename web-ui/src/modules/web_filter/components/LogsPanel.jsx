import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Activity, RefreshCw, ShieldCheck, Laptop, Pause, Play, Search, Filter, Info, X } from 'lucide-react';
import { ActionBadge } from './ActionBadge';

export function LogsPanel({ logs = [], isLoading, liveStreamPaused, setLiveStreamPaused, onRefresh }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [actionFilter, setActionFilter] = useState('ALL');
  const [selectedLog, setSelectedLog] = useState(null);

  const filteredLogs = logs.filter(log => {
    const actionStr = (log.metadata?.action || log.action || 'ALLOW').toUpperCase();
    const targetUrl = (log.metadata?.domain || log.metadata?.target || log.description || '').toLowerCase();
    const srcIp = (log.source_ip || log.metadata?.src_ip || '').toLowerCase();

    const matchesSearch = targetUrl.includes(searchTerm.toLowerCase()) || srcIp.includes(searchTerm.toLowerCase());
    const matchesAction = actionFilter === 'ALL' || actionStr === actionFilter;

    return matchesSearch && matchesAction;
  });

  if (isLoading && logs.length === 0) return (
    <div className="wf-loading"><RefreshCw size={18} className="wf-spin" /> جاري سحب سجلات العبور المباشرة...</div>
  );

  return (
    <div className="wf-panel" style={{ padding: '20px' }}>
      {/* Toolbar */}
      <div className="wf-toolbar" style={{ marginBottom: '16px', gap: '12px' }}>
        <div className="wf-panel-title">
          <Activity size={16} style={{ color: '#28c76f' }} /> سجلات العبور والمراقبة الحية (Live Web Traffic Stream)
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          {/* Search */}
          <div className="wf-search-bar" style={{ padding: '4px 10px' }}>
            <Search size={13} />
            <input
              className="wf-search"
              style={{ width: '160px' }}
              placeholder="بحث في النطاق / IP..."
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
            />
          </div>

          {/* Action Filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '4px', background: 'rgba(255,255,255,0.04)', borderRadius: '8px', padding: '2px 6px', border: '1px solid rgba(255,255,255,0.07)' }}>
            <Filter size={12} style={{ color: '#aaa', marginLeft: '4px' }} />
            <select
              className="wf-select"
              style={{ padding: '4px 8px', fontSize: '11px', border: 'none', background: 'none' }}
              value={actionFilter}
              onChange={e => setActionFilter(e.target.value)}
            >
              <option value="ALL">جميع الإجراءات</option>
              <option value="BLOCK">حظر (BLOCK)</option>
              <option value="ALLOW">سماح (ALLOW)</option>
              <option value="MONITOR">مراقبة (MONITOR)</option>
            </select>
          </div>

          {/* Stream Pause / Play */}
          <button
            className={`wf-btn wf-btn--sm ${liveStreamPaused ? 'wf-btn--primary' : 'wf-btn--secondary'}`}
            style={{ padding: '6px 12px', fontSize: '11px' }}
            onClick={() => setLiveStreamPaused(!liveStreamPaused)}
            title={liveStreamPaused ? 'استئناف التدفق المباشر' : 'إيقاف مؤقت للتدفق المباشر'}
          >
            {liveStreamPaused ? <><Play size={12} /> استئناف</> : <><Pause size={12} /> إيقاف مؤقت</>}
          </button>

          {/* Manual Refresh */}
          <button
            className="wf-btn wf-btn--secondary wf-btn--sm"
            style={{ padding: '6px 10px' }}
            onClick={onRefresh}
            title="تحديث السجلات الآن"
          >
            <RefreshCw size={12} />
          </button>

          <span className="wf-count-info">{filteredLogs.length} حدث</span>
        </div>
      </div>

      {/* Event list */}
      <div className="wf-log-grid">
        {filteredLogs.length === 0 && (
          <div className="wf-empty">
            <ShieldCheck size={32} style={{ opacity: 0.1 }} />
            <span>لا توجد أي سجلات عبور تطابق معايير التصفية الحالية.</span>
          </div>
        )}

        {filteredLogs.map((log, idx) => {
          const actionStr = (log.metadata?.action || log.action || 'ALLOW').toUpperCase();
          const targetUrl = log.metadata?.domain || log.metadata?.target || (log.description?.includes("'") ? log.description.split("'")[1] : log.description) || 'Unknown Target';
          const srcIp = log.source_ip || log.metadata?.src_ip || '192.168.1.105';
          const timestamp = new Date(log.timestamp || Date.now()).toLocaleTimeString('en-US', { hour12: false });

          return (
            <motion.div
              key={log.id || `${log.timestamp}-${idx}`}
              className="wf-log-row"
              initial={{ opacity: 0, x: 15 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.15, delay: Math.min(idx * 0.015, 0.2) }}
              onClick={() => setSelectedLog(log)}
              style={{ cursor: 'pointer' }}
            >
              <div className="wf-log-time">{timestamp}</div>
              <div className="wf-log-domain">{targetUrl}</div>
              <div className="wf-log-identity" title="عنوان المصدر (Source IP)">
                <Laptop size={12} /> {srcIp}
              </div>
              <div className="wf-log-action">
                <ActionBadge action={actionStr} />
              </div>
            </motion.div>
          );
        })}
      </div>

      {/* Selected Log Drawer/Modal */}
      <AnimatePresence>
        {selectedLog && (
          <div className="wf-modal-overlay">
            <motion.div
              className="wf-modal"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              style={{ maxWidth: '540px' }}
            >
              <div className="wf-modal-header">
                <div className="wf-modal-title">
                  <Info size={16} style={{ color: '#60a5fa' }} />
                  تفاصيل الحدث الأمني (Security Event Breakdown)
                </div>
                <button className="wf-modal-close" onClick={() => setSelectedLog(null)}>
                  <X size={16} />
                </button>
              </div>

              <div className="wf-modal-body" style={{ fontSize: '13px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.06)', paddingBottom: '8px' }}>
                  <span style={{ color: '#aaa' }}>الوقت والتاريخ:</span>
                  <span className="wf-mono">{new Date(selectedLog.timestamp || Date.now()).toLocaleString('en-US')}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.06)', paddingBottom: '8px' }}>
                  <span style={{ color: '#aaa' }}>اسم النطاق / Target:</span>
                  <span className="wf-mono" style={{ color: '#f0f0f5', fontWeight: 700 }}>{selectedLog.metadata?.domain || selectedLog.metadata?.target || selectedLog.description}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.06)', paddingBottom: '8px' }}>
                  <span style={{ color: '#aaa' }}>IP المصدر (Source IP):</span>
                  <span className="wf-mono" style={{ color: '#60a5fa' }}>{selectedLog.source_ip || selectedLog.metadata?.src_ip || 'N/A'}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.06)', paddingBottom: '8px' }}>
                  <span style={{ color: '#aaa' }}>الإجراء المتخذ (Action):</span>
                  <ActionBadge action={(selectedLog.metadata?.action || selectedLog.action || 'ALLOW').toUpperCase()} />
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', marginTop: '6px' }}>
                  <span style={{ color: '#aaa' }}>البيانات الخام (Raw Payload):</span>
                  <pre className="wf-mono" style={{ background: '#0a0c12', padding: '10px', borderRadius: '8px', overflowX: 'auto', fontSize: '11px', color: '#94a3b8' }}>
                    {JSON.stringify(selectedLog, null, 2)}
                  </pre>
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
