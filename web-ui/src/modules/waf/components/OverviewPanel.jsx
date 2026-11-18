import React, { useState, useEffect, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Activity, Cpu, AlertOctagon, Crosshair, Wifi, Shield, Search, Download, Trash2, X, Eye, AlertTriangle, Zap, Play } from 'lucide-react';
import { KpiCard, SectionCard, EmptyState } from '../../../components/Shared';
import { useLiveFeedStore } from '../../../stores/liveFeedStore';

export function OverviewPanel({ status, activeFeatures, events = [], eventsLoading = false, onSimulateAttack, isSimulating = false }) {
  const liveEvents = useLiveFeedStore(s => s.wafEvents);
  const blocked = useLiveFeedStore(s => s.wafBlocked);
  const challenged = useLiveFeedStore(s => s.wafChallenged);
  const setWafInitialStats = useLiveFeedStore(s => s.setWafInitialStats);
  const clearAllEvents = useLiveFeedStore(s => s.clearAll);

  const [search, setSearch] = useState('');
  const [actionFilter, setActionFilter] = useState('ALL');
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [simType, setSimType] = useState('sqli');

  // Combine live WebSocket events with historical REST API events
  const allEvents = useMemo(() => {
    const combined = [...liveEvents];
    const seenKeys = new Set(liveEvents.map(e => `${e.ip}_${e.time}_${e.path}`));
    (events || []).forEach(e => {
      const key = `${e.ip}_${e.time}_${e.path}`;
      if (!seenKeys.has(key)) {
        seenKeys.add(key);
        combined.push(e);
      }
    });
    return combined;
  }, [liveEvents, events]);

  // Sync initial statistics from backend status HTTP call
  useEffect(() => {
    if (status?.stats && blocked === 0 && challenged === 0) {
      setWafInitialStats(status.stats.blocked || 0, status.stats.challenged || 0);
    }
  }, [status?.stats, blocked, challenged, setWafInitialStats]);

  const totalBlocked = blocked || allEvents.filter(e => e.action === 'BLOCK').length || (status?.stats?.blocked || 0);
  const totalChallenged = challenged || allEvents.filter(e => e.action === 'CHALLENGE' || e.action === 'QUARANTINE').length || (status?.stats?.challenged || 0);

  // Filter events
  const filteredEvents = allEvents.filter(ev => {
    const matchAction = actionFilter === 'ALL' || ev.action === actionFilter;
    const q = search.toLowerCase();
    const matchQuery = !q || (
      (ev.ip && ev.ip.toLowerCase().includes(q)) ||
      (ev.path && ev.path.toLowerCase().includes(q)) ||
      (ev.cause && ev.cause.toLowerCase().includes(q))
    );
    return matchAction && matchQuery;
  });

  // Export CSV
  const handleExportCsv = () => {
    if (allEvents.length === 0) return;
    const headers = ["ID", "Time", "IP", "Path", "Cause", "Risk", "Action"];
    const rows = allEvents.map(e => [
      e.id, e.time, e.ip, e.path, `"${(e.cause || '').replace(/"/g, '""')}"`, e.risk, e.action
    ]);
    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `waf_threat_feed_${Date.now()}.csv`;
    a.click();
  };

  const handleRunSimulation = async () => {
    if (onSimulateAttack) {
      await onSimulateAttack(simType);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
      
      {/* KPI Section */}
      <div className="kpi-row">
        <KpiCard icon={<Activity size={18} />} value={status?.waf_enabled ? 'متصل' : 'منقطع'} label={`الوضع: ${(status?.mode || 'block').toUpperCase()}`} color={status?.waf_enabled ? 'var(--success)' : 'var(--danger)'} delay={0} />
        <KpiCard icon={<Cpu size={18} />} value={`${activeFeatures} / 12`} label="وحدات ونماذج نشطة" color="var(--accent)" delay={0.05} />
        <KpiCard icon={<AlertOctagon size={18} />} value={totalBlocked.toLocaleString()} label="محجوب (24 ساعة)" color="var(--danger)" delay={0.1} />
        <KpiCard icon={<Crosshair size={18} />} value={totalChallenged.toLocaleString()} label="تحدٍّ صدر (CAPTCHA)" color="var(--warning)" delay={0.15} />
      </div>

      {/* Main Threat Feed Section */}
      <SectionCard
        title={
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%', flexWrap: 'wrap', gap: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Wifi size={16} className={status?.waf_enabled ? 'pulse-icon' : ''} style={{ color: status?.waf_enabled ? 'var(--accent)' : 'var(--text-muted)' }} />
              <span>تيار التهديدات وسجل الفحص — Threat & Inspection Feed</span>
            </div>

            {/* Filter & Action Toolbar */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
              {/* Attack Simulator Trigger */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 4, background: 'rgba(0, 200, 255, 0.08)', padding: '2px 6px', borderRadius: 6, border: '1px solid rgba(0, 200, 255, 0.2)' }}>
                <select
                  value={simType}
                  onChange={e => setSimType(e.target.value)}
                  style={{ padding: '4px 8px', fontSize: '0.75rem', background: 'transparent', border: 'none', color: '#00c8ff', fontWeight: 'bold' }}
                >
                  <option value="sqli" style={{ background: '#101426', color: '#fff' }}>حقن SQL (SQLi)</option>
                  <option value="xss" style={{ background: '#101426', color: '#fff' }}>حقن برمجيات (XSS)</option>
                  <option value="path_traversal" style={{ background: '#101426', color: '#fff' }}>تسلل مسارات (Path Traversal)</option>
                  <option value="bot" style={{ background: '#101426', color: '#fff' }}>روبوت خبيث (Bot)</option>
                  <option value="bola" style={{ background: '#101426', color: '#fff' }}>تلاعب بمعرف كائن (BOLA/IDOR)</option>
                </select>
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={handleRunSimulation}
                  disabled={isSimulating}
                  style={{ padding: '4px 10px', fontSize: '0.75rem' }}
                  title="إرسال طلب محاكاة لهجوم لاختبار نظام الكشف والتنبيهات الحية"
                >
                  <Play size={11} /> {isSimulating ? 'يُحاكى...' : 'محاكاة هجوم'}
                </button>
              </div>

              <div style={{ position: 'relative', minWidth: 160 }}>
                <Search size={14} style={{ position: 'absolute', right: 8, top: 10, color: 'var(--text-muted)' }} />
                <input
                  type="text"
                  placeholder="بحث حسب IP أو المسار..."
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  style={{ width: '100%', padding: '6px 28px 6px 8px', fontSize: '0.8rem', background: 'var(--bg-overlay)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text-main)' }}
                />
              </div>

              <select
                value={actionFilter}
                onChange={e => setActionFilter(e.target.value)}
                style={{ padding: '6px 10px', fontSize: '0.8rem', background: 'var(--bg-overlay)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text-main)' }}
              >
                <option value="ALL">جميع الإجراءات</option>
                <option value="BLOCK">⛔ حجب فقط</option>
                <option value="CHALLENGE">⚡ تحدٍّ فقط</option>
              </select>

              <button className="btn btn-ghost" onClick={handleExportCsv} title="تصدير CSV" style={{ padding: '6px 10px' }}>
                <Download size={14} /> تصدير
              </button>

              <button className="btn btn-ghost" onClick={clearAllEvents} title="مسح السجل" style={{ padding: '6px 10px', color: 'var(--danger)' }}>
                <Trash2 size={14} />
              </button>
            </div>
          </div>
        }
      >
        {filteredEvents.length === 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12, padding: 30 }}>
            <EmptyState message={search ? "لا توجد نتائج تطابق البحث..." : "لا توجد سجلات مسجلة بعد."} icon={Shield} />
            {!search && (
              <button
                type="button"
                className="btn btn-primary"
                onClick={handleRunSimulation}
                disabled={isSimulating}
                style={{ fontSize: '0.82rem' }}
              >
                <Play size={13} /> {isSimulating ? 'جاري المحاكاة...' : 'محاكاة هجوم تجريبي لاختبار الـ WAF'}
              </button>
            )}
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>الوقت</th>
                  <th>IP المهاجم</th>
                  <th>المسار المستهدف</th>
                  <th>سبب الكشف (XAI)</th>
                  <th>المخاطرة</th>
                  <th>الإجراء</th>
                  <th>التفاصيل</th>
                </tr>
              </thead>
              <tbody>
                <AnimatePresence>
                  {filteredEvents.map((ev, i) => (
                    <motion.tr
                      key={ev.id}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      exit={{ opacity: 0 }}
                      transition={{ duration: 0.2 }}
                      style={{ background: i === 0 ? 'var(--bg-hover)' : 'transparent', cursor: 'pointer' }}
                      onClick={() => setSelectedEvent(ev)}
                    >
                      <td className="mono">{ev.time}</td>
                      <td className="mono" style={{ direction: 'ltr', textAlign: 'right' }}>{ev.ip}</td>
                      <td className="mono" style={{ color: 'var(--accent)', direction: 'ltr', textAlign: 'right' }}>{ev.path}</td>
                      <td>{ev.cause}</td>
                      <td className="mono" style={{ color: parseFloat(ev.risk) > 0.85 ? 'var(--danger)' : 'var(--warning)', fontWeight: 'bold' }}>{ev.risk}</td>
                      <td>
                        <span className={`badge ${ev.action === 'BLOCK' ? 'badge-danger' : 'badge-warning'}`}>
                          {ev.action === 'BLOCK' ? '⛔ حجب' : '⚡ تحدٍّ'}
                        </span>
                      </td>
                      <td>
                        <button className="btn btn-ghost" style={{ padding: 4 }} title="عرض التحليل العصبي">
                          <Eye size={14} />
                        </button>
                      </td>
                    </motion.tr>
                  ))}
                </AnimatePresence>
              </tbody>
            </table>
          </div>
        )}
      </SectionCard>

      {/* Threat Detail Modal */}
      {selectedEvent && (
        <div style={{
          position: 'fixed',
          top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0, 0, 0, 0.75)',
          backdropFilter: 'blur(4px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 9999
        }}>
          <div style={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border)',
            borderRadius: 12,
            width: '90%',
            maxWidth: 550,
            padding: 24,
            display: 'flex',
            flexDirection: 'column',
            gap: 16,
            boxShadow: '0 20px 50px rgba(0,0,0,0.6)'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border)', paddingBottom: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, fontWeight: 800, fontSize: '1.1rem' }}>
                <AlertTriangle size={20} style={{ color: selectedEvent.action === 'BLOCK' ? 'var(--danger)' : 'var(--warning)' }} />
                <span>تحليل الحدث الأمني — XAI Analysis</span>
              </div>
              <button onClick={() => setSelectedEvent(null)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
                <X size={20} />
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: '0.9rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px dashed var(--border)', paddingBottom: 6 }}>
                <span style={{ color: 'var(--text-muted)' }}>وقت الكشف</span>
                <span className="mono">{selectedEvent.time}</span>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px dashed var(--border)', paddingBottom: 6 }}>
                <span style={{ color: 'var(--text-muted)' }}>عنوان IP المهاجم</span>
                <span className="mono" style={{ color: 'var(--accent)' }}>{selectedEvent.ip}</span>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px dashed var(--border)', paddingBottom: 6 }}>
                <span style={{ color: 'var(--text-muted)' }}>المسار المستهدف</span>
                <span className="mono" style={{ color: 'var(--accent)' }}>{selectedEvent.path}</span>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px dashed var(--border)', paddingBottom: 6 }}>
                <span style={{ color: 'var(--text-muted)' }}>درجة المخاطرة المحسوبة</span>
                <span className="mono" style={{ color: parseFloat(selectedEvent.risk) > 0.85 ? 'var(--danger)' : 'var(--warning)', fontWeight: 'bold' }}>{selectedEvent.risk}</span>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px dashed var(--border)', paddingBottom: 6 }}>
                <span style={{ color: 'var(--text-muted)' }}>الإجراء المتخذ</span>
                <span className={`badge ${selectedEvent.action === 'BLOCK' ? 'badge-danger' : 'badge-warning'}`}>
                  {selectedEvent.action === 'BLOCK' ? '⛔ حجب كلي (BLOCK)' : '⚡ تحدٍّ (CAPTCHA)'}
                </span>
              </div>

              <div>
                <span style={{ color: 'var(--text-muted)', display: 'block', marginBottom: 6 }}>تفسير الذكاء الاصطناعي (XAI Explainer):</span>
                <div style={{ background: '#090d16', padding: 12, borderRadius: 6, border: '1px solid var(--border)', color: '#a78bfa', fontFamily: 'monospace', fontSize: '0.85rem' }}>
                  {selectedEvent.cause}
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 10 }}>
              <button className="btn btn-primary" onClick={() => setSelectedEvent(null)}>إغلاق</button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
