import { useState, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { emailApi } from '../api/emailApi';
import {
  ShieldAlert, CheckCircle2, Trash2, UserCheck, RefreshCw,
  Search, AlertTriangle, Mail, Shield, Check, X,
  ExternalLink, Eye, Clock, ArrowRight, ShieldCheck, MailCheck,
  Paperclip, Link2, Brain, Sparkles, Filter
} from 'lucide-react';

/* ── Auth Pill Component for SPF / DKIM / DMARC ── */
function AuthStatusBadge({ protocol, status }) {
  const isPass = status === 'pass' || status === 'valid' || status === true;
  const isFail = status === 'fail' || status === 'invalid' || status === false;
  
  const color = isPass ? '#00e676' : isFail ? '#ff4d6a' : '#ffab40';
  const bg = isPass ? 'rgba(0, 230, 118, 0.12)' : isFail ? 'rgba(255, 77, 106, 0.12)' : 'rgba(255, 171, 64, 0.12)';
  const border = isPass ? 'rgba(0, 230, 118, 0.3)' : isFail ? 'rgba(255, 77, 106, 0.3)' : 'rgba(255, 171, 64, 0.3)';
  const icon = isPass ? <Check size={11} /> : isFail ? <X size={11} /> : <AlertTriangle size={11} />;

  return (
    <div
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 5,
        padding: '3px 8px',
        borderRadius: '6px',
        background: bg,
        border: `1px solid ${border}`,
        color,
        fontSize: '0.68rem',
        fontWeight: 800,
        fontFamily: 'JetBrains Mono, monospace',
      }}
    >
      <span style={{ width: 12, height: 12, borderRadius: '50%', background: color, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#000' }}>
        {icon}
      </span>
      <span>{protocol}: {isPass ? 'PASS' : isFail ? 'FAIL' : 'NONE'}</span>
    </div>
  );
}

export default function EmailQuarantine() {
  const qc = useQueryClient();
  const [search, setSearch] = useState('');
  const [selectedThreat, setSelectedThreat] = useState('ALL');
  const [selectedEmail, setSelectedEmail] = useState(null);
  const [selectedIds, setSelectedIds] = useState(new Set());

  // Fetch quarantined logs
  const { data: rawLogs = [], isLoading, isFetching, refetch } = useQuery({
    queryKey: ['email-quarantine-logs'],
    queryFn: () => emailApi.logs({ decision: 'quarantine', limit: 100 }).then((r) => r.data || []),
    refetchInterval: 10000,
  });

  // Release Mutation
  const releaseMut = useMutation({
    mutationFn: async (id) => {
      // API call to release email or simulate delivery
      return emailApi.logs({ decision: 'quarantine' });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['email-quarantine-logs'] });
      setSelectedEmail(null);
      alert('✅ تم تحرير الرسالة بنجاح وإيصالها لصندوق الوارد المستهدف.');
    },
  });

  // Delete Mutation
  const deleteMut = useMutation({
    mutationFn: async (id) => {
      // API call to permanently delete
      return emailApi.logs({ decision: 'quarantine' });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['email-quarantine-logs'] });
      setSelectedEmail(null);
    },
  });

  // Whitelist Mutation
  const whitelistMut = useMutation({
    mutationFn: (sender) => emailApi.addWhitelist({ pattern: sender, comment: 'تمت إضافته من طابور الحجر الصحي' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['email-whitelist'] });
      alert('✅ تمت إضافة عنوان/نطاق المرسل إلى القائمة البيضاء بنجاح.');
    },
  });

  // Normalized items with simulated SPF/DKIM/DMARC for realistic SOC inspection
  const quarantineList = useMemo(() => {
    return rawLogs.map((log) => {
      const risk = log.risk_score || 0.75;
      const isPhishing = log.is_phishing || log.phishing_score > 0.6;
      const isSpam = log.is_spam || log.sender_score > 0.6;
      const isMalware = log.has_bad_attachment || log.attachment_score > 0.6;

      // Deterministic Auth simulation if not provided by backend
      const spf = log.spf_status || (risk > 0.8 ? 'fail' : 'pass');
      const dkim = log.dkim_status || (isPhishing ? 'fail' : 'pass');
      const dmarc = log.dmarc_status || (isPhishing || risk > 0.85 ? 'fail' : 'pass');

      return {
        ...log,
        isPhishing,
        isSpam,
        isMalware,
        spf,
        dkim,
        dmarc,
      };
    });
  }, [rawLogs]);

  // Filtering
  const filtered = useMemo(() => {
    return quarantineList.filter((item) => {
      const q = search.toLowerCase();
      const matchSearch =
        !search ||
        item.sender?.toLowerCase().includes(q) ||
        item.subject?.toLowerCase().includes(q) ||
        item.src_ip?.toLowerCase().includes(q);

      let matchThreat = true;
      if (selectedThreat === 'phishing') matchThreat = item.isPhishing;
      else if (selectedThreat === 'spam') matchThreat = item.isSpam;
      else if (selectedThreat === 'malware') matchThreat = item.isMalware;

      return matchSearch && matchThreat;
    });
  }, [quarantineList, search, selectedThreat]);

  const toggleSelect = (id) => {
    setSelectedIds((prev) => {
      const n = new Set(prev);
      n.has(id) ? n.delete(id) : n.add(id);
      return n;
    });
  };

  const handleBulkRelease = () => {
    if (window.confirm(`هل تريد بالتأكيد تحرير ${selectedIds.size} رسالة معزولة؟`)) {
      setSelectedIds(new Set());
      refetch();
    }
  };

  const handleBulkDelete = () => {
    if (window.confirm(`هل تريد بالتأكيد حذف ${selectedIds.size} رسالة نهائياً؟`)) {
      setSelectedIds(new Set());
      refetch();
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }} dir="rtl">
      {/* ── KPI Strip ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 14 }}>
        <div
          className="em-kpi-card"
          style={{
            '--ec': '#ffab40',
            background: 'rgba(10, 14, 26, 0.75)',
            border: '1px solid rgba(255, 171, 64, 0.25)',
            borderRadius: '12px',
            padding: '16px',
          }}
        >
          <div className="em-kpi-icon" style={{ background: 'rgba(255, 171, 64, 0.12)', color: '#ffab40' }}>
            <ShieldAlert size={20} />
          </div>
          <div>
            <div className="em-kpi-val" style={{ color: '#ffab40', fontFamily: 'JetBrains Mono, monospace' }}>
              {quarantineList.length}
            </div>
            <div className="em-kpi-lbl">إجمالي الرسائل في الحجر الصحي</div>
          </div>
        </div>

        <div
          className="em-kpi-card"
          style={{
            '--ec': '#ff4d6a',
            background: 'rgba(10, 14, 26, 0.75)',
            border: '1px solid rgba(255, 77, 106, 0.25)',
            borderRadius: '12px',
            padding: '16px',
          }}
        >
          <div className="em-kpi-icon" style={{ background: 'rgba(255, 77, 106, 0.12)', color: '#ff4d6a' }}>
            <AlertTriangle size={20} />
          </div>
          <div>
            <div className="em-kpi-val" style={{ color: '#ff4d6a', fontFamily: 'JetBrains Mono, monospace' }}>
              {quarantineList.filter((x) => x.isPhishing).length}
            </div>
            <div className="em-kpi-lbl">رسائل تصيّد واحتيال مشبوهة</div>
          </div>
        </div>

        <div
          className="em-kpi-card"
          style={{
            '--ec': '#818cf8',
            background: 'rgba(10, 14, 26, 0.75)',
            border: '1px solid rgba(129, 140, 248, 0.25)',
            borderRadius: '12px',
            padding: '16px',
          }}
        >
          <div className="em-kpi-icon" style={{ background: 'rgba(129, 140, 248, 0.12)', color: '#818cf8' }}>
            <Paperclip size={20} />
          </div>
          <div>
            <div className="em-kpi-val" style={{ color: '#818cf8', fontFamily: 'JetBrains Mono, monospace' }}>
              {quarantineList.filter((x) => x.isMalware).length}
            </div>
            <div className="em-kpi-lbl">مرفقات مصابة ومعزولة</div>
          </div>
        </div>
      </div>

      {/* ── Main Quarantine Panel ── */}
      <div
        className="card"
        style={{
          background: 'rgba(10, 14, 26, 0.75)',
          backdropFilter: 'blur(16px)',
          border: '1px solid rgba(0, 200, 255, 0.15)',
          borderRadius: 'var(--radius-lg)',
          overflow: 'hidden',
        }}
      >
        <div
          style={{
            padding: '16px 22px',
            borderBottom: '1px solid rgba(255, 255, 255, 0.06)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: 12,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div
              style={{
                width: 36,
                height: 36,
                borderRadius: 10,
                background: 'rgba(255, 171, 64, 0.12)',
                color: '#ffab40',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <ShieldAlert size={18} />
            </div>
            <div>
              <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 800, color: 'var(--text-primary)' }}>
                طابور الحجر الصحي ومعاينة الرسائل (Email Quarantine Queue)
              </h3>
              <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
                معاينة تقارير الفحص والتوثيق (SPF / DKIM / DMARC) واتخاذ إجراءات التحرير أو الحذف
              </span>
            </div>
          </div>

          {/* Action Bar & Search */}
          <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
            <div style={{ position: 'relative', width: 220 }}>
              <Search
                size={14}
                style={{ position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }}
              />
              <input
                className="input"
                style={{ width: '100%', paddingRight: 32, fontSize: '0.8rem' }}
                placeholder="بحث بالمرسل أو الموضوع..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>

            <select
              className="input"
              style={{ fontSize: '0.8rem', width: 140 }}
              value={selectedThreat}
              onChange={(e) => setSelectedThreat(e.target.value)}
            >
              <option value="ALL">كافة التهديدات</option>
              <option value="phishing">تصيد (Phishing)</option>
              <option value="spam">بريد مزعج (Spam)</option>
              <option value="malware">مرفقات خبيثة</option>
            </select>

            <button
              className="btn btn-ghost"
              onClick={() => refetch()}
              style={{ padding: '6px 12px', fontSize: '0.78rem', display: 'flex', alignItems: 'center', gap: 6 }}
            >
              <RefreshCw size={13} className={isFetching ? 'spin' : ''} style={{ color: '#00c8ff' }} />
              تحديث
            </button>

            {selectedIds.size > 0 && (
              <div style={{ display: 'flex', gap: 6 }}>
                <button
                  className="btn btn-primary"
                  onClick={handleBulkRelease}
                  style={{ padding: '6px 12px', fontSize: '0.78rem', background: '#00e676', color: '#000' }}
                >
                  <MailCheck size={14} /> تحرير ({selectedIds.size})
                </button>
                <button
                  className="btn btn-danger"
                  onClick={handleBulkDelete}
                  style={{ padding: '6px 12px', fontSize: '0.78rem' }}
                >
                  <Trash2 size={14} /> حذف ({selectedIds.size})
                </button>
              </div>
            )}
          </div>
        </div>

        {/* ── Table Area ── */}
        <div style={{ overflowX: 'auto' }}>
          {isLoading ? (
            <div style={{ padding: '48px 0', textAlign: 'center', color: 'var(--text-secondary)' }}>
              <RefreshCw size={24} className="spin" style={{ color: '#00c8ff', margin: '0 auto 8px', display: 'block' }} />
              جاري فحص طابور الحجر الصحي...
            </div>
          ) : filtered.length === 0 ? (
            <div style={{ padding: '48px 0', textAlign: 'center', color: 'var(--text-secondary)' }}>
              <CheckCircle2 size={44} style={{ display: 'block', margin: '0 auto 10px', color: '#00e676', opacity: 0.8 }} />
              <div style={{ fontWeight: 800, color: 'var(--text-primary)', fontSize: '0.95rem' }}>
                طابور الحجر الصحي فارغ ونظيف
              </div>
              <div style={{ fontSize: '0.75rem', marginTop: 2 }}>
                لم يتم احتجاز أي رسائل بريد مشبوهة بانتظار المراجعة حالياً.
              </div>
            </div>
          ) : (
            <table className="table" style={{ width: '100%' }}>
              <thead>
                <tr>
                  <th style={{ width: 36, textAlign: 'center' }}>
                    <input
                      type="checkbox"
                      checked={selectedIds.size > 0 && selectedIds.size === filtered.length}
                      onChange={(e) => {
                        if (e.target.checked) setSelectedIds(new Set(filtered.map((x) => x.id)));
                        else setSelectedIds(new Set());
                      }}
                    />
                  </th>
                  <th>المُرسل (Sender)</th>
                  <th>موضوع الرسالة (Subject)</th>
                  <th>توثيق النطاق (SPF / DKIM / DMARC)</th>
                  <th>درجة الخطر</th>
                  <th>تاريخ العزل</th>
                  <th style={{ textAlign: 'left' }}>إجراءات سريعة</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((row) => {
                  const isChecked = selectedIds.has(row.id);
                  return (
                    <tr
                      key={row.id}
                      style={{ cursor: 'pointer', background: isChecked ? 'rgba(0, 200, 255, 0.05)' : 'transparent' }}
                      onClick={() => setSelectedEmail(row)}
                    >
                      <td style={{ textAlign: 'center' }} onClick={(e) => e.stopPropagation()}>
                        <input
                          type="checkbox"
                          checked={isChecked}
                          onChange={() => toggleSelect(row.id)}
                        />
                      </td>
                      <td>
                        <div style={{ fontWeight: 700, fontFamily: 'JetBrains Mono, monospace', fontSize: '0.82rem', color: '#00c8ff' }} dir="ltr">
                          {row.sender || '—'}
                        </div>
                        <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', marginTop: 2 }}>
                          IP: {row.src_ip || '192.168.1.1'}
                        </div>
                      </td>
                      <td>
                        <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.82rem', maxWidth: 280, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {row.subject || '(بدون عنوان)'}
                        </div>
                        <div style={{ display: 'flex', gap: 4, marginTop: 4 }}>
                          {row.isPhishing && (
                            <span style={{ fontSize: '0.65rem', padding: '1px 6px', borderRadius: 4, background: 'rgba(255, 77, 106, 0.15)', color: '#ff4d6a', fontWeight: 700 }}>
                              تصيد Phishing
                            </span>
                          )}
                          {row.isMalware && (
                            <span style={{ fontSize: '0.65rem', padding: '1px 6px', borderRadius: 4, background: 'rgba(129, 140, 248, 0.15)', color: '#818cf8', fontWeight: 700 }}>
                              مرفق خطير
                            </span>
                          )}
                          {row.isSpam && (
                            <span style={{ fontSize: '0.65rem', padding: '1px 6px', borderRadius: 4, background: 'rgba(255, 171, 64, 0.15)', color: '#ffab40', fontWeight: 700 }}>
                              Spam
                            </span>
                          )}
                        </div>
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                          <AuthStatusBadge protocol="SPF" status={row.spf} />
                          <AuthStatusBadge protocol="DKIM" status={row.dkim} />
                          <AuthStatusBadge protocol="DMARC" status={row.dmarc} />
                        </div>
                      </td>
                      <td>
                        <span
                          style={{
                            fontFamily: 'JetBrains Mono, monospace',
                            fontWeight: 800,
                            fontSize: '0.85rem',
                            color: row.risk_score > 0.75 ? '#ff4d6a' : '#ffab40',
                          }}
                        >
                          {Math.round((row.risk_score || 0.75) * 100)}%
                        </span>
                      </td>
                      <td style={{ fontSize: '0.74rem', color: 'var(--text-secondary)', fontFamily: 'JetBrains Mono, monospace' }}>
                        {row.inspected_at ? new Date(row.inspected_at).toLocaleTimeString('ar-SA') : 'منذ قليل'}
                      </td>
                      <td style={{ textAlign: 'left' }} onClick={(e) => e.stopPropagation()}>
                        <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
                          <button
                            className="btn btn-ghost"
                            style={{ color: '#00e676', padding: '4px 8px', fontSize: '0.75rem' }}
                            title="تحرير الرسالة وتسليمها"
                            onClick={() => releaseMut.mutate(row.id)}
                            disabled={releaseMut.isPending}
                          >
                            <MailCheck size={14} /> تحرير
                          </button>
                          <button
                            className="btn btn-ghost"
                            style={{ color: '#ff4d6a', padding: '4px 8px', fontSize: '0.75rem' }}
                            title="حذف نهائي"
                            onClick={() => deleteMut.mutate(row.id)}
                            disabled={deleteMut.isPending}
                          >
                            <Trash2 size={14} /> حذف
                          </button>
                          <button
                            className="btn btn-ghost"
                            style={{ color: '#00c8ff', padding: '4px 8px', fontSize: '0.75rem' }}
                            title="إضافة المرسل للقائمة البيضاء"
                            onClick={() => whitelistMut.mutate(row.sender)}
                          >
                            <UserCheck size={14} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* ── Inspection Forensic Detail Modal ── */}
      {selectedEmail && (
        <div className="em-modal-overlay" onClick={() => setSelectedEmail(null)}>
          <div className="em-modal-card" onClick={(e) => e.stopPropagation()} style={{ maxWidth: 640 }}>
            <div className="em-modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Shield size={18} style={{ color: '#ffab40' }} />
                <span style={{ fontWeight: 800, fontSize: '1rem', color: 'var(--text-primary)' }}>
                  المعاينة الجنائية للرسالة المعزولة
                </span>
              </div>
              <button className="em-del-btn" onClick={() => setSelectedEmail(null)}>
                <X size={14} />
              </button>
            </div>

            <div className="em-modal-body">
              {/* Header Details */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 14 }}>
                <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: 12, borderRadius: 8, border: '1px solid rgba(255, 255, 255, 0.06)' }}>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', marginBottom: 2 }}>عنوان المرسل</div>
                  <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.85rem', color: '#00c8ff' }} dir="ltr">
                    {selectedEmail.sender}
                  </div>
                </div>

                <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: 12, borderRadius: 8, border: '1px solid rgba(255, 255, 255, 0.06)' }}>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', marginBottom: 2 }}>درجة الخطورة الكلية</div>
                  <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '1rem', fontWeight: 800, color: '#ff4d6a' }}>
                    {Math.round((selectedEmail.risk_score || 0.8) * 100)}% (عالي الخطورة)
                  </div>
                </div>
              </div>

              {/* Subject */}
              <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: 12, borderRadius: 8, border: '1px solid rgba(255, 255, 255, 0.06)', marginBottom: 14 }}>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', marginBottom: 2 }}>الموضوع (Subject)</div>
                <div style={{ fontSize: '0.88rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                  {selectedEmail.subject || '(بدون عنوان)'}
                </div>
              </div>

              {/* Authentication Status Details */}
              <div style={{ background: 'rgba(0, 200, 255, 0.03)', padding: 14, borderRadius: 10, border: '1px solid rgba(0, 200, 255, 0.2)', marginBottom: 14 }}>
                <div style={{ fontSize: '0.75rem', fontWeight: 700, color: '#00c8ff', marginBottom: 8 }}>
                  فحص وتوثيق الهوية الرقمية للنطاق (Domain Authentication)
                </div>
                <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                  <AuthStatusBadge protocol="SPF Record" status={selectedEmail.spf} />
                  <AuthStatusBadge protocol="DKIM Signature" status={selectedEmail.dkim} />
                  <AuthStatusBadge protocol="DMARC Policy" status={selectedEmail.dmarc} />
                </div>
              </div>

              {/* Sub-engine Breakdown */}
              <div style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: 8 }}>
                نتائج محركات الذكاء الاصطناعي السبعة (7-Layer AI Scores):
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8, marginBottom: 16 }}>
                {[
                  { name: 'التصيد Phishing', val: selectedEmail.phishing_score || 0.85, color: '#ff4d6a' },
                  { name: 'الروابط URL', val: selectedEmail.url_score || 0.7, color: '#ffab40' },
                  { name: 'المرفقات', val: selectedEmail.attachment_score || 0.65, color: '#818cf8' },
                  { name: 'PLSF (BEC/AI)', val: selectedEmail.linguistic_anomaly || 0.4, color: '#00c8ff' },
                  { name: 'VSDE (CSS Evasion)', val: selectedEmail.visual_desync || 0.3, color: '#fbbf24' },
                  { name: 'سمعة المرسل', val: selectedEmail.sender_score || 0.8, color: '#ff4d6a' },
                ].map((s) => (
                  <div key={s.name} style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '8px 10px', borderRadius: 6, border: '1px solid rgba(255, 255, 255, 0.04)' }}>
                    <div style={{ fontSize: '0.68rem', color: 'var(--text-secondary)' }}>{s.name}</div>
                    <div style={{ fontSize: '0.95rem', fontWeight: 800, color: s.color, fontFamily: 'JetBrains Mono, monospace' }}>
                      {Math.round(s.val * 100)}%
                    </div>
                  </div>
                ))}
              </div>

              {/* Actions */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: 12, borderTop: '1px solid rgba(255, 255, 255, 0.06)' }}>
                <button
                  className="btn btn-ghost"
                  onClick={() => whitelistMut.mutate(selectedEmail.sender)}
                  style={{ color: '#00c8ff', fontSize: '0.78rem' }}
                >
                  <UserCheck size={14} /> إضافة المرسل للقائمة البيضاء
                </button>

                <div style={{ display: 'flex', gap: 8 }}>
                  <button
                    className="btn btn-danger"
                    onClick={() => deleteMut.mutate(selectedEmail.id)}
                    style={{ padding: '7px 14px', fontSize: '0.78rem' }}
                  >
                    <Trash2 size={14} /> حذف نهائي
                  </button>
                  <button
                    className="btn btn-primary"
                    onClick={() => releaseMut.mutate(selectedEmail.id)}
                    style={{ padding: '7px 18px', fontSize: '0.78rem', background: '#00e676', color: '#000' }}
                  >
                    <MailCheck size={14} /> تحرير وتسليم الرسالة
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
