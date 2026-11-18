/**
 * EmailAlerts.jsx — Real-time alerts feed for blocked/quarantined emails.
 * Shows per-email score breakdown (phishing, url, spam, attachment, PLSF, VSDE).
 * FIX-10: Previously missing from UI — 70% of module data was invisible.
 */
import { useState, useEffect, useCallback } from 'react';
import { emailApi } from '../api/emailApi';
import {
  ShieldX, Brain, Eye, Link2, Paperclip, AlertTriangle,
  RefreshCw, ChevronDown, ChevronUp,
} from 'lucide-react';

const DECISION_COLOR = {
  block:      { bg: 'rgba(255,95,95,0.12)',  border: 'rgba(255,95,95,0.35)',  text: '#ff5f5f',  label: 'حظر'    },
  quarantine: { bg: 'rgba(251,191,36,0.12)', border: 'rgba(251,191,36,0.35)', text: '#fbbf24',  label: 'عزل'    },
  allow:      { bg: 'rgba(40,199,111,0.08)', border: 'rgba(40,199,111,0.2)',  text: '#28c76f',  label: 'سماح'   },
};

function ScoreBar({ label, value, color, icon: Icon }) {
  const pct = Math.round((value || 0) * 100);
  return (
    <div style={{ marginBottom: 6 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '.72rem', color: 'rgba(255,255,255,0.5)', marginBottom: 3 }}>
        <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          {Icon && <Icon size={11} />}{label}
        </span>
        <span style={{ color, fontWeight: 600 }}>{pct}%</span>
      </div>
      <div style={{ height: 4, background: 'rgba(255,255,255,0.07)', borderRadius: 4, overflow: 'hidden' }}>
        <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: 4, transition: 'width .4s ease' }} />
      </div>
    </div>
  );
}

function AlertCard({ row }) {
  const [expanded, setExpanded] = useState(false);
  const dc = DECISION_COLOR[row.decision] || DECISION_COLOR.allow;
  const time = row.inspected_at
    ? new Date(row.inspected_at).toLocaleString('ar-SA', { hour: '2-digit', minute: '2-digit', day: '2-digit', month: 'short' })
    : '—';

  const flags = [
    row.is_phishing      && { label: 'تصيد', color: '#ff5f5f',  icon: AlertTriangle },
    row.is_ai_mimicry    && { label: 'BEC/AI', color: '#a78bfa', icon: Brain          },
    row.has_visual_desync&& { label: 'CSS Evasion', color: '#fb923c', icon: Eye        },
    row.has_malicious_url&& { label: 'رابط خبيث', color: '#f43f5e', icon: Link2       },
    row.has_bad_attachment&& { label: 'مرفق خطر',  color: '#ef4444', icon: Paperclip  },
    row.is_spam          && { label: 'Spam',  color: '#fbbf24',  icon: ShieldX        },
  ].filter(Boolean);

  return (
    <div style={{
      background: dc.bg,
      border: `1px solid ${dc.border}`,
      borderRadius: 10,
      marginBottom: 10,
      overflow: 'hidden',
      transition: 'box-shadow .2s',
    }}>
      {/* Header row */}
      <div
        style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '12px 16px', cursor: 'pointer' }}
        onClick={() => setExpanded(e => !e)}
      >
        <span style={{
          minWidth: 52, textAlign: 'center', fontSize: '.7rem', fontWeight: 700,
          color: dc.text, background: `${dc.border}50`, padding: '2px 8px', borderRadius: 6,
        }}>
          {dc.label}
        </span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: '.82rem', fontWeight: 600, color: '#f0f0f5', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {row.sender || '—'}
          </div>
          <div style={{ fontSize: '.72rem', color: 'rgba(255,255,255,0.35)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {row.subject || 'بدون موضوع'}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
          {flags.slice(0, 3).map(f => (
            <span key={f.label} style={{
              display: 'flex', alignItems: 'center', gap: 3,
              fontSize: '.67rem', padding: '2px 7px', borderRadius: 20,
              background: `${f.color}18`, color: f.color, border: `1px solid ${f.color}33`,
            }}>
              <f.icon size={10} />{f.label}
            </span>
          ))}
          {flags.length > 3 && (
            <span style={{ fontSize: '.67rem', color: 'rgba(255,255,255,0.3)' }}>+{flags.length - 3}</span>
          )}
        </div>
        <div style={{ textAlign: 'right', minWidth: 70 }}>
          <div style={{ fontSize: '.78rem', fontWeight: 700, color: dc.text }}>{Math.round((row.risk_score || 0) * 100)}%</div>
          <div style={{ fontSize: '.65rem', color: 'rgba(255,255,255,0.3)' }}>{time}</div>
        </div>
        <div style={{ color: 'rgba(255,255,255,0.2)' }}>
          {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </div>
      </div>

      {/* Expanded detail */}
      {expanded && (
        <div style={{ padding: '0 16px 14px', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px 24px', marginTop: 12 }}>
            <div>
              <ScoreBar label="تصيد (Phishing)"   value={row.phishing_score}   color="#ff5f5f"  icon={AlertTriangle} />
              <ScoreBar label="روابط (URL)"        value={row.url_score}        color="#fb923c"  icon={Link2} />
              <ScoreBar label="مرفقات"             value={row.attachment_score}  color="#ef4444"  icon={Paperclip} />
            </div>
            <div>
              <ScoreBar label="المرسل"             value={row.sender_score}      color="#fbbf24"  icon={ShieldX} />
              <ScoreBar label="BEC/AI (PLSF)"      value={row.linguistic_anomaly} color="#a78bfa" icon={Brain} />
              <ScoreBar label="CSS Desync (VSDE)"  value={row.visual_desync}     color="#fb923c"  icon={Eye} />
            </div>
          </div>

          {row.matched_keywords?.length > 0 && (
            <div style={{ marginTop: 10 }}>
              <div style={{ fontSize: '.7rem', color: 'rgba(255,255,255,0.3)', marginBottom: 4 }}>كلمات مفتاحية مكتشفة:</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                {row.matched_keywords.slice(0, 8).map(kw => (
                  <span key={kw} style={{
                    fontSize: '.67rem', padding: '2px 7px', borderRadius: 20,
                    background: 'rgba(255,95,95,0.1)', color: '#ff8a80', border: '1px solid rgba(255,95,95,0.2)',
                  }}>{kw}</span>
                ))}
              </div>
            </div>
          )}

          {row.finding_categories?.length > 0 && (
            <div style={{ marginTop: 8 }}>
              <div style={{ fontSize: '.7rem', color: 'rgba(255,255,255,0.3)', marginBottom: 4 }}>التصنيفات:</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                {row.finding_categories.map(c => (
                  <span key={c} style={{ fontSize: '.67rem', padding: '2px 7px', borderRadius: 20, background: 'rgba(129,140,248,0.1)', color: '#818cf8', border: '1px solid rgba(129,140,248,0.2)' }}>
                    {c}
                  </span>
                ))}
              </div>
            </div>
          )}

          <div style={{ display: 'flex', gap: 16, marginTop: 10, fontSize: '.7rem', color: 'rgba(255,255,255,0.25)' }}>
            {row.src_ip    && <span>IP: {row.src_ip}</span>}
            {row.dst_port  && <span>Port: {row.dst_port}</span>}
            {row.latency_ms != null && <span>زمن: {Math.round(row.latency_ms)}ms</span>}
          </div>
        </div>
      )}
    </div>
  );
}

export default function EmailAlerts() {
  const [rows, setRows]       = useState([]);
  const [filter, setFilter]   = useState('block');
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await emailApi.logs({ decision: filter === 'all' ? undefined : filter, limit: 50 });
      setRows(res.data || []);
    } catch (e) {
      setError('تعذّر تحميل التنبيهات');
    } finally {
      setLoading(false);
    }
  }, [filter]);

  useEffect(() => { load(); }, [load]);

  const FILTERS = [
    { id: 'block',      label: 'محظورة' },
    { id: 'quarantine', label: 'معزولة' },
    { id: 'all',        label: 'الكل'   },
  ];

  return (
    <div className="em-panel" style={{ marginTop: 16 }}>
      <div className="em-panel-header">
        <div className="em-panel-title" style={{ color: '#ff5f5f' }}>
          <ShieldX size={14} /> تنبيهات الأمان
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <div style={{ display: 'flex', gap: 4 }}>
            {FILTERS.map(f => (
              <button
                key={f.id}
                onClick={() => setFilter(f.id)}
                style={{
                  fontSize: '.72rem', padding: '3px 10px', borderRadius: 6, border: 'none', cursor: 'pointer',
                  background: filter === f.id ? 'rgba(255,95,95,0.2)' : 'rgba(255,255,255,0.05)',
                  color: filter === f.id ? '#ff5f5f' : 'rgba(255,255,255,0.4)',
                  transition: 'all .15s',
                }}
              >{f.label}</button>
            ))}
          </div>
          <button
            onClick={load}
            disabled={loading}
            style={{
              background: 'rgba(129,140,248,0.1)', border: '1px solid rgba(129,140,248,0.2)',
              borderRadius: 6, padding: '4px 10px', cursor: 'pointer', color: '#818cf8',
              display: 'flex', alignItems: 'center', gap: 4, fontSize: '.72rem',
            }}
          >
            <RefreshCw size={12} style={{ animation: loading ? 'spin 1s linear infinite' : 'none' }} />
            تحديث
          </button>
        </div>
      </div>

      <div style={{ padding: '12px 16px' }}>
        {error && <div className="em-empty" style={{ color: '#ff5f5f' }}>{error}</div>}
        {!loading && !error && rows.length === 0 && (
          <div className="em-empty">لا توجد تنبيهات بهذا الفلتر.</div>
        )}
        {rows.map(row => <AlertCard key={row.id} row={row} />)}
      </div>
    </div>
  );
}
