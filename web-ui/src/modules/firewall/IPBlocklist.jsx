import { useState, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ShieldOff, ShieldCheck, Plus, Trash2, RefreshCw,
  AlertTriangle, Wifi, Clock, User, X, CheckCircle2,
  FileSpreadsheet, UploadCloud, Search, Tag, Globe, Cpu
} from 'lucide-react';
import { firewallApi, responseApi } from '../../services/api';
import './IPBlocklist.css';

/* ── Helpers ── */
function fmtTime(ts) {
  if (!ts) return '—';
  try {
    const d = typeof ts === 'number' ? new Date(ts > 1e11 ? ts : ts * 1000) : new Date(ts);
    return isNaN(d.getTime()) ? '—' : d.toLocaleString('ar-SA');
  } catch (e) {
    return '—';
  }
}

function fmtExpiry(ts) {
  if (!ts) return 'دائم';
  try {
    const d = typeof ts === 'number' ? new Date(ts > 1e11 ? ts : ts * 1000) : new Date(ts);
    const diff = d - Date.now();
    if (diff <= 0) return 'منتهي';
    const mins = Math.floor(diff / 60000);
    const hrs = Math.floor(mins / 60);
    if (hrs > 0) return `${hrs}س ${mins % 60}د`;
    if (mins > 0) return `${mins}د`;
    return `${Math.ceil(diff / 1000)}ث`;
  } catch (e) {
    return '—';
  }
}

function inferThreatTag(reason = '') {
  const r = reason.toLowerCase();
  if (r.includes('bot') || r.includes('ddos') || r.includes('flood')) return { type: 'botnet', label: 'Botnet / DDoS' };
  if (r.includes('tor') || r.includes('onion') || r.includes('proxy')) return { type: 'tor', label: 'Tor / Proxy' };
  if (r.includes('scan') || r.includes('port') || r.includes('recon')) return { type: 'scanner', label: 'Port Scanner' };
  if (r.includes('brute') || r.includes('auth') || r.includes('login') || r.includes('ssh')) return { type: 'bruteforce', label: 'Brute Force' };
  return { type: 'custom', label: 'Manual Block' };
}

/* ── Modal: Single IP Block ── */
function BlockModal({ onClose, onConfirm, loading, error, onReset }) {
  const [ip, setIp] = useState('');
  const [reason, setReason] = useState('حظر فوري');
  const [duration, setDuration] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!ip.trim()) return;
    if (onReset) onReset();
    onConfirm({ ip: ip.trim(), reason, duration: duration ? parseInt(duration, 10) : null });
  };

  return (
    <div className="bl-modal" onClick={() => { if (onReset) onReset(); onClose(); }}>
      <div className="bl-modal-card bl-modal-card--danger" onClick={(e) => e.stopPropagation()} dir="rtl">
        <div className="bl-modal-header">
          <h3 className="bl-modal-title">
            <ShieldOff size={18} style={{ color: '#ff4d6a' }} />
            حظر عنوان IP جديد في النواة
          </h3>
          <button className="bl-modal-close" onClick={() => { if (onReset) onReset(); onClose(); }}>
            <X size={16} />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="bl-modal-body">
          <p style={{ margin: '0 0 16px', fontSize: '0.78rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
            سيتم إدراج هذا العنوان في قاعدة الإسقاط الفوري على مستوى النواة (eBPF / XDP_DROP) فورياً.
          </p>

          {error && (
            <div
              style={{
                marginBottom: '14px',
                padding: '10px 14px',
                background: 'rgba(255, 77, 106, 0.1)',
                border: '1px solid rgba(255, 77, 106, 0.3)',
                borderRadius: '8px',
                color: '#ff4d6a',
                fontSize: '0.78rem',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
              }}
            >
              <AlertTriangle size={16} />
              <span>{error}</span>
            </div>
          )}

          <div className="bl-form-row">
            <label className="bl-form-lbl">عنوان IP *</label>
            <input
              className="bl-input"
              placeholder="مثال: 198.51.100.45"
              value={ip}
              onChange={(e) => { if (onReset && error) onReset(); setIp(e.target.value); }}
              required
              autoFocus
              dir="ltr"
            />
          </div>

          <div className="bl-form-row">
            <label className="bl-form-lbl">سبب الحظر والتصنيف</label>
            <input
              className="bl-input"
              style={{ fontFamily: 'Cairo, sans-serif' }}
              placeholder="مثال: هجوم مسح المنافذ Port Scanning"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
          </div>

          <div className="bl-form-row">
            <label className="bl-form-lbl">مدة الحظر بالثواني (اتركه فارغاً للحظر الدائم)</label>
            <input
              className="bl-input"
              type="number"
              placeholder="مثال: 3600 لحظر لمدة ساعة"
              value={duration}
              onChange={(e) => setDuration(e.target.value)}
              min={1}
              dir="ltr"
            />
          </div>

          <div className="bl-modal-actions">
            <button type="button" className="bl-action-btn" onClick={() => { if (onReset) onReset(); onClose(); }}>
              إلغاء
            </button>
            <button type="submit" className="bl-action-btn bl-action-btn--primary" disabled={loading || !ip.trim()}>
              {loading ? <RefreshCw size={14} className="bl-spin" /> : <ShieldOff size={14} />}
              تنفيذ الحظر الفوري
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

/* ── Modal: Bulk CIDR / Multi-IP Import ── */
function BulkImportModal({ onClose, onConfirm, loading, error }) {
  const [rawText, setRawText] = useState('');
  const [bulkReason, setBulkReason] = useState('استيراد جماعي لعناوين مشبوهة');

  const handleSubmit = (e) => {
    e.preventDefault();
    const lines = rawText
      .split(/[\n,;]/)
      .map((l) => l.trim())
      .filter((l) => l.length > 0);
    if (lines.length === 0) return;
    onConfirm({ ips: lines, reason: bulkReason });
  };

  const parsedCount = rawText
    .split(/[\n,;]/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0).length;

  return (
    <div className="bl-modal" onClick={onClose}>
      <div className="bl-modal-card bl-modal-card--danger" onClick={(e) => e.stopPropagation()} dir="rtl">
        <div className="bl-modal-header">
          <h3 className="bl-modal-title">
            <UploadCloud size={18} style={{ color: '#00c8ff' }} />
            استيراد جماعي لعناوين IP ونطاقات CIDR
          </h3>
          <button className="bl-modal-close" onClick={onClose}><X size={16} /></button>
        </div>

        <form onSubmit={handleSubmit} className="bl-modal-body">
          <p style={{ margin: '0 0 14px', fontSize: '0.78rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
            أدخل قائمة العناوين (عنوان في كل سطر أو مفصولة بفواصل). سيتم فحصها وإضافتها لجدول eBPF.
          </p>

          <div className="bl-form-row">
            <label className="bl-form-lbl">قائمة العناوين (تم اكتشاف {parsedCount} عنوان)</label>
            <textarea
              className="bl-input"
              rows={6}
              placeholder="198.51.100.1&#10;203.0.113.50&#10;192.0.2.0/24"
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
              style={{ direction: 'ltr', textAlign: 'left', fontSize: '0.8rem' }}
              required
            />
          </div>

          <div className="bl-form-row">
            <label className="bl-form-lbl">السبب / الملاحظة لجميع العناوين</label>
            <input
              className="bl-input"
              style={{ fontFamily: 'Cairo, sans-serif' }}
              value={bulkReason}
              onChange={(e) => setBulkReason(e.target.value)}
            />
          </div>

          <div className="bl-modal-actions">
            <button type="button" className="bl-action-btn" onClick={onClose}>إلغاء</button>
            <button
              type="submit"
              className="bl-action-btn bl-action-btn--primary"
              disabled={loading || parsedCount === 0}
            >
              {loading ? <RefreshCw size={14} className="bl-spin" /> : <ShieldOff size={14} />}
              حظر {parsedCount} عنوان دفعة واحدة
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

/* ── Main Component: IPBlocklist ── */
export default function IPBlocklist() {
  const qc = useQueryClient();
  const [modalOpen, setModalOpen] = useState(false);
  const [bulkModalOpen, setBulkModalOpen] = useState(false);
  const [modalErr, setModalErr] = useState('');
  const [search, setSearch] = useState('');
  const [selectedTag, setSelectedTag] = useState('ALL');

  // Fetch blocklist
  const { data: rawList = [], isLoading, isFetching, refetch } = useQuery({
    queryKey: ['firewall-blocklist'],
    queryFn: () => firewallApi.blockedIps().then((r) => r.data?.blocked_ips || []),
    refetchInterval: 10000,
  });

  // Block mutation
  const blockMut = useMutation({
    mutationFn: ({ ip, reason, duration }) => firewallApi.blockIp(ip, reason, duration).then((r) => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['firewall-blocklist'] });
      setModalOpen(false);
      setModalErr('');
    },
    onError: (err) => setModalErr(err.response?.data?.detail || err.message),
  });

  // Bulk Block mutation
  const bulkBlockMut = useMutation({
    mutationFn: async ({ ips, reason }) => {
      for (const ip of ips) {
        await firewallApi.blockIp(ip, reason).catch(() => {});
      }
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['firewall-blocklist'] });
      setBulkModalOpen(false);
    },
  });

  // Unblock mutation
  const unblockMut = useMutation({
    mutationFn: (ip) => firewallApi.unblockIp(ip).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['firewall-blocklist'] }),
  });

  // Clear all mutation
  const clearMut = useMutation({
    mutationFn: () => firewallApi.unblockAll().then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['firewall-blocklist'] }),
  });

  // Normalized list
  const blocklist = useMemo(() => {
    return rawList.map((item) => {
      const ip = typeof item === 'string' ? item : item.ip;
      const reason = typeof item === 'object' ? item.reason || 'حظر يدوي' : 'حظر يدوي';
      const created_at = typeof item === 'object' ? (item.blocked_at || item.created_at || item.timestamp || item.ts) : null;
      const expires_at = typeof item === 'object' ? item.expires_at : null;
      const threat = inferThreatTag(reason);
      return { ip, reason, created_at, expires_at, threat };
    });
  }, [rawList]);

  // Filtered list
  const filtered = useMemo(() => {
    return blocklist.filter((b) => {
      const q = search.toLowerCase();
      const matchesSearch = !search || b.ip.toLowerCase().includes(q) || b.reason.toLowerCase().includes(q);
      const matchesTag = selectedTag === 'ALL' || b.threat.type === selectedTag;
      return matchesSearch && matchesTag;
    });
  }, [blocklist, search, selectedTag]);

  const permCount = blocklist.filter((b) => !b.expires_at).length;
  const tempCount = blocklist.filter((b) => !!b.expires_at).length;

  const exportCSV = () => {
    const rows = [['IP', 'Reason', 'Threat Tag', 'Expires At', 'Created At']];
    filtered.forEach((b) => rows.push([b.ip, b.reason, b.threat.label, b.expires_at || 'Permanent', b.created_at || '']));
    const csvContent = 'data:text/csv;charset=utf-8,' + rows.map((e) => e.join(',')).join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', 'bunyanx_blocked_ips.csv');
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="bl-root" dir="rtl">
      {/* ── Hero Bar ── */}
      <div className="bl-hero">
        <div className="bl-hero-glow" />
        <div className="bl-hero-inner">
          <div className="bl-hero-left">
            <div className="bl-hero-icon">
              <ShieldOff size={24} />
            </div>
            <div>
              <h2 className="bl-hero-title">قائمة الحظر الفوري بالنواة (IP Blocklist)</h2>
              <p className="bl-hero-sub">eBPF Kernel XDP_DROP Block Table · L3/L4 Dropping</p>
            </div>
          </div>

          <div className="bl-hero-right">
            <button className="bl-action-btn" onClick={() => refetch()}>
              <RefreshCw size={13} className={isFetching ? 'bl-spin' : ''} />
              تحديث
            </button>
            <button className="bl-action-btn" onClick={exportCSV}>
              <FileSpreadsheet size={13} />
              تصدير CSV
            </button>
            <button className="bl-action-btn" onClick={() => setBulkModalOpen(true)}>
              <UploadCloud size={13} />
              استيراد جماعي
            </button>
            <button className="bl-action-btn bl-action-btn--primary" onClick={() => setModalOpen(true)}>
              <Plus size={14} />
              حظر عنوان IP
            </button>
          </div>
        </div>
      </div>

      {/* ── KPI Stat Strip ── */}
      <div className="bl-stat-strip">
        <div className="bl-kpi-card" style={{ '--st-c': '#ff4d6a' }}>
          <div className="bl-kpi-icon" style={{ background: 'rgba(255, 77, 106, 0.12)', color: '#ff4d6a' }}>
            <ShieldOff size={20} />
          </div>
          <div>
            <div className="bl-kpi-lbl">إجمالي العناوين المحظورة</div>
            <div className="bl-kpi-val" style={{ color: '#ff4d6a' }}>{blocklist.length}</div>
          </div>
        </div>

        <div className="bl-kpi-card" style={{ '--st-c': '#ffab40' }}>
          <div className="bl-kpi-icon" style={{ background: 'rgba(255, 171, 64, 0.12)', color: '#ffab40' }}>
            <Clock size={20} />
          </div>
          <div>
            <div className="bl-kpi-lbl">حظر مؤقت ينتهي قريباً</div>
            <div className="bl-kpi-val" style={{ color: '#ffab40' }}>{tempCount}</div>
          </div>
        </div>

        <div className="bl-kpi-card" style={{ '--st-c': '#00c8ff' }}>
          <div className="bl-kpi-icon" style={{ background: 'rgba(0, 200, 255, 0.12)', color: '#00c8ff' }}>
            <Cpu size={20} />
          </div>
          <div>
            <div className="bl-kpi-lbl">محرك الإسقاط السريع</div>
            <div className="bl-kpi-val" style={{ color: '#00c8ff', fontSize: '1.1rem' }}>eBPF / XDP</div>
          </div>
        </div>
      </div>

      {/* ── Main Table Panel ── */}
      <div className="bl-panel">
        <div className="bl-panel-header">
          <div className="bl-panel-title">
            <ShieldOff size={16} style={{ color: '#ff4d6a' }} />
            <span>جدول العناوين المسقطة بالنواة ({filtered.length})</span>
          </div>

          <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
            {/* Search */}
            <div style={{ position: 'relative', width: 220 }}>
              <Search size={14} style={{ position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
              <input
                className="bl-input"
                style={{ paddingRight: 32, fontSize: '0.78rem' }}
                placeholder="بحث في العناوين أو الأسباب..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>

            {/* Tag Filter */}
            <select
              className="bl-input"
              style={{ width: 140, fontSize: '0.78rem' }}
              value={selectedTag}
              onChange={(e) => setSelectedTag(e.target.value)}
            >
              <option value="ALL">كافة التصنيفات</option>
              <option value="botnet">Botnet / DDoS</option>
              <option value="tor">Tor / Proxy</option>
              <option value="scanner">Port Scanner</option>
              <option value="bruteforce">Brute Force</option>
              <option value="custom">Manual Block</option>
            </select>

            {blocklist.length > 0 && (
              <button
                className="bl-action-btn bl-action-btn--clear"
                onClick={() => {
                  if (window.confirm('هل أنت متأكد من رغبتك في رفع الحظر عن كافة العناوين؟')) {
                    clearMut.mutate();
                  }
                }}
              >
                <Trash2 size={13} />
                تفريغ القائمة
              </button>
            )}
          </div>
        </div>

        <div className="bl-table-wrap">
          {isLoading ? (
            <div className="bl-empty">
              <RefreshCw size={24} className="bl-spin" style={{ color: '#00c8ff' }} />
              <span>جاري تحميل قائمة الحظر...</span>
            </div>
          ) : filtered.length === 0 ? (
            <div className="bl-empty">
              <CheckCircle2 size={40} style={{ color: '#00e676', opacity: 0.8 }} />
              <div style={{ fontWeight: 700, color: 'var(--text-primary)' }}>لا توجد عناوين محظورة تطابق البحث</div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>جداول eBPF نظيفة ولا يوجد حظر نشط حالياً</div>
            </div>
          ) : (
            <table className="bl-table">
              <thead>
                <tr>
                  <th>عنوان IP</th>
                  <th>التصنيف الأمني</th>
                  <th>سبب الحظر والملاحظات</th>
                  <th>الصلاحية</th>
                  <th>تاريخ الحظر</th>
                  <th style={{ textAlign: 'left' }}>إجراء</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((b) => (
                  <tr key={b.ip} className="bl-row">
                    <td>
                      <span className="bl-ip">{b.ip}</span>
                    </td>
                    <td>
                      <span className={`bl-tag bl-tag--${b.threat.type}`}>
                        <Tag size={10} /> {b.threat.label}
                      </span>
                    </td>
                    <td style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>
                      {b.reason}
                    </td>
                    <td>
                      <span className={`bl-expiry ${b.expires_at ? 'bl-expiry--temp' : 'bl-expiry--perm'}`}>
                        <Clock size={10} />
                        {fmtExpiry(b.expires_at)}
                      </span>
                    </td>
                    <td style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', fontFamily: 'JetBrains Mono, monospace' }}>
                      {fmtTime(b.created_at)}
                    </td>
                    <td style={{ textAlign: 'left' }}>
                      <button
                        className="bl-unblock-btn"
                        onClick={() => unblockMut.mutate(b.ip)}
                        disabled={unblockMut.isPending}
                        title="رفع الحظر الفوري"
                      >
                        <ShieldCheck size={13} />
                        إلغاء الحظر
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* ── Modals ── */}
      {modalOpen && (
        <BlockModal
          onClose={() => { setModalOpen(false); setModalErr(''); }}
          onConfirm={(body) => blockMut.mutate(body)}
          loading={blockMut.isPending}
          error={modalErr}
          onReset={() => setModalErr('')}
        />
      )}

      {bulkModalOpen && (
        <BulkImportModal
          onClose={() => setBulkModalOpen(false)}
          onConfirm={(data) => bulkBlockMut.mutate(data)}
          loading={bulkBlockMut.isPending}
        />
      )}
    </div>
  );
}
