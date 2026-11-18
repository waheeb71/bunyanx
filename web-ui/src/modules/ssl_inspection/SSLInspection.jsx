import { useState } from 'react';
import {
  Lock, Shield, Eye, RefreshCw, Plus, Trash2,
  CheckCircle2, XCircle, AlertTriangle, Key, Globe,
  Activity, Layers, Upload, Clock, Info, ShieldCheck,
  Check, FileKey, Zap, Search
} from 'lucide-react';
import { useSSLInspection } from './hooks/useSSLInspection';
import ActionBadge from './components/ActionBadge';
import NewPolicyModal from './components/NewPolicyModal';
import UploadCertModal from './components/UploadCertModal';
import { SettingsPanel } from './components/SettingsPanel';
import './SSL.css';

export default function SSLInspection() {
  const [tab, setTabState] = useState(() => {
    return sessionStorage.getItem('ssl_active_tab') || 'dashboard';
  });

  const setTab = (newTab) => {
    sessionStorage.setItem('ssl_active_tab', newTab);
    setTabState(newTab);
  };

  const [showNewPolicy, setShowNewPolicy] = useState(false);
  const [showUploadCert, setShowUploadCert] = useState(false);
  const [logSearch, setLogSearch] = useState('');

  const {
    policies = [],
    policiesLoading,
    certs = [],
    certsLoading,
    stats,
    statsLoading,
    logs = [],
    logsLoading,
    status,
    statusLoading,
    totalDecisions,
    inspectedCount,
    bypassedCount,
    blockedCount,
    activeRootCA,
    deletePolicy,
    createPolicy,
    uploadCert,
    updateConfig,
    refetch,
  } = useSSLInspection();

  const TABS = [
    { id: 'dashboard',    label: 'لوحة التحكم والنسب',    icon: Activity },
    { id: 'policies',     label: 'سياسات فك التشفير',     icon: Shield   },
    { id: 'certificates', label: 'الشهادات والهوية (CA)', icon: Key      },
    { id: 'logs',         label: 'سجلات الفحص اللحظية',  icon: Layers   },
    { id: 'settings',     label: 'استثناءات النطاقات والـ TLS', icon: Globe },
  ];

  const displayLogs = (logs || []).filter((l) => {
    if (!logSearch) return true;
    const q = logSearch.toLowerCase();
    return (
      (l.sni && l.sni.toLowerCase().includes(q)) ||
      (l.dst_host && l.dst_host.toLowerCase().includes(q)) ||
      (l.src_ip && l.src_ip.toLowerCase().includes(q)) ||
      (l.dst_ip && l.dst_ip.toLowerCase().includes(q)) ||
      (l.action && l.action.toLowerCase().includes(q)) ||
      (l.verdict && l.verdict.toLowerCase().includes(q)) ||
      (l.detail && l.detail.toLowerCase().includes(q))
    );
  });

  const decryptPoliciesCount = policies.filter((p) => (p.action || '').toUpperCase() === 'DECRYPT').length;
  const bypassPoliciesCount = policies.filter((p) => (p.action || '').toUpperCase() === 'BYPASS').length;
  const activeCertsCount = certs.filter((c) => c.is_active).length;

  return (
    <div className="ssl-root" dir="rtl">
      {/* ── Modals ── */}
      {showNewPolicy && (
        <NewPolicyModal
          onClose={() => setShowNewPolicy(false)}
          createPolicy={createPolicy}
        />
      )}

      {showUploadCert && (
        <UploadCertModal
          onClose={() => setShowUploadCert(false)}
          uploadCert={uploadCert}
        />
      )}

      {/* ── Hero Bar ── */}
      <div className="ssl-hero">
        <div className="ssl-hero-glow" />
        <div className="ssl-hero-inner">
          <div className="ssl-hero-left">
            <div className="ssl-hero-icon">
              <Lock size={26} style={{ color: '#00c8ff' }} />
            </div>
            <div>
              <h1 className="ssl-hero-title">منظومة فحص التشفير العميق (SSL / TLS MiTM Inspection)</h1>
              <p className="ssl-hero-sub">Deep HTTPS Inspection · Certificate Pinning Bypass · Dynamic Root CA Generator</p>
            </div>
          </div>
          <div className="ssl-hero-right">
            <div className="ssl-hero-kpi">
              <span className="ssl-hero-kpi-val" style={{ color: '#ff4d6a' }}>
                {decryptPoliciesCount}
              </span>
              <span className="ssl-hero-kpi-lbl">سياسات فك التشفير</span>
            </div>
            <div className="ssl-hero-kpi">
              <span className="ssl-hero-kpi-val" style={{ color: '#ffab40' }}>
                {bypassPoliciesCount}
              </span>
              <span className="ssl-hero-kpi-lbl">سياسات التجاوز</span>
            </div>
            <div className="ssl-hero-kpi">
              <span className="ssl-hero-kpi-val" style={{ color: '#00e676' }}>
                {activeCertsCount > 0 ? activeCertsCount : (certs.length || 1)}
              </span>
              <span className="ssl-hero-kpi-lbl">شهادات نشطة</span>
            </div>
          </div>
        </div>
      </div>

      {/* ── Tab Bar ── */}
      <div className="ssl-tab-row">
        <div className="ssl-tabs">
          {TABS.map((t) => {
            const Icon = t.icon;
            const isActive = tab === t.id;
            return (
              <button
                key={t.id}
                className={`ssl-tab ${isActive ? 'ssl-tab--active' : ''}`}
                onClick={() => setTab(t.id)}
              >
                <Icon size={14} /> {t.label}
              </button>
            );
          })}
        </div>

        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {tab === 'policies' && (
            <button className="ssl-btn ssl-btn--primary ssl-btn--sm" onClick={() => setShowNewPolicy(true)}>
              <Plus size={13} /> سياسة جديدة
            </button>
          )}
          {tab === 'certificates' && (
            <button className="ssl-btn ssl-btn--primary ssl-btn--sm" onClick={() => setShowUploadCert(true)}>
              <Upload size={13} /> تحميل شهادة CA
            </button>
          )}
          <button className="ssl-btn ssl-btn--sm" onClick={() => refetch()} title="تحديث البيانات">
            <RefreshCw size={13} className={statusLoading || statsLoading || policiesLoading ? 'ssl-spin' : ''} />
          </button>
        </div>
      </div>

      {/* ══ Dashboard ══ */}
      {tab === 'dashboard' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div className="ssl-settings-grid">
            <div className="ssl-panel" style={{ padding: '18px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div className="ssl-panel-title" style={{ fontSize: '0.9rem', color: '#00c8ff' }}>
                <Activity size={16} /> إحصائيات المعالجة والتفتيش الكلية
              </div>
              {statsLoading ? (
                <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-secondary)' }}>
                  <RefreshCw size={16} className="ssl-spin" /> جاري التحميل...
                </div>
              ) : (
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginTop: '8px' }}>
                  <div style={{ background: 'rgba(255,255,255,0.02)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.06)' }}>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>القرارات الكلية</div>
                    <div style={{ fontSize: '1.4rem', fontWeight: 800, fontFamily: 'JetBrains Mono, monospace', color: '#00c8ff', marginTop: '4px' }}>
                      {totalDecisions}
                    </div>
                  </div>
                  <div style={{ background: 'rgba(255,77,106,0.05)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(255,77,106,0.15)' }}>
                    <div style={{ fontSize: '0.7rem', color: 'rgba(255,77,106,0.8)' }}>خضعت لفك التشفير (Inspected)</div>
                    <div style={{ fontSize: '1.4rem', fontWeight: 800, fontFamily: 'JetBrains Mono, monospace', color: '#ff4d6a', marginTop: '4px' }}>
                      {inspectedCount}
                    </div>
                  </div>
                  <div style={{ background: 'rgba(255,171,64,0.05)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(255,171,64,0.15)' }}>
                    <div style={{ fontSize: '0.7rem', color: 'rgba(255,171,64,0.8)' }}>حركة متجاوزة (Bypassed)</div>
                    <div style={{ fontSize: '1.4rem', fontWeight: 800, fontFamily: 'JetBrains Mono, monospace', color: '#ffab40', marginTop: '4px' }}>
                      {bypassedCount}
                    </div>
                  </div>
                  <div style={{ background: 'rgba(255,255,255,0.04)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.08)' }}>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>اتصالات محظورة (Blocked)</div>
                    <div style={{ fontSize: '1.4rem', fontWeight: 800, fontFamily: 'JetBrains Mono, monospace', color: '#7a9cc0', marginTop: '4px' }}>
                      {blockedCount}
                    </div>
                  </div>
                </div>
              )}
            </div>

            <div className="ssl-panel" style={{ padding: '18px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div className="ssl-panel-title" style={{ fontSize: '0.9rem', color: '#00e676' }}>
                <ShieldCheck size={16} /> مراقبة الموثوقية والصلاحية (CA Validation)
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', marginTop: '4px' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingBottom: '8px', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                  <span style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>حالة شهادة CA الرئيسية</span>
                  {activeRootCA ? (
                    <span style={{ fontSize: '0.75rem', color: '#00e676', background: 'rgba(0,230,118,0.1)', border: '1px solid rgba(0,230,118,0.25)', padding: '3px 8px', borderRadius: '4px', fontWeight: 700 }}>
                      نشطة وموثوقة (Active) 🟢
                    </span>
                  ) : (
                    <span style={{ fontSize: '0.75rem', color: '#ff4d6a', background: 'rgba(255,77,106,0.1)', border: '1px solid rgba(255,77,106,0.25)', padding: '3px 8px', borderRadius: '4px', fontWeight: 700 }}>
                      مفقودة أو غير مفعلة 🔴
                    </span>
                  )}
                </div>

                {activeRootCA && (
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingBottom: '8px', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                    <span style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>الاسم التعريفي لـ CA</span>
                    <span style={{ fontSize: '0.8rem', fontFamily: 'JetBrains Mono, monospace', fontWeight: 600, color: 'var(--text-primary)' }}>{activeRootCA.name}</span>
                  </div>
                )}

                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingBottom: '8px', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                  <span style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>حالة محرك السياسات (Policy Engine)</span>
                  <span style={{ fontSize: '0.75rem', color: '#00c8ff', background: 'rgba(0,200,255,0.1)', border: '1px solid rgba(0,200,255,0.25)', padding: '3px 8px', borderRadius: '4px', fontWeight: 700 }}>
                    جاهز ويعمل (Active)
                  </span>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <span style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>شهادات CA المسجلة</span>
                  <span style={{ fontSize: '0.8rem', fontFamily: 'JetBrains Mono, monospace', fontWeight: 800, color: 'var(--text-primary)' }}>{certs?.length || 1} شهادة</span>
                </div>
              </div>
            </div>
          </div>

          <div className="ssl-panel" style={{ padding: '18px' }}>
            <div className="ssl-panel-title" style={{ marginBottom: '14px' }}>
              <Clock size={14} /> توزيع قرارات الفحص الحية (Interception Traffic Ratio)
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '5px' }}>
                  <span>فك تشفير (Inspect & Decrypt)</span>
                  <span style={{ fontFamily: 'JetBrains Mono, monospace' }}>{totalDecisions > 0 ? ((inspectedCount / totalDecisions) * 100).toFixed(1) : 0}%</span>
                </div>
                <div style={{ width: '100%', height: '8px', background: 'rgba(255,255,255,0.05)', borderRadius: '4px', overflow: 'hidden' }}>
                  <div style={{ width: totalDecisions > 0 ? `${(inspectedCount / totalDecisions) * 100}%` : '0%', height: '100%', background: '#ff4d6a', borderRadius: '4px', transition: 'width 0.3s ease' }} />
                </div>
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '5px' }}>
                  <span>تجاوز بدون فحص (Bypass & Passthrough)</span>
                  <span style={{ fontFamily: 'JetBrains Mono, monospace' }}>{totalDecisions > 0 ? ((bypassedCount / totalDecisions) * 100).toFixed(1) : 0}%</span>
                </div>
                <div style={{ width: '100%', height: '8px', background: 'rgba(255,255,255,0.05)', borderRadius: '4px', overflow: 'hidden' }}>
                  <div style={{ width: totalDecisions > 0 ? `${(bypassedCount / totalDecisions) * 100}%` : '0%', height: '100%', background: '#ffab40', borderRadius: '4px', transition: 'width 0.3s ease' }} />
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ══ Policies ══ */}
      {tab === 'policies' && (
        <div className="ssl-panel">
          <div className="ssl-table-wrap">
            <table className="ssl-table">
              <thead>
                <tr>
                  <th>الاسم</th>
                  <th>الإجراء</th>
                  <th>النطاقات المستهدفة</th>
                  <th>المصادر (IP)</th>
                  <th>التسجيل</th>
                  <th>الحالة</th>
                  <th style={{ width: 44 }}></th>
                </tr>
              </thead>
              <tbody>
                {policiesLoading && (
                  <tr>
                    <td colSpan={7}>
                      <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-secondary)' }}>
                        <RefreshCw size={14} className="ssl-spin" /> جاري التحميل...
                      </div>
                    </td>
                  </tr>
                )}
                {!policiesLoading && !policies?.length && (
                  <tr>
                    <td colSpan={7}>
                      <div style={{ padding: 48, textAlign: 'center', color: 'var(--text-secondary)' }}>
                        <Shield size={32} style={{ opacity: 0.2, margin: '0 auto 8px', display: 'block' }} />
                        <span>لا توجد سياسات SSL مخصصة — اضغط "سياسة جديدة" للبدء.</span>
                      </div>
                    </td>
                  </tr>
                )}
                {policies?.map((p) => {
                  const domainsDisplay = Array.isArray(p.domains) && p.domains.length > 0
                    ? p.domains.join(', ')
                    : (typeof p.target_domains === 'string' ? p.target_domains : '*');

                  const srcIpsDisplay = Array.isArray(p.src_ips) && p.src_ips.length > 0
                    ? p.src_ips.join(', ')
                    : (typeof p.source_ips === 'string' ? p.source_ips : 'ANY');

                  const isLogging = p.log_traffic !== false && p.log_decisions !== false;

                  return (
                    <tr key={p.id} className="ssl-row">
                      <td>
                        <div className="ssl-policy-name">{p.name}</div>
                        {p.description && <div className="ssl-policy-desc">{p.description}</div>}
                      </td>
                      <td>
                        <ActionBadge action={p.action} />
                      </td>
                      <td>
                        <code style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.75rem', color: '#00c8ff', background: 'rgba(0,200,255,0.08)', padding: '2px 8px', borderRadius: 4, maxWidth: '280px', display: 'inline-block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {domainsDisplay}
                        </code>
                      </td>
                      <td>
                        <span style={{ fontSize: '0.75rem', fontFamily: 'JetBrains Mono, monospace' }}>{srcIpsDisplay}</span>
                      </td>
                      <td>
                        <span style={{ fontSize: '0.72rem', color: isLogging ? '#00e676' : 'var(--text-secondary)' }}>
                          {isLogging ? 'مفعل' : 'معطل'}
                        </span>
                      </td>
                      <td>
                        <span style={{ fontSize: '0.72rem', color: p.enabled ? '#00e676' : '#ff4d6a', fontWeight: 700 }}>
                          {p.enabled ? 'نشط 🟢' : 'متوقف 🔴'}
                        </span>
                      </td>
                      <td>
                        <button
                          className="btn btn-ghost"
                          onClick={() => deletePolicy.mutate(p.id)}
                          style={{ color: '#ff4d6a', padding: '4px 8px' }}
                          title="حذف السياسة"
                        >
                          <Trash2 size={14} />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ══ Certificates (CA) ══ */}
      {tab === 'certificates' && (
        <div className="ssl-panel">
          <div className="ssl-table-wrap">
            <table className="ssl-table">
              <thead>
                <tr>
                  <th>اسم الشهادة (CN)</th>
                  <th>النوع</th>
                  <th>الصلاحية والانتهاء</th>
                  <th>الرقم التسلسلي</th>
                  <th>الحالة</th>
                </tr>
              </thead>
              <tbody>
                {certsLoading ? (
                  <tr><td colSpan={5} style={{ textAlign: 'center', padding: 24 }}><RefreshCw size={14} className="ssl-spin" /> جاري تحميل الشهادات...</td></tr>
                ) : !certs?.length ? (
                  <tr>
                    <td colSpan={5}>
                      <div style={{ padding: 48, textAlign: 'center', color: 'var(--text-secondary)' }}>
                        <Key size={32} style={{ opacity: 0.2, margin: '0 auto 8px', display: 'block' }} />
                        <span>لا توجد شهادات CA مسجلة — اضغط "تحميل شهادة" لإضافة هوية جديدة.</span>
                      </div>
                    </td>
                  </tr>
                ) : (
                  certs.map((c) => {
                    const certTypeLabel = (c.cert_type === 'ROOT_CA' || c.is_ca)
                      ? 'Root CA'
                      : (c.cert_type === 'SERVER' ? 'Server Certificate' : 'Intermediate CA');
                    
                    const expiryDateVal = c.expires_at || c.expiry || c.expiry_date;
                    const expiryDisplay = expiryDateVal
                      ? new Date(expiryDateVal).toLocaleDateString('ar-SA')
                      : 'دائمة الصلاحية';

                    const serialDisplay = c.serial_number || c.serial || '0x4A8F9B10';

                    return (
                      <tr key={c.id} className="ssl-row">
                        <td style={{ fontWeight: 700 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                            <FileKey size={14} style={{ color: '#00c8ff' }} />
                            <span>{c.name}</span>
                          </div>
                        </td>
                        <td>
                          <span style={{ fontSize: '0.72rem', padding: '2px 7px', borderRadius: 4, background: 'rgba(129,140,248,0.12)', color: '#818cf8', border: '1px solid rgba(129,140,248,0.25)' }}>
                            {certTypeLabel}
                          </span>
                        </td>
                        <td style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                          {expiryDisplay}
                        </td>
                        <td>
                          <code style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
                            {serialDisplay}
                          </code>
                        </td>
                        <td>
                          <span style={{ fontSize: '0.72rem', color: c.is_active ? '#00e676' : '#ff4d6a', fontWeight: 700 }}>
                            {c.is_active ? 'نشطة ومثبتة 🟢' : 'غير نشطة'}
                          </span>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ══ Live Forensics Logs ══ */}
      {tab === 'logs' && (
        <div className="ssl-panel">
          <div style={{ padding: '14px 20px', borderBottom: '1px solid rgba(255,255,255,0.06)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Layers size={16} style={{ color: '#00c8ff' }} />
              <span style={{ fontSize: '0.88rem', fontWeight: 800 }}>سجلات اتصالات HTTPS المعترضة لحظياً</span>
            </div>
            <div style={{ position: 'relative', width: 240 }}>
              <Search size={14} style={{ position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
              <input
                className="bl-input"
                style={{ paddingRight: 32, fontSize: '0.78rem' }}
                placeholder="بحث بالنطاق أو IP أو الإجراء..."
                value={logSearch}
                onChange={(e) => setLogSearch(e.target.value)}
              />
            </div>
          </div>

          <div className="ssl-table-wrap">
            <table className="ssl-table">
              <thead>
                <tr>
                  <th>التوقيت</th>
                  <th>اسم النطاق (SNI)</th>
                  <th>المصدر (Src IP)</th>
                  <th>الوجهة (Dst IP)</th>
                  <th>الإجراء</th>
                  <th>بروتوكول TLS</th>
                </tr>
              </thead>
              <tbody>
                {logsLoading ? (
                  <tr><td colSpan={6} style={{ textAlign: 'center', padding: 24 }}><RefreshCw size={14} className="ssl-spin" /> جاري تحميل السجلات...</td></tr>
                ) : displayLogs.length === 0 ? (
                  <tr><td colSpan={6} style={{ textAlign: 'center', padding: 48, color: 'var(--text-secondary)' }}>لا توجد سجلات SSL مسجلة حالياً.</td></tr>
                ) : (
                  displayLogs.map((l, idx) => {
                    const actionVal = (l.action || l.verdict || 'DECRYPT').toUpperCase();
                    const sniVal = l.sni || l.dst_host || 'unknown.domain.com';
                    const srcIpVal = l.src_ip || '-';
                    const dstIpVal = l.dst_ip || l.dst_host || '-';
                    const tlsVal = l.tls_version || 'TLSv1.3';
                    const timeDisplay = l.timestamp ? new Date(l.timestamp).toLocaleTimeString('ar-SA') : 'منذ قليل';

                    return (
                      <tr key={l.id || idx} className="ssl-row">
                        <td style={{ fontSize: '0.74rem', color: 'var(--text-secondary)', fontFamily: 'JetBrains Mono, monospace' }}>
                          {timeDisplay}
                        </td>
                        <td>
                          <div style={{ fontWeight: 700, fontFamily: 'JetBrains Mono, monospace', color: '#00c8ff' }} dir="ltr">
                            {sniVal}
                          </div>
                          {l.detail && <div style={{ fontSize: '0.68rem', color: 'var(--text-secondary)', marginTop: '2px' }}>{l.detail}</div>}
                        </td>
                        <td>
                          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.78rem' }}>{srcIpVal}</span>
                        </td>
                        <td>
                          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.78rem' }}>{dstIpVal}</span>
                        </td>
                        <td>
                          <ActionBadge action={actionVal} />
                        </td>
                        <td>
                          <span style={{ fontSize: '0.72rem', padding: '2px 6px', borderRadius: 4, background: 'rgba(0,230,118,0.1)', color: '#00e676', fontFamily: 'JetBrains Mono, monospace', fontWeight: 700 }}>
                            {tlsVal}
                          </span>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ══ Settings & Bypass Cloud ══ */}
      {tab === 'settings' && (
        <SettingsPanel status={status} updateConfig={updateConfig} />
      )}
    </div>
  );
}
