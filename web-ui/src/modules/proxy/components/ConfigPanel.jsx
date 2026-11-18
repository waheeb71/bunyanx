import { useState, useEffect } from 'react';
import { Server, Activity, Network, Trash2, Plus, Shield, ShieldCheck, Save, AlertCircle, Copy, ExternalLink, RefreshCw } from 'lucide-react';
import { SectionCard, SkeletonLines } from '../../../components/Shared';
import Toggle from './Toggle';

export default function ConfigPanel({ config: cfg, configLoading, updateConfig, updateConfigPending, modeMeta, notify }) {
  const [formData, setFormData] = useState(cfg || {});
  const [hasChanges, setHasChanges] = useState(false);

  // New item form inputs
  const [newSsrfHost, setNewSsrfHost] = useState('');
  const [newBackendHost, setNewBackendHost] = useState('');
  const [newBackendPort, setNewBackendPort] = useState(8080);
  const [newBackendSsl, setNewBackendSsl] = useState(false);
  const [newHeader, setNewHeader] = useState('');

  // Keep formData synced with server config when loaded or updated
  useEffect(() => {
    if (cfg && Object.keys(cfg).length > 0) {
      setFormData(cfg);
      setHasChanges(false);
    }
  }, [cfg]);

  const updateField = (key, value) => {
    setFormData(prev => {
      const next = { ...prev, [key]: value };
      setHasChanges(true);
      return next;
    });
  };

  const updateHardeningField = (key, value) => {
    setFormData(prev => {
      const next = {
        ...prev,
        hardening: {
          ...(prev.hardening || {}),
          [key]: value,
        }
      };
      setHasChanges(true);
      return next;
    });
  };

  const handleAddBackend = () => {
    if (!newBackendHost) return;
    const currentBackends = formData.backends || [];
    const updated = [...currentBackends, { host: newBackendHost.trim(), port: Number(newBackendPort), ssl: newBackendSsl }];
    updateField('backends', updated);
    setNewBackendHost('');
    setNewBackendPort(8080);
    setNewBackendSsl(false);
  };

  const handleRemoveBackend = (idx) => {
    const updated = (formData.backends || []).filter((_, i) => i !== idx);
    updateField('backends', updated);
  };

  const handleAddSsrfHost = () => {
    if (!newSsrfHost.trim()) return;
    const currentHosts = formData.allowed_ssrf_hosts || [];
    if (currentHosts.includes(newSsrfHost.trim())) return;
    const updated = [...currentHosts, newSsrfHost.trim()];
    updateField('allowed_ssrf_hosts', updated);
    setNewSsrfHost('');
  };

  const handleRemoveSsrfHost = (host) => {
    const updated = (formData.allowed_ssrf_hosts || []).filter(h => h !== host);
    updateField('allowed_ssrf_hosts', updated);
  };

  const handleAddStripHeader = () => {
    if (!newHeader.trim()) return;
    const currentHeaders = formData.hardening?.strip_headers || [];
    if (currentHeaders.includes(newHeader.trim())) return;
    const updated = [...currentHeaders, newHeader.trim()];
    updateHardeningField('strip_headers', updated);
    setNewHeader('');
  };

  const handleRemoveStripHeader = (hdr) => {
    const currentHeaders = formData.hardening?.strip_headers || [];
    const updated = currentHeaders.filter(h => h !== hdr);
    updateHardeningField('strip_headers', updated);
  };

  const handleSave = () => {
    updateConfig(formData, {
      onSuccess: () => {
        setHasChanges(false);
        if (notify) notify({ type: 'success', message: 'تم حفظ إعدادات البروكسي وتحديث الخدمة بنجاح' });
      },
      onError: (err) => {
        if (notify) notify({ type: 'error', message: err?.response?.data?.detail || 'حدث خطأ أثناء حفظ الإعدادات' });
      }
    });
  };

  if (configLoading) {
    return <SectionCard><SkeletonLines count={6} /></SectionCard>;
  }

  const mode = formData.mode || 'transparent_proxy';
  const currentModeMeta = modeMeta?.[mode] || modeMeta?.transparent_proxy || {};

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
      {/* Save Action Banner when changes exist */}
      {hasChanges && (
        <div className="prx-save-banner">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <AlertCircle size={18} color="var(--warning)" />
            <span>هناك تغييرات غير محفوظة في إعدادات البروكسي</span>
          </div>
          <button
            className="prx-btn-save"
            onClick={handleSave}
            disabled={updateConfigPending}
          >
            <Save size={16} />
            {updateConfigPending ? 'جاري الحفظ...' : 'حفظ التغييرات'}
          </button>
        </div>
      )}

      {/* ── 1. Engine & Mode Status ── */}
      <SectionCard title="حالة المحرك ونمط التشغيل" icon={Activity}>
        <div className="prx-config-row">
          <div>
            <div style={{ fontWeight: 700 }}>تمكين محرك البروكسي (Proxy Engine)</div>
            <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>تشغيل خدمة البروكسي الداخلية لاعتراض وحماية حركة المرور.</div>
          </div>
          <Toggle
            checked={!!formData.is_active}
            onChange={() => updateField('is_active', !formData.is_active)}
          />
        </div>

        <div className="prx-config-row" style={{ marginTop: 'var(--sp-3)' }}>
          <div>
            <div style={{ fontWeight: 700 }}>وضع البروكسي (Proxy Mode)</div>
            <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginTop: 4 }}>{currentModeMeta.desc}</div>
          </div>
          <select
            className="prx-input" style={{ minWidth: 240 }}
            value={mode}
            onChange={e => updateField('mode', e.target.value)}
          >
            <option value="transparent_proxy">بروكسي شفاف (Transparent Proxy)</option>
            <option value="forward_proxy">بروكسي توجيه قياسي (Forward Proxy)</option>
            <option value="reverse_proxy">بروكسي عكسي (Reverse Proxy)</option>
          </select>
        </div>
      </SectionCard>

      {/* ── 2. Network Core Ports & Limits ── */}
      <SectionCard title="إعدادات الشبكة والمنافذ (Network & Limits)" icon={Network}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 'var(--sp-3)' }}>
          <div className="prx-field-group">
            <label>منفذ الاستماع المشفّر (HTTPS Listen Port)</label>
            <input
              type="number" className="prx-input mono"
              value={formData.listen_port || 8443}
              onChange={e => updateField('listen_port', +e.target.value)}
            />
          </div>

          <div className="prx-field-group">
            <label>منفذ الاستماع العادي (HTTP Port)</label>
            <input
              type="number" className="prx-input mono"
              value={formData.http_port || 8080}
              onChange={e => updateField('http_port', +e.target.value)}
            />
          </div>

          <div className="prx-field-group">
            <label>الحد الأقصى للاتصالات المتزامنة (Max Connections)</label>
            <input
              type="number" className="prx-input mono"
              value={formData.max_connections || 10000}
              onChange={e => updateField('max_connections', +e.target.value)}
            />
          </div>

          <div className="prx-field-group">
            <label>حجم بفر القراءة للطلب (Buffer Size - Bytes)</label>
            <input
              type="number" className="prx-input mono"
              value={formData.buffer_size || 65536}
              onChange={e => updateField('buffer_size', +e.target.value)}
            />
          </div>

          <div className="prx-field-group">
            <label>مهلة إغلاق الاتصال الخامل (Connection Timeout - Sec)</label>
            <input
              type="number" className="prx-input mono"
              value={formData.connection_timeout || 300}
              onChange={e => updateField('connection_timeout', +e.target.value)}
            />
          </div>

          <div className="prx-field-group" style={{ justifyContent: 'center' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer', marginTop: 22 }}>
              <Toggle
                checked={!!formData.strict_cert_validation}
                onChange={() => updateField('strict_cert_validation', !formData.strict_cert_validation)}
              />
              <div>
                <div style={{ fontWeight: 600, fontSize: '0.88rem' }}>فحص الشهادات الصارم (Strict SSL)</div>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>رفض شهادات الخوادم غير الموثوقة أو المنتهية.</div>
              </div>
            </label>
          </div>
        </div>
      </SectionCard>

      {/* ── 3. Reverse Proxy & Health Checks (only relevant for Reverse Proxy or VIPs) ── */}
      <SectionCard title="الخوادم الخلفية وفحص الصحة (Reverse Proxy & Health Checks)" icon={Server}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 'var(--sp-3)', marginBottom: 'var(--sp-3)' }}>
          <div className="prx-field-group">
            <label>فترة فحص صحة الخوادم (Health Check Interval - Sec)</label>
            <input
              type="number" className="prx-input mono"
              value={formData.health_check_interval || 10}
              onChange={e => updateField('health_check_interval', +e.target.value)}
            />
          </div>

          <div className="prx-field-group">
            <label>مهلة استجابة فحص الصحة (Health Check Timeout - Sec)</label>
            <input
              type="number" className="prx-input mono"
              value={formData.health_check_timeout || 3}
              onChange={e => updateField('health_check_timeout', +e.target.value)}
            />
          </div>
        </div>

        <div style={{ fontWeight: 600, marginBottom: 8, fontSize: '0.9rem' }}>قائمة الخوادم الخلفية المعرفة (Backends):</div>
        {(!formData.backends || formData.backends.length === 0) ? (
          <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: 12 }}>لا توجد خوادم خلفية مضافة حالياً.</div>
        ) : (
          <div className="prx-table-wrapper" style={{ marginBottom: 12 }}>
            <table className="prx-table">
              <thead>
                <tr>
                  <th>العنوان (Host)</th>
                  <th>المنفذ (Port)</th>
                  <th>تشفير (SSL/TLS)</th>
                  <th style={{ width: 60 }}>حذف</th>
                </tr>
              </thead>
              <tbody>
                {formData.backends.map((b, idx) => (
                  <tr key={idx}>
                    <td className="mono">{b.host}</td>
                    <td className="mono">{b.port}</td>
                    <td>
                      <span className={`prx-badge ${b.ssl ? 'https' : 'http'}`}>
                        {b.ssl ? 'HTTPS (SSL)' : 'HTTP'}
                      </span>
                    </td>
                    <td>
                      <button className="prx-btn-delete" onClick={() => handleRemoveBackend(idx)}>
                        <Trash2 size={14} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Add Backend Inline */}
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <input
            type="text" placeholder="مثال: 10.10.0.50 أو backend.internal"
            className="prx-input mono" style={{ flex: 2, minWidth: 180 }}
            value={newBackendHost} onChange={e => setNewBackendHost(e.target.value)}
          />
          <input
            type="number" placeholder="Port"
            className="prx-input mono" style={{ width: 100 }}
            value={newBackendPort} onChange={e => setNewBackendPort(e.target.value)}
          />
          <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.82rem', cursor: 'pointer' }}>
            <span>SSL:</span>
            <Toggle checked={newBackendSsl} onChange={() => setNewBackendSsl(!newBackendSsl)} />
          </label>
          <button type="button" className="prx-btn-add" onClick={handleAddBackend}>
            <Plus size={14} /> إضافة خادم
          </button>
        </div>
      </SectionCard>

      {/* ── 4. HTTP Hardening & Server Cloaking ── */}
      <SectionCard title="تصلب وتخفي الهيدرات (HTTP Hardening & Cloaking)" icon={ShieldCheck}>
        <div className="prx-config-row" style={{ marginBottom: 'var(--sp-3)' }}>
          <div>
            <div style={{ fontWeight: 700 }}>تمكين التخفي الهيكلي (Server Cloaking)</div>
            <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>إزالة هيدرات الخوادم الأصلية واستبدالها لتقليل مخاطر الاستطلاع (Reconnaissance).</div>
          </div>
          <Toggle
            checked={!!formData.hardening?.cloaking_enabled}
            onChange={() => updateHardeningField('cloaking_enabled', !formData.hardening?.cloaking_enabled)}
          />
        </div>

        <div className="prx-field-group" style={{ marginBottom: 'var(--sp-3)' }}>
          <label>اسم بانر السيرفر الموهوم (Server Banner Header)</label>
          <input
            type="text" className="prx-input mono"
            value={formData.hardening?.server_banner || 'bunyanx-NGFW'}
            onChange={e => updateHardeningField('server_banner', e.target.value)}
          />
        </div>

        <div style={{ fontWeight: 600, marginBottom: 8, fontSize: '0.9rem' }}>الهيدرات المحذوفة تلقائياً (Strip Headers):</div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 12 }}>
          {(formData.hardening?.strip_headers || []).map((hdr, idx) => (
            <span key={idx} className="prx-pill-tag">
              {hdr}
              <button type="button" onClick={() => handleRemoveStripHeader(hdr)}><Trash2 size={12} /></button>
            </span>
          ))}
        </div>

        <div style={{ display: 'flex', gap: 8 }}>
          <input
            type="text" placeholder="إضافة هيدر آخر للمسح (مثال: X-Powered-By)"
            className="prx-input mono" style={{ flex: 1 }}
            value={newHeader} onChange={e => setNewHeader(e.target.value)}
          />
          <button type="button" className="prx-btn-add" onClick={handleAddStripHeader}>
            <Plus size={14} /> إضافة
          </button>
        </div>
      </SectionCard>

      {/* ── 5. SSRF Whitelist ── */}
      <SectionCard title="قائمة السماح ضد هجمات الـ SSRF (Allowed SSRF Hosts)" icon={Shield}>
        <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: 10 }}>
          استثناء عناوين أو نطاقات معينة من قيود منع الطلبات الداخلية عبر الـ Proxy.
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 12 }}>
          {(!formData.allowed_ssrf_hosts || formData.allowed_ssrf_hosts.length === 0) ? (
            <span style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>لا توجد عناوين مستثناة من الـ SSRF حالياً.</span>
          ) : (
            formData.allowed_ssrf_hosts.map((host, idx) => (
              <span key={idx} className="prx-pill-tag accent">
                {host}
                <button type="button" onClick={() => handleRemoveSsrfHost(host)}><Trash2 size={12} /></button>
              </span>
            ))
          )}
        </div>

        <div style={{ display: 'flex', gap: 8 }}>
          <input
            type="text" placeholder="مثال: internal-api.company.local"
            className="prx-input mono" style={{ flex: 1 }}
            value={newSsrfHost} onChange={e => setNewSsrfHost(e.target.value)}
          />
          <button type="button" className="prx-btn-add" onClick={handleAddSsrfHost}>
            <Plus size={14} /> إضافة نطاق
          </button>
        </div>
      </SectionCard>
    </div>
  );
}
