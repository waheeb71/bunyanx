import React, { useState, useEffect } from 'react';
import {
  Shield, ShieldCheck, Key, Activity, Globe, Layers, Info, Save,
  RefreshCw, CheckCircle2, Plus, X, Tag, Sparkles, Building2, Landmark,
  Cloud, Lock, Sliders, Check
} from 'lucide-react';

/* ── Pre-defined Regulatory Domain Presets ── */
const PRESETS = {
  saudi_banks: {
    label: 'القطاع المالي والبنكي (SAMA & Banks)',
    icon: Landmark,
    category: 'financial',
    domains: [
      '*.sama.gov.sa',
      '*.alrajhibank.com.sa',
      '*.alahli.com',
      '*.alinma.com',
      '*.riyadbank.com',
      '*.albilad.com',
      '*.anb.com.sa',
      '*.bsf.com.sa',
      '*.sabb.com',
      '*.bankaljazira.com'
    ]
  },
  saudi_gov: {
    label: 'الخدمات الحكومية والهوية (Gov.sa & Nafath)',
    icon: Building2,
    category: 'gov',
    domains: [
      '*.gov.sa',
      '*.absher.sa',
      '*.iam.gov.sa',
      '*.nafath.gov.sa',
      '*.moj.gov.sa',
      '*.zatca.gov.sa',
      '*.nic.gov.sa',
      '*.sdaia.gov.sa'
    ]
  },
  cloud_pinning: {
    label: 'تحديثات Certificate Pinning (Apple, MS, Google)',
    icon: Cloud,
    category: 'pinned',
    domains: [
      '*.apple.com',
      '*.icloud.com',
      '*.windowsupdate.com',
      '*.microsoft.com',
      '*.google.com',
      '*.googleapis.com',
      '*.digicert.com',
      '*.letsencrypt.org'
    ]
  }
};

export function SettingsPanel({ status, updateConfig }) {
  const [form, setForm] = useState(null);
  const [saveMsg, setSaveMsg] = useState(null);
  const [newDomainInput, setNewDomainInput] = useState('');
  const [activeFilter, setActiveFilter] = useState('ALL');

  useEffect(() => {
    if (status) {
      setForm({
        enabled: status.enabled !== false,
        default_action: status.default_action || 'inspect',
        detect_pinning: status.detect_pinning !== false,
        pinning_action: status.pinning_action || 'bypass',
        bypass_domains: status.bypass_domains || [
          '*.sama.gov.sa',
          '*.alrajhibank.com.sa',
          '*.absher.sa',
          '*.apple.com',
          '*.windowsupdate.com'
        ],
        pinned_domains: status.pinned_domains || [],
        bypass_ips: status.bypass_ips || [],
        bypass_categories: status.bypass_categories || [],
        tls: {
          min_tls_version: status.tls?.min_tls_version || 'TLSv1.2',
          max_tls_version: status.tls?.max_tls_version || 'TLSv1.3',
          cipher_suites: status.tls?.cipher_suites || [
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256',
            'TLS_AES_128_GCM_SHA256',
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-RSA-CHACHA20-POLY1305',
            'ECDHE-RSA-AES128-GCM-SHA256'
          ],
          alpn_protocols: status.tls?.alpn_protocols || ['h2', 'http/1.1'],
        },
        pki: {
          ca_cert_path: status.pki?.ca_cert_path || 'certs/root-ca.crt',
          ca_key_path: status.pki?.ca_key_path || 'certs/root-ca.key',
          use_intermediate_ca: status.pki?.use_intermediate_ca !== false,
          intermediate_ca_cert: status.pki?.intermediate_ca_cert || 'certs/intermediate-ca.crt',
          intermediate_ca_key: status.pki?.intermediate_ca_key || 'certs/intermediate-ca.key',
          cert_validity_days: status.pki?.cert_validity_days ?? 365,
          cert_key_size: status.pki?.cert_key_size ?? 4096,
          cert_cache_size: status.pki?.cert_cache_size ?? 10000,
          cert_cache_dir: status.pki?.cert_cache_dir || 'certs/cache',
        },
        security: {
          strict_cert_validation: status.security?.strict_cert_validation !== false,
          block_expired_certs: status.security?.block_expired_certs !== false,
          block_legacy_tls: status.security?.block_legacy_tls !== false,
        },
        logging: {
          log_decisions: status.logging?.log_decisions !== false,
          log_sni: status.logging?.log_sni !== false,
          level: status.logging?.level || 'INFO',
        }
      });
    }
  }, [status]);

  if (!form) {
    return (
      <div className="ssl-panel" style={{ padding: 48, textAlign: 'center', color: 'var(--text-secondary)' }}>
        <RefreshCw size={24} className="ssl-spin" style={{ color: '#00c8ff', margin: '0 auto 8px', display: 'block' }} />
        جاري تحميل إعدادات محرك فحص التشفير SSL/TLS...
      </div>
    );
  }

  const setVal = (k, val) => {
    setForm((f) => ({ ...f, [k]: val }));
  };

  const setNestedVal = (section, k, val) => {
    setForm((f) => ({
      ...f,
      [section]: {
        ...f[section],
        [k]: val,
      },
    }));
  };

  const handleAddDomain = (e) => {
    e.preventDefault();
    if (!newDomainInput.trim()) return;
    const d = newDomainInput.trim();
    if (!form.bypass_domains.includes(d)) {
      setForm((f) => ({ ...f, bypass_domains: [...f.bypass_domains, d] }));
    }
    setNewDomainInput('');
  };

  const handleRemoveDomain = (domainToRemove) => {
    setForm((f) => ({
      ...f,
      bypass_domains: f.bypass_domains.filter((d) => d !== domainToRemove),
    }));
  };

  const handleApplyPreset = (presetKey) => {
    const preset = PRESETS[presetKey];
    if (!preset) return;
    const current = new Set(form.bypass_domains);
    preset.domains.forEach((d) => current.add(d));
    setForm((f) => ({ ...f, bypass_domains: Array.from(current) }));
  };

  const handleSave = (e) => {
    e.preventDefault();
    setSaveMsg(null);
    updateConfig.mutate(form, {
      onSuccess: () => {
        setSaveMsg({ type: 'success', text: 'تم حفظ وتطبيق إعدادات محرك SSL/TLS بنجاح!' });
        setTimeout(() => setSaveMsg(null), 4000);
      },
      onError: (ex) => {
        setSaveMsg({ type: 'error', text: 'فشل في حفظ الإعدادات: ' + (ex.response?.data?.detail || ex.message) });
      },
    });
  };

  const categorizeDomain = (d) => {
    if (d.includes('bank') || d.includes('sama') || d.includes('alahli') || d.includes('rajhi') || d.includes('inma')) return 'financial';
    if (d.includes('gov') || d.includes('absher') || d.includes('nafath') || d.includes('iam')) return 'gov';
    if (d.includes('apple') || d.includes('microsoft') || d.includes('google') || d.includes('digicert')) return 'pinned';
    return 'custom';
  };

  const filteredDomains = form.bypass_domains.filter((d) => {
    if (activeFilter === 'ALL') return true;
    return categorizeDomain(d) === activeFilter;
  });

  return (
    <form onSubmit={handleSave} style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* ── Notification Message ── */}
      {saveMsg && (
        <div
          style={{
            padding: '12px 18px',
            borderRadius: '10px',
            fontSize: '0.82rem',
            fontWeight: 700,
            background: saveMsg.type === 'success' ? 'rgba(0, 230, 118, 0.12)' : 'rgba(255, 77, 106, 0.12)',
            border: `1px solid ${saveMsg.type === 'success' ? 'rgba(0, 230, 118, 0.3)' : 'rgba(255, 77, 106, 0.3)'}`,
            color: saveMsg.type === 'success' ? '#00e676' : '#ff4d6a',
            display: 'flex',
            alignItems: 'center',
            gap: 8,
          }}
        >
          <CheckCircle2 size={16} />
          <span>{saveMsg.text}</span>
        </div>
      )}

      {/* ── 1. Bypass Domains Interactive Tag Cloud ── */}
      <div
        className="ssl-panel"
        style={{
          background: 'rgba(10, 14, 26, 0.75)',
          backdropFilter: 'blur(16px)',
          border: '1px solid rgba(0, 200, 255, 0.15)',
          borderRadius: 'var(--radius-lg)',
          padding: '22px',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14, flexWrap: 'wrap', gap: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div
              style={{
                width: 36,
                height: 36,
                borderRadius: 10,
                background: 'rgba(0, 230, 118, 0.12)',
                color: '#00e676',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <Globe size={18} />
            </div>
            <div>
              <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 800, color: 'var(--text-primary)' }}>
                سحابة استثناءات النطاقات (SSL Bypass Domains Cloud)
              </h3>
              <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
                النطاقات المعفاة من فك التشفير لحماية الخصوصية وتفادي كسر Certificate Pinning
              </span>
            </div>
          </div>

          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {Object.entries(PRESETS).map(([key, preset]) => {
              const Icon = preset.icon;
              return (
                <button
                  key={key}
                  type="button"
                  className="ssl-preset-btn"
                  onClick={() => handleApplyPreset(key)}
                  title={`إضافة نطاقات ${preset.label}`}
                >
                  <Icon size={12} style={{ color: '#00c8ff' }} />
                  + {preset.label.split(' ')[0]} {preset.label.split(' ')[1]}
                </button>
              );
            })}
          </div>
        </div>

        {/* Input for adding new domain tag */}
        <div style={{ display: 'flex', gap: 10, marginBottom: 14 }}>
          <input
            className="bl-input"
            style={{ flex: 1, direction: 'ltr', textAlign: 'left' }}
            placeholder="أدخل نطاقاً جديداً (مثال: *.mybank.com أو login.gov.sa)..."
            value={newDomainInput}
            onChange={(e) => setNewDomainInput(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); handleAddDomain(e); } }}
          />
          <button
            type="button"
            className="ssl-btn ssl-btn--primary"
            onClick={handleAddDomain}
            style={{ padding: '8px 16px', fontSize: '0.78rem' }}
          >
            <Plus size={14} /> إضافة وسام
          </button>
        </div>

        {/* Tag Filters */}
        <div style={{ display: 'flex', gap: 6, marginBottom: 10, flexWrap: 'wrap' }}>
          {[
            { id: 'ALL', label: `الكل (${form.bypass_domains.length})` },
            { id: 'financial', label: 'القطاع البنكي' },
            { id: 'gov', label: 'الجهات الحكومية' },
            { id: 'pinned', label: 'تحديثات السحابة' },
            { id: 'custom', label: 'مخصص' },
          ].map((f) => (
            <button
              key={f.id}
              type="button"
              onClick={() => setActiveFilter(f.id)}
              style={{
                fontSize: '0.72rem',
                padding: '3px 10px',
                borderRadius: '6px',
                border: '1px solid',
                cursor: 'pointer',
                background: activeFilter === f.id ? 'rgba(0, 200, 255, 0.15)' : 'transparent',
                borderColor: activeFilter === f.id ? 'rgba(0, 200, 255, 0.35)' : 'rgba(255, 255, 255, 0.08)',
                color: activeFilter === f.id ? '#00c8ff' : 'var(--text-secondary)',
                fontWeight: 700,
              }}
            >
              {f.label}
            </button>
          ))}
        </div>

        {/* Dynamic Tag Cloud */}
        <div className="ssl-tag-cloud">
          {filteredDomains.length === 0 ? (
            <div style={{ padding: '24px 0', width: '100%', textAlign: 'center', color: 'var(--text-secondary)', fontSize: '0.78rem' }}>
              لا توجد نطاقات مضافة تحت هذا التصنيف.
            </div>
          ) : (
            filteredDomains.map((domain) => {
              const cat = categorizeDomain(domain);
              return (
                <span key={domain} className={`ssl-domain-tag ${cat}`} dir="ltr">
                  <span>{domain}</span>
                  <button
                    type="button"
                    className="ssl-tag-remove"
                    onClick={() => handleRemoveDomain(domain)}
                    title="إزالة النطاق"
                  >
                    <X size={12} />
                  </button>
                </span>
              );
            })
          )}
        </div>
      </div>

      {/* ── 2. Cipher Suites Matrix & TLS 1.3 ── */}
      <div
        className="ssl-panel"
        style={{
          background: 'rgba(10, 14, 26, 0.75)',
          backdropFilter: 'blur(16px)',
          border: '1px solid rgba(0, 200, 255, 0.15)',
          borderRadius: 'var(--radius-lg)',
          padding: '22px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
          <div
            style={{
              width: 36,
              height: 36,
              borderRadius: 10,
              background: 'rgba(129, 140, 248, 0.12)',
              color: '#818cf8',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <Lock size={18} />
          </div>
          <div>
            <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 800, color: 'var(--text-primary)' }}>
              مصفوفة خوارزميات التشفير المعتمدة (Cipher Suites & TLS Matrix)
            </h3>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
              حماية ضد ثغرات التراجع التشفيري (Downgrade Attacks) وفرض معايير TLSv1.3 و Perfect Forward Secrecy
            </span>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 12, marginBottom: 16 }}>
          <div style={{ padding: '12px 14px', background: 'rgba(255, 255, 255, 0.02)', borderRadius: 10, border: '1px solid rgba(255, 255, 255, 0.06)' }}>
            <div style={{ fontSize: '0.74rem', color: 'var(--text-secondary)', marginBottom: 4 }}>الحد الأدنى لبروتوكول TLS</div>
            <select
              className="bl-input"
              value={form.tls.min_tls_version}
              onChange={(e) => setNestedVal('tls', 'min_tls_version', e.target.value)}
              style={{ fontSize: '0.8rem' }}
            >
              <option value="TLSv1.2">TLS 1.2 (موصى به كحد أدنى)</option>
              <option value="TLSv1.3">TLS 1.3 (أقصى معايير الأمان)</option>
            </select>
          </div>

          <div style={{ padding: '12px 14px', background: 'rgba(255, 255, 255, 0.02)', borderRadius: 10, border: '1px solid rgba(255, 255, 255, 0.06)' }}>
            <div style={{ fontSize: '0.74rem', color: 'var(--text-secondary)', marginBottom: 4 }}>حظر إصدارات TLS القديمة (Legacy TLS)</div>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 8, cursor: 'pointer', fontSize: '0.8rem', color: '#00e676', fontWeight: 700 }}>
              <input
                type="checkbox"
                checked={form.security.block_legacy_tls}
                onChange={(e) => setNestedVal('security', 'block_legacy_tls', e.target.checked)}
              />
              إسقاط اتصالات SSLv3 / TLS 1.0 / 1.1 تلقائياً
            </label>
          </div>
        </div>

        {/* Cipher Suites Grid */}
        <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: 8 }}>
          الخوارزميات النشطة في مصافحة TLS (Cipher Suites Active):
        </div>
        <div className="ssl-cipher-grid">
          {form.tls.cipher_suites.map((cipher) => (
            <div key={cipher} className="ssl-cipher-card">
              <span className="ssl-cipher-name">{cipher}</span>
              <span className="ssl-cipher-grade">Grade A+</span>
            </div>
          ))}
        </div>
      </div>

      {/* ── 3. Action Save Button ── */}
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
        <button
          type="submit"
          className="ssl-btn ssl-btn--primary"
          disabled={updateConfig.isPending}
          style={{ padding: '10px 24px', fontSize: '0.85rem', fontWeight: 800 }}
        >
          <Save size={15} />
          {updateConfig.isPending ? 'جاري حفظ الإعدادات...' : 'حفظ وتطبيق إعدادات SSL/TLS'}
        </button>
      </div>
    </form>
  );
}
