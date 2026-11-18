import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { systemApi } from '../../services/api';
import {
  ShieldAlert, Globe, Trash2, Plus, Server, Zap, Network, RefreshCw,
  Lock, CheckCircle2, ChevronDown, ChevronUp, AlertCircle
} from 'lucide-react';
import './Settings.css';

export default function StealthSettings() {
  const qc = useQueryClient();

  // Collapsible add form states
  const [showAddVip, setShowAddVip] = useState(false);
  const [showAddDns, setShowAddDns] = useState(false);

  const [newVip, setNewVip] = useState({
    name: '',
    external_ip: '',
    external_port: '',
    internal_ip: '',
    internal_port: '',
    use_tls_upstream: false,
  });

  const [newDnsRule, setNewDnsRule] = useState({
    name: '',
    domain_pattern: '',
    redirect_ip: '',
    source_ips: '',
  });

  const { data: config, isLoading } = useQuery({
    queryKey: ['config', 'base.yaml'],
    queryFn: async () => {
      const res = await systemApi.config('base.yaml');
      return res.data;
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ category, key, value }) =>
      systemApi.updateConfig({ category, key, value }, 'base.yaml'),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['config'] }),
  });

  if (isLoading) {
    return (
      <div className="s-loading">
        <RefreshCw className="spin text-cyan-400" size={20} />
        <span>جاري تحميل إعدادات التخفي والـ VIP...</span>
      </div>
    );
  }

  const proxyConfig = config?.proxy || {};
  const dnsConfig = config?.modules?.dns_security || {};
  const vips = proxyConfig.vips || [];
  const hardening = proxyConfig.hardening || {};
  const dnsRules = dnsConfig.steering?.rules || [];

  const handleHardeningChange = (key, value) => {
    updateMutation.mutate({
      category: 'proxy',
      key: 'hardening',
      value: { ...hardening, [key]: value },
    });
  };

  const handleAddVip = (e) => {
    e.preventDefault();
    if (!newVip.name || !newVip.external_ip) return;
    const itemToAdd = {
      ...newVip,
      external_port: parseInt(newVip.external_port) || 80,
      internal_port: parseInt(newVip.internal_port) || 80,
    };
    updateMutation.mutate({
      category: 'proxy',
      key: 'vips',
      value: [...vips, itemToAdd],
    });
    setNewVip({
      name: '',
      external_ip: '',
      external_port: '',
      internal_ip: '',
      internal_port: '',
      use_tls_upstream: false,
    });
    setShowAddVip(false);
  };

  const handleDeleteVip = (index) => {
    updateMutation.mutate({
      category: 'proxy',
      key: 'vips',
      value: vips.filter((_, i) => i !== index),
    });
  };

  const handleAddDnsRule = (e) => {
    e.preventDefault();
    if (!newDnsRule.domain_pattern || !newDnsRule.redirect_ip) return;
    const ruleToSave = {
      ...newDnsRule,
      source_ips: newDnsRule.source_ips
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean),
    };
    const updatedDnsSecurity = {
      ...dnsConfig,
      steering: {
        ...(dnsConfig.steering || {}),
        enabled: true,
        rules: [...dnsRules, ruleToSave],
      },
    };
    updateMutation.mutate({
      category: 'modules',
      key: 'dns_security',
      value: updatedDnsSecurity,
    });
    setNewDnsRule({ name: '', domain_pattern: '', redirect_ip: '', source_ips: '' });
    setShowAddDns(false);
  };

  const handleDeleteDnsRule = (index) => {
    const updatedDnsSecurity = {
      ...dnsConfig,
      steering: {
        ...(dnsConfig.steering || {}),
        rules: dnsRules.filter((_, i) => i !== index),
      },
    };
    updateMutation.mutate({
      category: 'modules',
      key: 'dns_security',
      value: updatedDnsSecurity,
    });
  };

  return (
    <div className="stealth-settings" dir="rtl">
      {/* ══════════════════════════════════════════════════════
          القسم 1: إخفاء الهوية وتصليب الخادم
         ══════════════════════════════════════════════════════ */}
      <section className="s-card" style={{ marginBottom: 20 }}>
        <div className="s-card-header">
          <div className="s-card-icon danger">
            <ShieldAlert size={18} />
          </div>
          <div>
            <h3 className="s-card-title">إخفاء الهوية وتصليب الخادم (Stealth & Cloaking)</h3>
            <p className="s-card-subtitle">تمويه استجابات الخادم وإخفاء معلومات بصمة النظام الحقيقية</p>
          </div>
          <span className="s-badge s-badge-danger" style={{ marginRight: 'auto' }}>
            Stealth Active
          </span>
        </div>

        <div className="s-card-body">
          <div className="s-setting-row">
            <div className="s-setting-info">
              <div className="s-setting-key">تفعيل التمويه السيبراني (Server Cloaking)</div>
              <div className="s-setting-desc">
                إخفاء ترويسات الخادم الحقيقية واستبدالها بهوية مخصصة لمنع استطلاع المهاجمين.
              </div>
            </div>
            <div className="s-setting-ctrl">
              <label className="s-toggle">
                <input
                  type="checkbox"
                  checked={hardening.cloaking_enabled || false}
                  onChange={(e) => handleHardeningChange('cloaking_enabled', e.target.checked)}
                />
                <span className="s-toggle-track">
                  <span className="s-toggle-thumb" />
                </span>
              </label>
            </div>
          </div>

          <div className="s-setting-row">
            <div className="s-setting-info">
              <div className="s-setting-key">بانر الخادم المخصص (Server Banner String)</div>
              <div className="s-setting-desc">
                قيمة الترويسة المزيفة <code>Server: ...</code> التي ستظهر في نتائج فحص المنافذ.
              </div>
            </div>
            <div className="s-setting-ctrl" style={{ width: '280px' }}>
              <input
                type="text"
                className="s-input s-input-mono"
                value={hardening.server_banner || ''}
                onChange={(e) => handleHardeningChange('server_banner', e.target.value)}
                placeholder="e.g. bunyanx-NGFW/2.x"
              />
            </div>
          </div>
        </div>
      </section>

      {/* ══════════════════════════════════════════════════════
          القسم 2: خرائط IP الافتراضية (VIP)
         ══════════════════════════════════════════════════════ */}
      <section className="s-card" style={{ marginBottom: 20 }}>
        <div className="s-card-header">
          <div className="s-card-icon primary">
            <Server size={18} />
          </div>
          <div>
            <h3 className="s-card-title">خرائط العناوين الافتراضية (Virtual IP - VIP)</h3>
            <p className="s-card-subtitle">توجيه الحزم الخارجية على الجدار الناري إلى الخوادم الداخلية بشفافية</p>
          </div>
          <div style={{ marginRight: 'auto', display: 'flex', alignItems: 'center', gap: 10 }}>
            <span className="s-badge s-badge-primary">{vips.length} قاعدة نشطة</span>
            <button
              className="s-btn s-btn-primary s-btn-sm"
              onClick={() => setShowAddVip(!showAddVip)}
            >
              <Plus size={14} />
              {showAddVip ? 'إغلاق النموذج' : 'إضافة VIP جديد'}
            </button>
          </div>
        </div>

        {/* نموذج إضافة VIP بتصميم بطاقة عصرية */}
        {showAddVip && (
          <form className="s-form-card" onSubmit={handleAddVip}>
            <div className="s-form-title">
              <Plus size={15} /> إضافة قاعدة توجيه VIP جديدة
            </div>
            <div className="s-form-grid">
              <div className="s-form-field">
                <label className="s-form-label">اسم الخدمة</label>
                <input
                  type="text"
                  className="s-input"
                  placeholder="مثال: Web Portal VIP"
                  value={newVip.name}
                  onChange={(e) => setNewVip({ ...newVip, name: e.target.value })}
                  required
                />
              </div>

              <div className="s-form-field">
                <label className="s-form-label">العنوان الخارجي (Listening IP)</label>
                <input
                  type="text"
                  className="s-input s-input-mono"
                  placeholder="0.0.0.0 أو IP العام"
                  value={newVip.external_ip}
                  onChange={(e) => setNewVip({ ...newVip, external_ip: e.target.value })}
                  required
                />
              </div>

              <div className="s-form-field">
                <label className="s-form-label">المنفذ الخارجي (Port)</label>
                <input
                  type="number"
                  className="s-input s-input-mono"
                  placeholder="443"
                  value={newVip.external_port}
                  onChange={(e) => setNewVip({ ...newVip, external_port: e.target.value })}
                  required
                />
              </div>

              <div className="s-form-field">
                <label className="s-form-label">العنوان الداخلي (Forward IP)</label>
                <input
                  type="text"
                  className="s-input s-input-mono"
                  placeholder="192.168.10.50"
                  value={newVip.internal_ip}
                  onChange={(e) => setNewVip({ ...newVip, internal_ip: e.target.value })}
                  required
                />
              </div>

              <div className="s-form-field">
                <label className="s-form-label">المنفذ الداخلي (Internal Port)</label>
                <input
                  type="number"
                  className="s-input s-input-mono"
                  placeholder="8080"
                  value={newVip.internal_port}
                  onChange={(e) => setNewVip({ ...newVip, internal_port: e.target.value })}
                  required
                />
              </div>

              <div className="s-form-field" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
                <label className="s-form-label">تشفير TLS Upstream</label>
                <label className="s-toggle" style={{ marginTop: 4 }}>
                  <input
                    type="checkbox"
                    checked={newVip.use_tls_upstream}
                    onChange={(e) => setNewVip({ ...newVip, use_tls_upstream: e.target.checked })}
                  />
                  <span className="s-toggle-track">
                    <span className="s-toggle-thumb" />
                  </span>
                </label>
              </div>
            </div>

            <div className="s-form-actions">
              <button type="submit" className="s-btn s-btn-primary">
                <CheckCircle2 size={14} /> حفظ وإضافة VIP
              </button>
              <button
                type="button"
                className="s-btn s-btn-ghost"
                onClick={() => setShowAddVip(false)}
              >
                إلغاء
              </button>
            </div>
          </form>
        )}

        <div className="s-card-body" style={{ padding: 0 }}>
          <table className="s-table">
            <thead>
              <tr>
                <th>اسم الخدمة</th>
                <th>الاستماع الخارجي (Listening)</th>
                <th>التوجيه الداخلي (Forwarding)</th>
                <th>تشفير TLS</th>
                <th style={{ textAlign: 'left' }}>إجراء</th>
              </tr>
            </thead>
            <tbody>
              {vips.length === 0 ? (
                <tr>
                  <td colSpan="5" style={{ textAlign: 'center', padding: '36px', color: 'var(--text-muted)' }}>
                    لا توجد قواعد VIP مسجلة حالياً
                  </td>
                </tr>
              ) : (
                vips.map((vip, i) => (
                  <tr key={i}>
                    <td style={{ fontWeight: 700, color: 'var(--text-primary)' }}>{vip.name}</td>
                    <td>
                      <code className="s-code-badge">
                        {vip.external_ip}:{vip.external_port}
                      </code>
                    </td>
                    <td>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
                        <Zap size={13} style={{ color: '#ffab40' }} />
                        <code className="s-code-badge forward">
                          {vip.internal_ip}:{vip.internal_port}
                        </code>
                      </span>
                    </td>
                    <td>
                      <span className={`s-badge ${vip.use_tls_upstream ? 's-badge-success' : 's-badge-mono'}`}>
                        {vip.use_tls_upstream ? 'HTTPS/TLS' : 'HTTP/Plain'}
                      </span>
                    </td>
                    <td style={{ textAlign: 'left' }}>
                      <button
                        className="s-btn-icon danger"
                        title="حذف القاعدة"
                        onClick={() => handleDeleteVip(i)}
                      >
                        <Trash2 size={15} />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* ══════════════════════════════════════════════════════
          القسم 3: توجيه DNS الداخلي (Split-Horizon DNS Steering)
         ══════════════════════════════════════════════════════ */}
      <section className="s-card">
        <div className="s-card-header">
          <div className="s-card-icon accent">
            <Globe size={18} />
          </div>
          <div>
            <h3 className="s-card-title">توجيه DNS الداخلي (Split-Horizon DNS Steering)</h3>
            <p className="s-card-subtitle">اعتراض وإعادة توجيه استعلامات DNS لنطاقات محددة نحو خوادم مخصصة</p>
          </div>
          <div style={{ marginRight: 'auto', display: 'flex', alignItems: 'center', gap: 10 }}>
            <span className="s-badge s-badge-accent">{dnsRules.length} قواعد</span>
            <button
              className="s-btn s-btn-primary s-btn-sm"
              onClick={() => setShowAddDns(!showAddDns)}
            >
              <Plus size={14} />
              {showAddDns ? 'إغلاق النموذج' : 'إضافة قاعدة DNS'}
            </button>
          </div>
        </div>

        {/* نموذج إضافة قاعدة DNS */}
        {showAddDns && (
          <form className="s-form-card" onSubmit={handleAddDnsRule}>
            <div className="s-form-title">
              <Plus size={15} /> إضافة قاعدة توجيه DNS Steering جديدة
            </div>
            <div className="s-form-grid">
              <div className="s-form-field">
                <label className="s-form-label">نمط النطاق (Domain Pattern)</label>
                <input
                  type="text"
                  className="s-input s-input-mono"
                  placeholder="مثال: *.corp.local أو portal.internal"
                  value={newDnsRule.domain_pattern}
                  onChange={(e) => setNewDnsRule({ ...newDnsRule, domain_pattern: e.target.value })}
                  required
                />
              </div>

              <div className="s-form-field">
                <label className="s-form-label">عنوان IP الوجهة (Redirect IP)</label>
                <input
                  type="text"
                  className="s-input s-input-mono"
                  placeholder="192.168.1.100"
                  value={newDnsRule.redirect_ip}
                  onChange={(e) => setNewDnsRule({ ...newDnsRule, redirect_ip: e.target.value })}
                  required
                />
              </div>

              <div className="s-form-field">
                <label className="s-form-label">نطاقات المصدر المحددة (CIDRs مفصولة بفاصلة)</label>
                <input
                  type="text"
                  className="s-input s-input-mono"
                  placeholder="10.0.0.0/24 (اتركه فارغاً للتطبيق على الجميع)"
                  value={newDnsRule.source_ips}
                  onChange={(e) => setNewDnsRule({ ...newDnsRule, source_ips: e.target.value })}
                />
              </div>
            </div>

            <div className="s-form-actions">
              <button type="submit" className="s-btn s-btn-primary">
                <CheckCircle2 size={14} /> حفظ وإضافة قاعدة DNS
              </button>
              <button
                type="button"
                className="s-btn s-btn-ghost"
                onClick={() => setShowAddDns(false)}
              >
                إلغاء
              </button>
            </div>
          </form>
        )}

        <div className="s-card-body" style={{ padding: 0 }}>
          <table className="s-table">
            <thead>
              <tr>
                <th>نمط النطاق (Domain Pattern)</th>
                <th>عنوان الاستجابة الموجه (Redirect IP)</th>
                <th>نطاقات المصدر (Source CIDRs)</th>
                <th style={{ textAlign: 'left' }}>إجراء</th>
              </tr>
            </thead>
            <tbody>
              {dnsRules.length === 0 ? (
                <tr>
                  <td colSpan="4" style={{ textAlign: 'center', padding: '36px', color: 'var(--text-muted)' }}>
                    لا توجد قواعد DNS Steering مسجلة حالياً
                  </td>
                </tr>
              ) : (
                dnsRules.map((rule, i) => (
                  <tr key={i}>
                    <td>
                      <code className="s-code-badge domain">{rule.domain_pattern}</code>
                    </td>
                    <td>
                      <code className="s-code-badge forward">{rule.redirect_ip}</code>
                    </td>
                    <td>
                      {rule.source_ips?.length > 0 ? (
                        rule.source_ips.map((s) => (
                          <span key={s} className="s-badge s-badge-mono" style={{ margin: '2px' }}>
                            {s}
                          </span>
                        ))
                      ) : (
                        <span className="s-badge s-badge-success">تطبيق شامل (Global)</span>
                      )}
                    </td>
                    <td style={{ textAlign: 'left' }}>
                      <button
                        className="s-btn-icon danger"
                        title="حذف القاعدة"
                        onClick={() => handleDeleteDnsRule(i)}
                      >
                        <Trash2 size={15} />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* إشعار الحفظ */}
      {updateMutation.isPending && (
        <div className="s-toast">
          <RefreshCw size={15} className="spin" />
          جاري تطبيق التحديثات على محرك التوجيه...
        </div>
      )}
    </div>
  );
}
