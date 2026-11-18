import React, { useState } from 'react';
import { Settings, Zap, Network, RefreshCw } from 'lucide-react';
import { SectionCard } from '../../../components/Shared';
import Toggle from './Toggle';

const ENGINES = [
  { key: 'enable_dga_detection', label: 'كشف الخوارزميات التوليدية (DGA)', icon: '🎲' },
  { key: 'enable_tunneling_detection', label: 'اكتشاف أنفاق DNS (Tunneling)', icon: '🚇' },
  { key: 'enable_threat_intel', label: 'استخبارات التهديدات', icon: '🔍' },
  { key: 'enable_rate_limiting', label: 'تحديد معدل الطلبات', icon: '⏱️' },
  { key: 'enable_tld_blocking', label: 'حظر النطاقات العليا المشبوهة', icon: '🚫' },
  { key: 'enable_dart_detection', label: 'محرك DART الثلاثي', icon: '🔺' },
];

export function DNSSettingsView({ config, updateConfig, syncThreatIntel }) {
  const [toast, setToast] = useState(null);

  const showToast = (message, type = 'success') => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 4000);
  };

  const mutate = (key, val) => {
    updateConfig.mutate({ ...config, [key]: val }, {
      onSuccess: () => showToast('تم تحديث الإعدادات بنجاح!', 'success'),
      onError: (err) => showToast(`فشل تحديث الإعدادات: ${err.message || 'خطأ غير معروف'}`, 'error')
    });
  };

  const handleSyncIntel = () => {
    syncThreatIntel.mutate(undefined, {
      onSuccess: () => showToast('تم بدء مزامنة قاعدة البيانات الذكية للتهديدات بنجاح.', 'success'),
      onError: (err) => showToast(`فشلت المزامنة: ${err.message || err.detail || err}`, 'error')
    });
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
      {toast && (
        <div className={`dns-toast dns-toast-${toast.type}`}>
          {toast.message}
        </div>
      )}

      <SectionCard title="حالة الوحدة" icon={Settings}>
        <div className="dns-config-row">
          <div>
            <div style={{ fontWeight: 700 }}>محرك أمان DNS — المفتاح الرئيسي</div>
            <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>تفعيل أو إيقاف خط أنابيب التفتيش بالكامل.</div>
          </div>
          <Toggle checked={config.is_active} onChange={() => mutate('is_active', !config.is_active)} />
        </div>
      </SectionCard>

      <SectionCard title="محركات الكشف" icon={Zap}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          {ENGINES.map(({ key, label, icon }) => (
            <div key={key} className={`dns-config-row ${config[key] ? 'active' : ''}`}>
              <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                <span style={{ fontSize: '1.2rem' }}>{icon}</span>
                <span style={{ fontWeight: 600 }}>{label}</span>
              </div>
              <Toggle checked={config[key]} onChange={() => mutate(key, !config[key])} />
            </div>
          ))}
        </div>
      </SectionCard>

      <SectionCard title="معلمات المحرك" icon={Settings}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          {[
            { key: 'dga_entropy_threshold', label: 'عتبة إنتروبيا DGA', step: 0.1 },
            { key: 'tunneling_query_threshold', label: 'عتبة استعلامات الأنفاق', step: 5 },
            { key: 'rate_limit_per_minute', label: 'الحد الأقصى (استعلام / دقيقة)', step: 10 },
          ].map(({ key, label, step }) => (
            <div key={key} className="dns-config-row">
              <span style={{ fontWeight: 600 }}>{label}</span>
              <input
                className="dns-input mono" style={{ width: 100, textAlign: 'center' }}
                defaultValue={config[key]}
                onBlur={e => mutate(key, step < 1 ? parseFloat(e.target.value) : parseInt(e.target.value))}
              />
            </div>
          ))}

          <div className="dns-config-row" style={{ flexDirection: 'column', alignItems: 'stretch', gap: 8 }}>
            <div style={{ fontWeight: 600 }}>النطاقات العليا (TLDs) المشبوهة</div>
            <input
              className="dns-input mono" dir="ltr"
              defaultValue={config.suspicious_tlds}
              onBlur={e => mutate('suspicious_tlds', e.target.value)}
            />
          </div>
          <div className="dns-config-row">
            <span style={{ fontWeight: 600 }}>عنوان Sinkhole IP</span>
            <input
              className="dns-input mono" dir="ltr" style={{ width: 180, textAlign: 'center' }}
              defaultValue={config.sinkhole_ip}
              placeholder="10.0.0.1"
              onBlur={e => mutate('sinkhole_ip', e.target.value.trim())}
            />
          </div>
        </div>
      </SectionCard>

      <SectionCard title="بروتوكولات التشفير والفحص العميق (DNSSEC & DoH/DoT)" icon={Zap}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          <div className="dns-config-row">
            <div>
              <div style={{ fontWeight: 700 }}>التحقق من تواقيع DNSSEC</div>
              <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>التحقق التشفيري من صحة إجابات النطاقات وكشف التزوير والتسمم (Cache Poisoning)</div>
            </div>
            <Toggle
              checked={config.dnssec_validation ?? true}
              onChange={() => mutate('dnssec_validation', !config.dnssec_validation)}
            />
          </div>

          <div className="dns-config-row">
            <div>
              <div style={{ fontWeight: 700 }}>تفتيش حركة DNS over HTTPS (DoH)</div>
              <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>فك تشفير وفحص استعلامات DoH الموجهة لخوادم خارجية لمنع الالتفاف</div>
            </div>
            <Toggle
              checked={config.inspect_doh ?? true}
              onChange={() => mutate('inspect_doh', !config.inspect_doh)}
            />
          </div>

          <div className="dns-config-row">
            <div>
              <div style={{ fontWeight: 700 }}>فحص استعلامات DNS over TLS (DoT)</div>
              <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>مراقبة استعلامات المنفذ 853 وكشف الأنفاق المشفرة</div>
            </div>
            <Toggle
              checked={config.inspect_dot ?? true}
              onChange={() => mutate('inspect_dot', !config.inspect_dot)}
            />
          </div>
        </div>
      </SectionCard>

      <SectionCard title="تغذية استخبارات التهديدات (Threat Intel Feed)" icon={Network}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-3)' }}>
          <div className="dns-config-row" style={{ flexDirection: 'column', alignItems: 'stretch', gap: 8 }}>
            <div style={{ fontWeight: 600 }}>رابط ملقم ذكاء التهديدات (Feed URL)</div>
            <input
              className="dns-input mono" dir="ltr"
              defaultValue={config.feed_url}
              placeholder="https://example.com/feed.txt"
              onBlur={e => mutate('feed_url', e.target.value.trim())}
            />
          </div>
          <div className="dns-config-row">
            <span style={{ fontWeight: 600 }}>دورة التحديث التلقائي (بالساعات)</span>
            <input
              className="dns-input mono" style={{ width: 100, textAlign: 'center' }}
              defaultValue={config.refresh_interval_hours}
              onBlur={e => mutate('refresh_interval_hours', parseInt(e.target.value) || 24)}
            />
          </div>
          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 8 }}>
            <button
              className="dns-btn-primary" style={{ display: 'flex', alignItems: 'center', gap: 8 }}
              onClick={handleSyncIntel}
              disabled={syncThreatIntel.isPending}
            >
              <RefreshCw size={14} className={syncThreatIntel.isPending ? 'spin' : ''} /> تحديث قاعدة التهديدات الآن
            </button>
          </div>
        </div>
      </SectionCard>
    </div>
  );
}

export default DNSSettingsView;
