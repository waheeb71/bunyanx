import React from 'react';
import { ShieldAlert, Cpu, Code, Layers, Target, Lock, Server, Zap, Eye, Activity, ShieldCheck } from 'lucide-react';
import { SectionCard } from '../../../components/Shared';
import { FeatureToggleRow, Toggle } from './Toggle';

export function WaapShieldsPanel({ status, handleToggle, handleGnnToggle }) {
  const f = status?.features || {};

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
      <SectionCard title="حماية API بمبدأ الثقة الصفرية" icon={ShieldAlert}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <FeatureToggleRow icon={Code} label="التحقق من مخطط API" desc="التحقق من حمولات JSON/XML مقابل مخططات OpenAPI" enabled={f.waap_api_schema} onChange={v => handleToggle('waap_api_schema', v)} color="var(--accent)" />
          <FeatureToggleRow icon={Layers} label="فاحص GraphQL العميق" desc="يمنع هجمات DoS عبر تجميع الاستعلامات وكسر GraphQL" enabled={f.waap_graphql} onChange={v => handleToggle('waap_graphql', v)} color="#a78bfa" />
          <FeatureToggleRow icon={Target} label="البصمة المتقدمة JA3/JA4" desc="يدمج بصمات TLS لكشف تزوير البوتات" enabled={f.waap_fingerprint} onChange={v => handleToggle('waap_fingerprint', v)} color="var(--accent)" />
          <FeatureToggleRow icon={Lock} label="الاستيلاء على الحسابات" desc="يتتبع حشو بيانات الاعتماد الشاذ والقوة الغاشمة الموزعة" enabled={f.waap_ato} onChange={v => handleToggle('waap_ato', v)} color="var(--danger)" />
        </div>
      </SectionCard>

      <SectionCard title="المعالجات العصبية والتسريع" icon={Cpu}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <FeatureToggleRow icon={Server} label="محرك GNN المنطقي" desc="شبكات الرسم البياني لاكتشاف تلاعب المسار التسلسلي" enabled={f.gnn} onChange={v => handleGnnToggle(v)} color="#a78bfa" />
          <FeatureToggleRow icon={Zap} label="تسريع eBPF النووي" desc="تفريغ عناوين IP عالية المخاطر إلى نواة Linux XDP" enabled={f.ebpf_fast_path} onChange={v => handleToggle('ebpf_fast_path', v)} color="var(--warning)" />
          <FeatureToggleRow icon={Eye} label="محرك الخداع (Deception)" desc="يحقن tokens مزيفة لإثبات النية الخبيثة بشكل قاطع" enabled={f.deception_engine} onChange={v => handleToggle('deception_engine', v)} color="var(--success)" />
          <FeatureToggleRow icon={Activity} label="حلقة التعلم التلقائي" desc="تجمع الأحداث الشاذة لإعادة التدريب في ساعات غير الذروة" enabled={f.self_learning} onChange={v => handleToggle('self_learning', v)} color="var(--accent)" />
        </div>
      </SectionCard>

      <div className="waf-xai-banner">
        <div className="waf-xai-icon">
          <ShieldCheck size={28} style={{ color: f.xai_explainer ? 'var(--accent)' : 'var(--text-muted)' }} />
        </div>
        <div className="waf-xai-body">
          <div className="waf-xai-title">نسب الذكاء القابل للتفسير (XAI Explainer)</div>
          <div className="waf-xai-desc">
            عند التفعيل، يترجم WAF قراراته العصبية إلى نسب مئوية مقروءة — مثل «75% احتمال بوت» — وتُرسل إلى SIEM.
          </div>
        </div>
        <Toggle checked={f.xai_explainer} onChange={val => handleToggle('xai_explainer', val)} color="var(--accent)" />
      </div>
    </div>
  );
}
