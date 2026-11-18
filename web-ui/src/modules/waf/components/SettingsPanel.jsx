import { useState, useEffect } from 'react';
import { 
  Settings, Shield, RefreshCw, Save, Server, Target, 
  Cpu, Activity, Zap, Lock, Database, FileCode, CheckCircle2, AlertTriangle, UploadCloud
} from 'lucide-react';
import { SectionCard } from '../../../components/Shared';
import { FeatureToggleRow } from './Toggle';

export function SettingsPanel({ settings, loading, mutators, onOpenSchemaModal }) {
  const [toastMsg, setToastMsg] = useState(null);

  // Local state for all fields to allow editing before saving
  const [local, setLocal] = useState(settings || {});

  useEffect(() => {
    if (settings) {
      setLocal(settings);
    }
  }, [settings]);

  if (loading && !settings) {
    return <div className="waf-empty" style={{ padding: 40 }}><RefreshCw className="waf-spin" style={{ opacity: 0.5, marginBottom: 12 }} size={24} /> جاري تحميل الإعدادات...</div>;
  }

  if (!settings && !loading) {
    return (
      <div className="waf-empty" style={{ padding: 40, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12 }}>
        <AlertTriangle size={32} style={{ color: 'var(--warning)' }} />
        <span>تعذر تحميل إعدادات WAF من الخادم</span>
        <button className="btn btn-ghost" onClick={() => mutators.reloadSettings?.()} style={{ border: '1px solid var(--border)' }}>
          <RefreshCw size={14} /> إعادة المحاولة
        </button>
      </div>
    );
  }

  const showToast = (text, type = 'success') => {
    setToastMsg({ text, type });
    setTimeout(() => setToastMsg(null), 3000);
  };

  // Handle generic nested state update
  const updateNested = (cat, field, value) => {
    setLocal(prev => ({
      ...prev,
      [cat]: { ...prev[cat], [field]: value }
    }));
  };
  
  // Update AI Model fields specifically since it's deeply nested
  const updateModel = (model, field, value) => {
    setLocal(prev => ({
      ...prev,
      ai_models: {
        ...prev.ai_models,
        [model]: { ...prev.ai_models[model], [field]: value }
      }
    }));
  };

  const updateDefense = (defense, field, value) => {
    setLocal(prev => ({
      ...prev,
      defenses: {
        ...prev.defenses,
        [defense]: { ...prev.defenses[defense], [field]: value }
      }
    }));
  };

  // UI Helpers
  const CardHeader = ({ icon: Icon, title }) => (
    <h3 style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '1.1rem', marginBottom: '16px', color: 'var(--text-main)', borderBottom: '1px solid var(--border)', paddingBottom: '10px' }}>
      <Icon size={18} style={{ color: 'var(--accent)' }} /> {title}
    </h3>
  );

  const InputRow = ({ label, type = "number", value, onChange, min, max, step }) => (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
      <span style={{ fontSize: '0.9rem', color: 'var(--text-muted)' }}>{label}</span>
      <input 
        type={type} 
        value={value ?? ''} 
        onChange={(e) => onChange(type === 'number' ? parseFloat(e.target.value) : e.target.value)} 
        min={min} max={max} step={step}
        style={{ width: '80px', padding: '4px 8px', background: 'var(--bg-overlay)', border: '1px solid var(--border)', borderRadius: '4px', color: 'var(--text-main)', textAlign: 'center' }}
        dir="ltr"
      />
    </div>
  );

  const SelectRow = ({ label, value, options, onChange }) => (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
      <span style={{ fontSize: '0.9rem', color: 'var(--text-muted)' }}>{label}</span>
      <select 
        value={value} 
        onChange={(e) => onChange(e.target.value)}
        style={{ padding: '4px 8px', background: 'var(--bg-overlay)', border: '1px solid var(--border)', borderRadius: '4px', color: 'var(--text-main)' }}
      >
        {options.map(opt => <option key={opt.value} value={opt.value}>{opt.label}</option>)}
      </select>
    </div>
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', padding: '10px 0' }}>
      
      {/* Toast Notification Banner */}
      {toastMsg && (
        <div style={{
          padding: '12px 16px',
          borderRadius: 8,
          background: toastMsg.type === 'success' ? 'rgba(40, 199, 111, 0.15)' : 'rgba(234, 84, 85, 0.15)',
          border: `1px solid ${toastMsg.type === 'success' ? 'var(--success)' : 'var(--danger)'}`,
          color: toastMsg.type === 'success' ? 'var(--success)' : 'var(--danger)',
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          fontSize: '0.9rem'
        }}>
          {toastMsg.type === 'success' ? <CheckCircle2 size={18} /> : <AlertTriangle size={18} />}
          <span>{toastMsg.text}</span>
        </div>
      )}

      {/* ── Top Bar ── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--bg-card)', padding: '16px 20px', borderRadius: '12px', border: '1px solid var(--border)', flexWrap: 'wrap', gap: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <Settings size={20} style={{ color: 'var(--accent)' }} />
          <div>
            <div style={{ fontWeight: 'bold' }}>إعدادات جدار الحماية (WAF & WAAP)</div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>تعديلات متقدمة للمحركات والحدود واستيراد المخططات</div>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          <button
            onClick={() => { mutators.reloadSettings(); showToast('تم إعادة تحميل الإعدادات من waf.yaml'); }}
            style={{ background: 'var(--bg-overlay)', border: '1px solid var(--border)', padding: '6px 12px', borderRadius: '6px', color: 'var(--text-main)', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.85rem' }}
          >
            <RefreshCw size={14} /> إعادة تحميل من YAML
          </button>
          <button
            onClick={onOpenSchemaModal}
            className="btn btn-primary"
            style={{ padding: '6px 12px', fontSize: '0.85rem' }}
          >
            <UploadCloud size={14} /> رفع مخطط OpenAPI
          </button>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '20px' }}>
        
        {/* ── Global Settings ── */}
        <SectionCard>
          <CardHeader icon={Globe} title="الإعدادات العامة (Global)" />
          
          <FeatureToggleRow 
            label="تشغيل WAF" 
            desc="إيقاف/تشغيل المحرك بالكامل" 
            enabled={local.waf_enabled} 
            onChange={(val) => { setLocal({...local, waf_enabled: val}); mutators.setWafMaster(val); showToast(`WAF Master ${val ? 'مُفعّل' : 'معطّل'}`); }} 
            color="#28c76f" 
          />
          <div style={{ margin: '16px 0' }}></div>
          <SelectRow 
            label="وضع التشغيل (Mode)" 
            value={local.mode} 
            options={[
              { value: 'enforce', label: 'تطبيق الحظر (Enforce)' },
              { value: 'monitor', label: 'مراقبة فقط (Monitor)' },
              { value: 'learning', label: 'تعلم آلي (Learning)' }
            ]}
            onChange={(val) => { setLocal({...local, mode: val}); mutators.setWafMode(val); showToast(`تم تغيير وضع التشغيل إلى ${val.toUpperCase()}`); }}
          />
        </SectionCard>

        {/* ── Risk Scoring ── */}
        <SectionCard>
          <CardHeader icon={Target} title="تسجيل المخاطر (Risk Scoring)" />
          
          <InputRow label="حد السماح (Allow)" value={local.risk_scoring?.allow} onChange={v => updateNested('risk_scoring', 'allow', v)} step="0.05" />
          <InputRow label="حد التحدي (Challenge)" value={local.risk_scoring?.challenge} onChange={v => updateNested('risk_scoring', 'challenge', v)} step="0.05" />
          <InputRow label="حد الحظر (Block)" value={local.risk_scoring?.block} onChange={v => updateNested('risk_scoring', 'block', v)} step="0.05" />
          
          <button onClick={() => {
            mutators.updateRiskThresholds({
              allow: local.risk_scoring.allow, challenge: local.risk_scoring.challenge, block: local.risk_scoring.block
            });
            showToast('تم حفظ حدود المخاطر بنجاح!');
          }} style={{ width: '100%', padding: '8px', background: 'var(--accent)', color: '#fff', border: 'none', borderRadius: '6px', cursor: 'pointer', marginTop: 12, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6 }}>
            <Save size={14} /> حفظ حدود المخاطر
          </button>
        </SectionCard>

        {/* ── AI Models Tuning ── */}
        <SectionCard>
          <CardHeader icon={Cpu} title="نماذج الذكاء الاصطناعي" />
          
          <div style={{ marginBottom: 16 }}>
            <div style={{ fontSize: '0.9rem', marginBottom: 8, color: 'var(--accent)' }}>معالجة اللغات الطبيعية (NLP)</div>
            <InputRow label="عتبة الكشف" value={local.ai_models?.nlp?.threshold} onChange={v => updateModel('nlp', 'threshold', v)} step="0.1" />
            <InputRow label="الوزن (Weight)" value={local.ai_models?.nlp?.weight} onChange={v => updateModel('nlp', 'weight', v)} step="0.05" />
            <button onClick={() => { mutators.configModel('nlp', { detection_threshold: local.ai_models.nlp.threshold, weight: local.ai_models.nlp.weight }); showToast('تم حفظ إعدادات NLP'); }} style={{ width: '100%', padding: '6px', fontSize: '0.8rem', background: 'var(--bg-overlay)', border: '1px solid var(--border)', color: 'var(--text-main)', borderRadius: '4px', cursor: 'pointer' }}>حفظ إعدادات NLP</button>
          </div>

          <div style={{ marginBottom: 16, borderTop: '1px dashed var(--border)', paddingTop: 16 }}>
            <div style={{ fontSize: '0.9rem', marginBottom: 8, color: 'var(--accent)' }}>محرك GNN (السلوك والجلسات)</div>
            <InputRow label="عتبة الكشف" value={local.ai_models?.gnn?.threshold} onChange={v => updateModel('gnn', 'threshold', v)} step="0.1" />
            <InputRow label="الوزن (Weight)" value={local.ai_models?.gnn?.weight} onChange={v => updateModel('gnn', 'weight', v)} step="0.05" />
            <InputRow label="نافذة الطلبات" value={local.ai_models?.gnn?.session_window} onChange={v => updateModel('gnn', 'session_window', v)} />
            <button onClick={() => { mutators.configModel('gnn', { detection_threshold: local.ai_models.gnn.threshold, weight: local.ai_models.gnn.weight, session_window_requests: local.ai_models.gnn.session_window }); showToast('تم حفظ إعدادات GNN'); }} style={{ width: '100%', padding: '6px', fontSize: '0.8rem', background: 'var(--bg-overlay)', border: '1px solid var(--border)', color: 'var(--text-main)', borderRadius: '4px', cursor: 'pointer' }}>حفظ إعدادات GNN</button>
          </div>
        </SectionCard>

        {/* ── Defenses & WAAP ── */}
        <SectionCard>
          <CardHeader icon={Shield} title="دفاعات WAAP" />
          
          <div style={{ marginBottom: 16 }}>
            <div style={{ fontSize: '0.9rem', marginBottom: 8, color: 'var(--accent)' }}>الاستخبارات والتهديدات (Threat Intel)</div>
            <InputRow label="الوزن (Weight)" value={local.defenses?.threat_intel?.weight} onChange={v => updateDefense('threat_intel', 'weight', v)} step="0.05" />
            <button onClick={() => { mutators.configThreatIntel({ weight: local.defenses.threat_intel.weight, abuseipdb_enabled: local.defenses.threat_intel.abuseipdb, otx_enabled: local.defenses.threat_intel.otx, spamhaus_enabled: local.defenses.threat_intel.spamhaus, feodo_enabled: local.defenses.threat_intel.feodo }); showToast('تم حفظ إعدادات Threat Intel'); }} style={{ width: '100%', padding: '6px', fontSize: '0.8rem', background: 'var(--bg-overlay)', border: '1px solid var(--border)', color: 'var(--text-main)', borderRadius: '4px', cursor: 'pointer' }}>حفظ إعدادات Threat Intel</button>
          </div>

          <div style={{ marginBottom: 16, borderTop: '1px dashed var(--border)', paddingTop: 16 }}>
            <div style={{ fontSize: '0.9rem', marginBottom: 8, color: 'var(--accent)' }}>محرك الخداع (Deception)</div>
            <InputRow label="عتبة الحقن" value={local.defenses?.deception?.injection_threshold} onChange={v => updateDefense('deception', 'injection_threshold', v)} step="0.1" />
            <InputRow label="TTL للمقالب (ثواني)" value={local.defenses?.deception?.ttl_s} onChange={v => updateDefense('deception', 'ttl_s', v)} />
            <button onClick={() => { mutators.configDeception({ injection_threshold: local.defenses.deception.injection_threshold, ttl_seconds: local.defenses.deception.ttl_s }); showToast('تم حفظ إعدادات الخداع'); }} style={{ width: '100%', padding: '6px', fontSize: '0.8rem', background: 'var(--bg-overlay)', border: '1px solid var(--border)', color: 'var(--text-main)', borderRadius: '4px', cursor: 'pointer' }}>حفظ إعدادات الخداع</button>
          </div>
        </SectionCard>

        {/* ── Dynamic Amplifiers ── */}
        <SectionCard>
          <CardHeader icon={Zap} title="المضاعفات الديناميكية (Dynamic Amplifiers)" />
          
          <div style={{ marginBottom: 16 }}>
            <div style={{ fontSize: '0.9rem', marginBottom: 8, color: 'var(--accent)' }}>السمعة والروبوتات</div>
            <InputRow label="مضاعف السمعة (Reputation)" value={local.dynamic_amplifiers?.reputation_boost} onChange={v => updateNested('dynamic_amplifiers', 'reputation_boost', v)} step="0.01" />
            <InputRow label="مضاعف الروبوتات (Bot)" value={local.dynamic_amplifiers?.bot_boost} onChange={v => updateNested('dynamic_amplifiers', 'bot_boost', v)} step="0.01" />
            <InputRow label="عتبة السمعة" value={local.dynamic_amplifiers?.reputation_threshold} onChange={v => updateNested('dynamic_amplifiers', 'reputation_threshold', v)} step="0.01" />
            <InputRow label="عتبة الروبوتات" value={local.dynamic_amplifiers?.bot_threshold} onChange={v => updateNested('dynamic_amplifiers', 'bot_threshold', v)} step="0.01" />
          </div>

          <div style={{ marginBottom: 16, borderTop: '1px dashed var(--border)', paddingTop: 16 }}>
            <div style={{ fontSize: '0.9rem', marginBottom: 8, color: 'var(--accent)' }}>أوزان وتجاوزات متقدمة</div>
            <InputRow label="تجاوز ثقة عالية (NLP+GAF)" value={local.dynamic_amplifiers?.high_confidence_override} onChange={v => updateNested('dynamic_amplifiers', 'high_confidence_override', v)} step="0.01" />
            <InputRow label="وزن تجاوز GNN" value={local.dynamic_amplifiers?.gnn_override_weight} onChange={v => updateNested('dynamic_amplifiers', 'gnn_override_weight', v)} step="0.01" />
            <InputRow label="وزن مضاعف البصمة" value={local.dynamic_amplifiers?.fingerprint_boost_weight} onChange={v => updateNested('dynamic_amplifiers', 'fingerprint_boost_weight', v)} step="0.01" />
            <button onClick={() => {
              mutators.configDynamicAmplifiers({
                reputation_boost: local.dynamic_amplifiers.reputation_boost,
                bot_boost: local.dynamic_amplifiers.bot_boost,
                reputation_threshold: local.dynamic_amplifiers.reputation_threshold,
                bot_threshold: local.dynamic_amplifiers.bot_threshold,
                high_confidence_override: local.dynamic_amplifiers.high_confidence_override,
                gnn_override_weight: local.dynamic_amplifiers.gnn_override_weight,
                fingerprint_boost_weight: local.dynamic_amplifiers.fingerprint_boost_weight
              });
              showToast('تم حفظ إعدادات المضاعفات الديناميكية');
            }} style={{ width: '100%', padding: '6px', fontSize: '0.8rem', background: 'var(--bg-overlay)', border: '1px solid var(--border)', color: 'var(--text-main)', borderRadius: '4px', cursor: 'pointer', marginTop: 8 }}>حفظ إعدادات المضاعفات</button>
          </div>
        </SectionCard>

        {/* ── Auto-Learning & Rate Limiting ── */}
        <SectionCard>
          <CardHeader icon={Activity} title="التعلم التلقائي والتحكم بالمعدل (Auto-Learning & Rate Limit)" />
          
          <FeatureToggleRow 
            label="التعلم الآلي المستمر (Auto-Learning)" 
            desc="تحديث خط الأساس وسلوك الحركة تلقائياً" 
            enabled={local.auto_learning_enabled ?? true} 
            onChange={(val) => setLocal({...local, auto_learning_enabled: val})} 
            color="#00cfe8" 
          />
          <div style={{ margin: '16px 0' }}></div>
          <InputRow label="حد الطلبات / دقيقة (Rate Limit)" value={local.rate_limit_requests ?? 1000} onChange={v => setLocal({...local, rate_limit_requests: v})} />
          <InputRow label="حجم الانفجار المسموح (Burst)" value={local.rate_limit_burst ?? 150} onChange={v => setLocal({...local, rate_limit_burst: v})} />
        </SectionCard>

      </div>
    </div>
  );
}

function Globe(props) {
  return <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1 4-10z"/><path d="M2 12h20"/></svg>
}
