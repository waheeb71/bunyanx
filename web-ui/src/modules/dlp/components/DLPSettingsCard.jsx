import React, { useState } from 'react';
import { Shield, Zap, Fingerprint, BrainCircuit, Activity, Sliders, RefreshCw, FileCode, CheckCircle2 } from 'lucide-react';
import { useDLP } from '../hooks/useDLP';

const ToggleRow = ({ label, desc, checked, onChange, disabled }) => (
  <div
    style={{
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      padding: '14px 18px',
      background: 'rgba(255, 255, 255, 0.02)',
      borderRadius: '10px',
      border: '1px solid rgba(255, 255, 255, 0.06)',
      opacity: disabled ? 0.45 : 1,
      transition: 'all 0.2s ease',
    }}
  >
    <div>
      <div style={{ fontWeight: 700, fontSize: '0.88rem', color: 'var(--text-primary)' }}>{label}</div>
      <div style={{ fontSize: '0.74rem', color: 'var(--text-secondary)', marginTop: 2 }}>{desc}</div>
    </div>
    <label className="toggle" style={{ flexShrink: 0, marginRight: 16 }}>
      <input type="checkbox" checked={!!checked} onChange={onChange} disabled={disabled} />
      <span className="toggle-slider" />
    </label>
  </div>
);

const SliderRow = ({ label, desc, value, min = 0, max = 1, step = 0.05, onChange, color = '#00c8ff' }) => (
  <div
    style={{
      padding: '14px 18px',
      background: 'rgba(255, 255, 255, 0.02)',
      borderRadius: '10px',
      border: '1px solid rgba(255, 255, 255, 0.06)',
      display: 'flex',
      flexDirection: 'column',
      gap: 8,
    }}
  >
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
      <div>
        <div style={{ fontWeight: 700, fontSize: '0.86rem', color: 'var(--text-primary)' }}>{label}</div>
        <div style={{ fontSize: '0.74rem', color: 'var(--text-secondary)', marginTop: 2 }}>{desc}</div>
      </div>
      <span
        style={{
          fontWeight: 800,
          fontSize: '0.95rem',
          color,
          minWidth: 48,
          textAlign: 'left',
          fontFamily: 'JetBrains Mono, monospace',
          direction: 'ltr',
          background: `${color}15`,
          border: `1px solid ${color}35`,
          padding: '2px 8px',
          borderRadius: '6px',
        }}
      >
        {value}
      </span>
    </div>
    <input
      type="range"
      style={{ width: '100%', accentColor: color, transform: 'scaleX(-1)', cursor: 'pointer' }}
      min={min}
      max={max}
      step={step}
      value={value ?? 0}
      onChange={onChange}
    />
  </div>
);

export default function DLPSettingsCard() {
  const { config, updateConfig, optimizeWeights, yamlSettings } = useDLP();
  const [optLaunched, setOptLaunched] = useState(false);

  const set = (key, val) => {
    updateConfig.mutate({ ...config, [key]: val });
  };

  const handleOptimize = () => {
    optimizeWeights.mutate(undefined, {
      onSuccess: () => {
        setOptLaunched(true);
        setTimeout(() => setOptLaunched(false), 5000);
      },
    });
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* ── Core Settings ── */}
      <div
        className="card"
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
              background: 'rgba(255, 77, 106, 0.12)',
              color: '#ff4d6a',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <Shield size={18} />
          </div>
          <div>
            <h3 style={{ fontWeight: 800, fontSize: '1rem', color: 'var(--text-primary)', margin: 0 }}>
              المحرك الأساسي لمنع التسريب (Core Engine)
            </h3>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
              التحكم في فحص التدفق اللحظي وسياسات الإسقاط الفوري
            </span>
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <ToggleRow
            label="تفعيل محرك حماية البيانات (DLP Active)"
            desc="تنشيط طبقات الفحص الـ 3 (المحتوى والسلوك والذكاء الاصطناعي)"
            checked={config.is_active}
            onChange={(e) => set('is_active', e.target.checked)}
          />
          <ToggleRow
            label="الحظر التلقائي للتسريبات المشبوهة"
            desc="إسقاط فوري لكافة الحزم التي تتطابق مع قواعد المحتوى الممنوعة"
            checked={config.block_on_match}
            onChange={(e) => set('block_on_match', e.target.checked)}
            disabled={!config.is_active}
          />
        </div>
      </div>

      {/* ── BEFP Behavioral Settings ── */}
      <div
        className="card"
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
              background: 'rgba(0, 200, 255, 0.12)',
              color: '#00c8ff',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <BrainCircuit size={18} />
          </div>
          <div>
            <h3 style={{ fontWeight: 800, fontSize: '1rem', color: 'var(--text-primary)', margin: 0 }}>
              محرك كشف السلوكيات الشاذة (BEFP Engine)
            </h3>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
              ضبط عتبات التنبيه ودرجة الخطر التراكمي (ERS Score)
            </span>
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <ToggleRow
            label="التحليل السلوكي المتزامن"
            desc="نظام تقييم بـ 5 إشارات (ERS) وغابة العزلة باستخدام الذكاء الاصطناعي"
            checked={config.befp_enabled}
            onChange={(e) => set('befp_enabled', e.target.checked)}
            disabled={!config.is_active}
          />

          <SliderRow
            label="عتبة الحظر السلوكي (Block Threshold)"
            desc="مستوى تقييم السلوك (ERS) المطلوب لتشغيل الحظر أو فخ الخداع"
            value={config.befp_block_threshold ?? 0.8}
            color="#ff4d6a"
            onChange={(e) => set('befp_block_threshold', parseFloat(e.target.value))}
          />

          <SliderRow
            label="عتبة التنبيه والاستدعاء (Alert Threshold)"
            desc="مستوى تقييم السلوك (ERS) للإبلاغ عن نشاط مشبوه"
            value={config.befp_alert_threshold ?? 0.35}
            color="#ffab40"
            onChange={(e) => set('befp_alert_threshold', parseFloat(e.target.value))}
          />
        </div>
      </div>

      {/* ── ERS Signal Weights ── */}
      {config.befp_enabled && (
        <div
          className="card"
          style={{
            background: 'rgba(10, 14, 26, 0.75)',
            backdropFilter: 'blur(16px)',
            border: '1px solid rgba(0, 200, 255, 0.15)',
            borderRadius: 'var(--radius-lg)',
            padding: '22px',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16, flexWrap: 'wrap', gap: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
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
                <Sliders size={18} />
              </div>
              <div>
                <h3 style={{ fontWeight: 800, fontSize: '1rem', color: 'var(--text-primary)', margin: 0 }}>
                  أوزان إشارات التقييم الخماسي (ERS Signal Weights)
                </h3>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
                  توزيع الأوزان النسبية بين إشارات المحرك السلوكي
                </span>
              </div>
            </div>

            <button
              className="btn btn-ghost"
              onClick={handleOptimize}
              disabled={optimizeWeights.isPending}
              style={{ fontSize: '0.78rem', fontWeight: 700, padding: '6px 14px', display: 'flex', alignItems: 'center', gap: 6 }}
            >
              <RefreshCw size={13} style={{ animation: optimizeWeights.isPending ? 'spin 1s linear infinite' : 'none', color: '#00c8ff' }} />
              {optimizeWeights.isPending ? 'جاري التحسين...' : 'تحسين الأوزان تلقائياً (Grid Search)'}
            </button>
          </div>

          {optLaunched && (
            <div
              style={{
                marginBottom: 14,
                padding: '10px 14px',
                background: 'rgba(0, 230, 118, 0.1)',
                border: '1px solid rgba(0, 230, 118, 0.25)',
                borderRadius: '8px',
                fontSize: '0.8rem',
                color: '#00e676',
                fontWeight: 700,
                display: 'flex',
                alignItems: 'center',
                gap: 8,
              }}
            >
              <CheckCircle2 size={16} /> تم إطلاق عملية تحسين الأوزان في الخلفية بنجاح.
            </div>
          )}

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {[
              { key: 'w_entropy', label: 'معدل عشوائية المحتوى (Shannon Entropy)', color: '#ff4d6a' },
              { key: 'w_velocity', label: 'شذوذ سرعة التدفق والتلقي', color: '#ffab40' },
              { key: 'w_chunking', label: 'أنماط التقطيع الدقيق', color: '#fbbf24' },
              { key: 'w_protocol', label: 'الانحراف عن البروتوكول المعتاد', color: '#00e676' },
              { key: 'w_accumulation', label: 'التراكم الزمني خلال 24 ساعة', color: '#00c8ff' },
            ].map(({ key, label, color }) => (
              <SliderRow
                key={key}
                label={label}
                desc={`الوزن النسبي: ${((config[key] ?? 0) * 100).toFixed(0)}%`}
                value={config[key] ?? 0}
                color={color}
                onChange={(e) => set(key, parseFloat(e.target.value))}
              />
            ))}
          </div>
        </div>
      )}

      {/* ── Causal Deception Engine ── */}
      <div
        className="card"
        style={{
          background: 'rgba(10, 14, 26, 0.75)',
          backdropFilter: 'blur(16px)',
          border: '1px solid rgba(255, 171, 64, 0.25)',
          borderRadius: 'var(--radius-lg)',
          padding: '22px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
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
            <Zap size={18} />
          </div>
          <div>
            <h3 style={{ color: '#ffab40', margin: 0, fontSize: '1rem', fontWeight: 800 }}>
              محرك الخداع الاستباقي (Causal Deception Engine)
            </h3>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
              نظام تضليل المهاجمين وحقن البيانات الوهمية المبصومة
            </span>
          </div>
        </div>

        <ToggleRow
          label="فخاخ العلامات المائية للبيانات (Watermarked Deception)"
          desc="عند كشف محاولة تسريب، يتم حقن بيانات وهمية مبصومة لتتبع المهاجم بدلاً من الإسقاط الصامت"
          checked={config.deception_enabled ?? true}
          onChange={(e) => set('deception_enabled', e.target.checked)}
        />
      </div>

      {/* ── Save Settings Button ── */}
      <div style={{ display: 'flex', alignItems: 'center' }}>
        <button
          className="btn btn-primary"
          style={{ width: '100%', padding: '12px 0', fontWeight: 800, fontSize: '0.88rem' }}
          onClick={() => updateConfig.mutate(config)}
          disabled={updateConfig.isPending}
        >
          <Activity size={16} style={{ marginLeft: 8 }} />
          {updateConfig.isPending ? 'جاري حفظ الإعدادات...' : 'حفظ وتطبيق إعدادات الـ DLP'}
        </button>
      </div>
    </div>
  );
}
