import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { mlCoreApi } from '../../services/api';
import {
  BrainCircuit, Save, RefreshCw, Sliders, Clock, Cpu,
  CheckCircle2, AlertTriangle, Zap, HardDrive, Activity, Sparkles
} from 'lucide-react';
import './MLCore.css';

/* ── Metric Display ── */
function MetricDisplay({ value, label, color, unit = '' }) {
  return (
    <div className="mlc-metric-card" style={{ '--mlc-c': color }}>
      <div className="mlc-metric-val" style={{ color }}>
        {value}{unit}
      </div>
      <div className="mlc-metric-label">{label}</div>
    </div>
  );
}

/* ── Visual Slider ── */
function VisualSlider({ name, label, desc, value, min, max, step, unit, color, onChange }) {
  const pct = ((value - min) / (max - min)) * 100;
  return (
    <div className="mlc-slider-block">
      <div className="mlc-slider-top">
        <div>
          <div className="mlc-slider-label">{label}</div>
          <div className="mlc-slider-desc">{desc}</div>
        </div>
        <div
          className="mlc-slider-val-badge"
          style={{ color, borderColor: `${color}40`, background: `${color}15` }}
        >
          {value}{unit}
        </div>
      </div>
      <div className="mlc-slider-track">
        <div
          className="mlc-slider-fill"
          style={{
            width: `${pct}%`,
            background: `linear-gradient(90deg, ${color}88, ${color})`,
          }}
        />
        <div
          className="mlc-slider-glow"
          style={{
            left: `${pct}%`,
            background: color,
            boxShadow: `0 0 10px ${color}`,
          }}
        />
        <input
          name={name}
          type="range"
          min={min}
          max={max}
          step={step}
          value={value}
          onChange={(e) => onChange(parseFloat(e.target.value))}
          className="mlc-slider-input"
        />
      </div>
      <div className="mlc-slider-ticks">
        <span>{min}{unit}</span>
        <span>{((min + max) / 2).toFixed(max < 10 ? 2 : 0)}{unit}</span>
        <span>{max}{unit}</span>
      </div>
    </div>
  );
}

/* ── Toggle Setting Row ── */
function ToggleSetting({ name, label, desc, checked, onChange, icon: Icon, color = '#00c8ff' }) {
  return (
    <div className={`mlc-toggle-row ${checked ? 'mlc-toggle-row--on' : ''}`}>
      <div
        className="mlc-toggle-icon"
        style={{
          background: checked ? `${color}15` : 'rgba(255,255,255,0.03)',
          borderColor: checked ? `${color}35` : 'rgba(255,255,255,0.08)',
          color: checked ? color : 'var(--text-muted)',
        }}
      >
        <Icon size={18} />
      </div>
      <div className="mlc-toggle-info">
        <div className="mlc-toggle-label" style={{ color: checked ? 'var(--text-primary)' : 'var(--text-secondary)' }}>
          {label}
        </div>
        <div className="mlc-toggle-desc">{desc}</div>
      </div>
      <label className="mm-switch">
        <input
          type="checkbox"
          name={name}
          checked={checked}
          onChange={(e) => onChange(e.target.checked)}
        />
        <span className="mm-switch-track" />
      </label>
    </div>
  );
}

export default function MLCoreSettings() {
  const qc = useQueryClient();

  const { data: config, isLoading } = useQuery({
    queryKey: ['ml-core-config'],
    queryFn: () => mlCoreApi.config().then((r) => r.data),
  });

  const [local, setLocal] = useState(null);
  const cfg =
    local ||
    config || {
      correlation_threshold: 0.85,
      time_window_seconds: 300,
      enable_deep_learning: true,
    };

  const updateMut = useMutation({
    mutationFn: (newCfg) => mlCoreApi.updateConfig(newCfg),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['ml-core-config'] });
      setLocal(null);
    },
  });

  const handleSave = () => {
    updateMut.mutate({
      correlation_threshold: cfg.correlation_threshold,
      time_window_seconds: cfg.time_window_seconds,
      enable_deep_learning: cfg.enable_deep_learning,
    });
  };

  const set = (key) => (val) =>
    setLocal((prev) => ({ ...(prev || cfg), [key]: val }));

  if (isLoading) {
    return (
      <div className="mlc-loading">
        <RefreshCw size={22} className="mm-spin text-cyan-400" />
        <span>جاري تحميل معاملات محرك الاستدلال الذكي...</span>
      </div>
    );
  }

  const sensitivityRisk =
    cfg.correlation_threshold < 0.7
      ? { label: 'حساسية مرتفعة جداً — قد تزداد الإنذارات الكاذبة', color: '#ff4d6a', icon: AlertTriangle }
      : cfg.correlation_threshold > 0.92
      ? { label: 'حساسية منخفضة — قد تتجاوز بعض التهديدات الخفية', color: '#ffab40', icon: AlertTriangle }
      : { label: 'نطاق إنتاجي مثالي متوازن', color: '#00e676', icon: CheckCircle2 };

  const SensIcon = sensitivityRisk.icon;

  return (
    <div className="mlc-root" dir="rtl">
      {/* ── Hero Banner ── */}
      <div className="mlc-hero">
        <div className="mlc-hero-glow" />
        <div className="mlc-hero-inner">
          <div className="mlc-hero-left">
            <div className="mlc-hero-icon">
              <BrainCircuit size={28} style={{ color: '#00c8ff' }} />
            </div>
            <div>
              <h2 className="mlc-hero-title">محرك التعلم الآلي والاستدلال التنبؤي (AI-Core)</h2>
              <p className="mlc-hero-sub">ONNX Runtime · Neural Inference & Threat Correlation Engine</p>
            </div>
          </div>
          <div className="mlc-hero-badges">
            <span className="mlc-badge mlc-badge--cyan">
              <Sparkles size={12} /> AI-Powered
            </span>
            <span className="mlc-badge mlc-badge--green">
              <Activity size={12} /> تشغيل فوري بالنواة
            </span>
          </div>
        </div>
      </div>

      {/* ── Metric Cards Row ── */}
      <div className="mlc-metrics-row">
        <MetricDisplay
          value={(cfg.correlation_threshold * 100).toFixed(0)}
          unit="%"
          label="عتبة الارتباط الأدنى"
          color="#00c8ff"
        />
        <MetricDisplay
          value={cfg.time_window_seconds}
          unit="ث"
          label="نافذة الذاكرة الزمنية"
          color="#818cf8"
        />
        <MetricDisplay
          value={cfg.enable_deep_learning ? 'ONNX Active' : 'Off'}
          label="محرك التعلم العميق"
          color={cfg.enable_deep_learning ? '#00e676' : '#ff4d6a'}
        />
        <MetricDisplay
          value={
            cfg.time_window_seconds >= 60
              ? `${(cfg.time_window_seconds / 60).toFixed(1)} دقيقة`
              : `${cfg.time_window_seconds} ثانية`
          }
          label="سياق تتبع التهديد"
          color="#ffab40"
        />
      </div>

      {/* ── Recommendation Alert Box ── */}
      <div className="mlc-info-card">
        <div className="mlc-info-left">
          <Zap size={16} style={{ color: '#00c8ff', flexShrink: 0 }} />
          <span>
            تتحكم هذه المعاملات في حساسية نماذج الذكاء الاصطناعي لكشف الشذوذ والربط بين الحوادث.
            <strong> النطاق الموصى به لبيئات الإنتاج: 0.80 – 0.90</strong>.
          </span>
        </div>
        <div
          className="mlc-risk-tag"
          style={{
            color: sensitivityRisk.color,
            background: `${sensitivityRisk.color}15`,
            borderColor: `${sensitivityRisk.color}35`,
          }}
        >
          <SensIcon size={13} /> {sensitivityRisk.label}
        </div>
      </div>

      {/* ── Sliders Card ── */}
      <div className="mlc-card">
        <div className="mlc-card-header">
          <Sliders size={16} style={{ color: '#00c8ff' }} />
          <span>معاملات حساسية النموذج والاستدلال</span>
        </div>

        <VisualSlider
          name="correlation_threshold"
          label="عتبة الارتباط والثقة (Correlation Threshold)"
          desc="درجة اليقين الدنيا لاعتبار الحدث هجوماً سيبرانياً يستوجب التدخل التلقائي"
          value={cfg.correlation_threshold}
          min={0}
          max={1}
          step={0.05}
          unit=""
          color="#00c8ff"
          onChange={set('correlation_threshold')}
        />

        <VisualSlider
          name="time_window_seconds"
          label="نافذة السياق الزمني (Time Window Seconds)"
          desc="الفترة الزمنية التي يحتفظ فيها المحرك بالأحداث المترابطة لاكتشاف الهجمات المعقدة"
          value={cfg.time_window_seconds}
          min={30}
          max={900}
          step={30}
          unit="ث"
          color="#818cf8"
          onChange={set('time_window_seconds')}
        />
      </div>

      {/* ── Hardware Acceleration Toggles ── */}
      <div className="mlc-card">
        <div className="mlc-card-header">
          <Cpu size={16} style={{ color: '#00e676' }} />
          <span>تسريع العتاد ومحركات الاستدلال المتقدمة</span>
        </div>

        <ToggleSetting
          name="enable_deep_learning"
          label="تفعيل محرك ONNX Runtime للتعلم العميق"
          desc="تفريغ نماذج الشبكات العصبية العميقة إلى مكتبات ONNX عالية الكفاءة"
          checked={cfg.enable_deep_learning}
          onChange={(v) => set('enable_deep_learning')(v)}
          icon={BrainCircuit}
          color="#00c8ff"
        />

        <ToggleSetting
          name="enable_gpu"
          label="تسريع المعالجة عبر كروت الشاشة (GPU / CUDA)"
          desc="تسريع الاستدلال اللحظي للشبكات العصبية — يتطلب بيئة تدعم NVIDIA CUDA"
          checked={cfg.enable_gpu ?? false}
          onChange={(v) => set('enable_gpu')(v)}
          icon={HardDrive}
          color="#00e676"
        />
      </div>

      {/* ── Save Action Footer ── */}
      <div className="mlc-footer">
        {local && (
          <span className="mlc-unsaved">
            <AlertTriangle size={14} /> توجد تعديلات غير محفوظة
          </span>
        )}
        <button
          className="s-btn s-btn-primary"
          onClick={handleSave}
          disabled={updateMut.isPending || !local}
        >
          {updateMut.isPending ? (
            <>
              <RefreshCw size={15} className="mm-spin" /> جاري الحفظ والتطبيق...
            </>
          ) : (
            <>
              <Save size={15} /> حفظ إعدادات محرك الذكاء الاصطناعي
            </>
          )}
        </button>

        {updateMut.isSuccess && (
          <span className="mlc-saved-note">
            <CheckCircle2 size={14} style={{ color: '#00e676' }} /> تم تطبيق الإعدادات بنجاح
          </span>
        )}
      </div>
    </div>
  );
}
