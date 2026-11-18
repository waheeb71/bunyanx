import React from 'react';
import { Cpu, Zap, Network, Activity } from 'lucide-react';
import { SectionCard } from '../../../components/Shared';
import Toggle from './Toggle';

export function SettingsView({ cfg, phantomStatus, phantomDrift, traps, updateConfig }) {
  const pct = Math.round((cfg.anomaly_threshold ?? 0.5) * 100);
  const phantomConfPct = Math.round((cfg.phantom_confidence_threshold ?? 0.70) * 100);
  const causalDensityPct = Math.round((cfg.causal_density_threshold ?? 0.50) * 100);

  const handleUpdate = (updates) => {
    updateConfig.mutate({ ...cfg, ...updates });
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>

      {/* Engine Config */}
      <SectionCard title="إعداد محرك IDS/IPS" icon={Cpu}>
        {/* Mode Picker */}
        <div className="ids-config-row">
          <div>
            <div style={{ fontWeight: 700 }}>وضع التطبيق</div>
            <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>التبديل بين المراقبة السلبية والحجب النشط عبر eBPF/XDP</div>
          </div>
          <div className="ids-mode-pills">
            <button
              className={`ids-mode-pill ${cfg.mode === 'blocking' ? 'active' : ''}`}
              data-color="danger"
              onClick={() => handleUpdate({ mode: 'blocking' })}
            >
              ⛔ IPS — حجب نشط
            </button>
            <button
              className={`ids-mode-pill ${cfg.mode === 'monitoring' ? 'active' : ''}`}
              data-color="accent"
              onClick={() => handleUpdate({ mode: 'monitoring' })}
            >
              👁 IDS — مراقبة فقط
            </button>
          </div>
        </div>

        {/* L3 Anomaly */}
        <div className="ids-config-row">
          <div>
            <div style={{ fontWeight: 700 }}>كشف الشذوذ L3</div>
            <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>Isolation Forest لاكتشاف الشذوذات على مستوى الشبكة</div>
          </div>
          <Toggle
            checked={cfg.enable_l3_anomaly ?? true}
            onChange={() => handleUpdate({ enable_l3_anomaly: !cfg.enable_l3_anomaly })}
            color="var(--accent)"
          />
        </div>

        {/* L7 DPI */}
        <div className="ids-config-row">
          <div>
            <div style={{ fontWeight: 700 }}>فحص الحزم العميق L7</div>
            <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>XGBoost + Random Forest لتصنيف هجمات طبقة التطبيقات</div>
          </div>
          <Toggle
            checked={cfg.enable_l7_dpi ?? true}
            onChange={() => handleUpdate({ enable_l7_dpi: !cfg.enable_l7_dpi })}
            color="var(--success)"
          />
        </div>

        {/* Anomaly Threshold Slider */}
        <div className="ids-config-row" style={{ flexDirection: 'column', alignItems: 'stretch', gap: 12 }}>
          <div>
            <div style={{ fontWeight: 700 }}>عتبة الحجب بالذكاء الاصطناعي</div>
            <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>درجة الشذوذ التي يبدأ فوقها الحجب التلقائي</div>
          </div>
          <div className="ids-slider-wrap">
            <div className="ids-slider-labels">
              <span>0 — سماح كلي</span>
              <span className="mono" style={{ color: 'var(--accent)', fontWeight: 800 }}>{pct}%</span>
              <span>100 — حجب المؤكد</span>
            </div>
            <div className="ids-slider-track">
              <div className="ids-slider-fill" style={{ width: `${pct}%` }} />
              <input
                type="range" min={0} max={100} step={5}
                value={pct}
                onChange={e => handleUpdate({ anomaly_threshold: Number(e.target.value) / 100 })}
                className="ids-slider-input"
              />
            </div>
          </div>
        </div>
      </SectionCard>

      {/* PHANTOM Threat Engine Settings */}
      <SectionCard title="إعدادات محرك PHANTOM المتقدم" icon={Network}>
        {/* Enable PHANTOM */}
        <div className="ids-config-row">
          <div>
            <div style={{ fontWeight: 700 }}>تفعيل محرك PHANTOM</div>
            <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>محرك GNN + Transformer للتحليل السلوكي العميق والتحقق من النية المشتركة</div>
          </div>
          <Toggle
            checked={cfg.enable_phantom ?? true}
            onChange={() => handleUpdate({ enable_phantom: !cfg.enable_phantom })}
            color="var(--danger)"
          />
        </div>

        {/* Require Legacy Confirm */}
        <div className="ids-config-row">
          <div>
            <div style={{ fontWeight: 700 }}>تطلب تأكيد المحرك القديم</div>
            <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>حجب الاتصال فقط عندما يوافق المحرك التقليدي مع PHANTOM (وضع محافظ جداً)</div>
          </div>
          <Toggle
            checked={cfg.require_legacy_confirm ?? false}
            onChange={() => handleUpdate({ require_legacy_confirm: !cfg.require_legacy_confirm })}
            color="var(--warning)"
          />
        </div>

        {/* PHANTOM Confidence Threshold Slider */}
        <div className="ids-config-row" style={{ flexDirection: 'column', alignItems: 'stretch', gap: 12 }}>
          <div>
            <div style={{ fontWeight: 700 }}>عتبة ثقة PHANTOM</div>
            <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>درجة الثقة الأدنى لتنفيذ الحجب التلقائي عبر الذكاء الاصطناعي</div>
          </div>
          <div className="ids-slider-wrap">
            <div className="ids-slider-labels">
              <span>0 — حساسية قصوى</span>
              <span className="mono" style={{ color: 'var(--danger)', fontWeight: 800 }}>{phantomConfPct}%</span>
              <span>100 — دقة قصوى</span>
            </div>
            <div className="ids-slider-track">
              <div className="ids-slider-fill" style={{ width: `${phantomConfPct}%`, background: 'var(--danger)' }} />
              <input
                type="range" min={0} max={100} step={5}
                value={phantomConfPct}
                onChange={e => handleUpdate({ phantom_confidence_threshold: Number(e.target.value) / 100 })}
                className="ids-slider-input"
              />
            </div>
          </div>
        </div>

        {/* Causal Density Threshold Slider */}
        <div className="ids-config-row" style={{ flexDirection: 'column', alignItems: 'stretch', gap: 12 }}>
          <div>
            <div style={{ fontWeight: 700 }}>عتبة الكثافة السببية للتهديدات</div>
            <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>درجة كثافة الاتصالات في الرسم البياني لتسريع استجابة المنع</div>
          </div>
          <div className="ids-slider-wrap">
            <div className="ids-slider-labels">
              <span>0 — تسريع دائم</span>
              <span className="mono" style={{ color: 'var(--warning)', fontWeight: 800 }}>{causalDensityPct}%</span>
              <span>100 — منع حذر</span>
            </div>
            <div className="ids-slider-track">
              <div className="ids-slider-fill" style={{ width: `${causalDensityPct}%`, background: 'var(--warning)' }} />
              <input
                type="range" min={0} max={100} step={5}
                value={causalDensityPct}
                onChange={e => handleUpdate({ causal_density_threshold: Number(e.target.value) / 100 })}
                className="ids-slider-input"
              />
            </div>
          </div>
        </div>
      </SectionCard>

      {/* Active Defense & Decoy Traps */}
      <SectionCard title="التصدي الفوري والمصائد الخداعية (Active Defense & Decoy Traps)" icon={Zap}>
        <div className="ids-config-row">
          <div>
            <div style={{ fontWeight: 700 }}>الحجر التلقائي وإسقاط الجلسات (Auto-Quarantine)</div>
            <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>عزل عناوين IP المهاجمة تلقائياً عند تجاوز عتبة التهديد المؤكدة</div>
          </div>
          <Toggle
            checked={cfg.auto_quarantine_enabled ?? true}
            onChange={() => handleUpdate({ auto_quarantine_enabled: !cfg.auto_quarantine_enabled })}
            color="var(--danger)"
          />
        </div>

        <div className="ids-config-row">
          <div>
            <div style={{ fontWeight: 700 }}>تسريع إسقاط الحزم عبر eBPF / XDP</div>
            <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>إسقاط الحزم المعادية في مرحلة برنامج تشغيل بطاقة الشبكة قبل وصولها لنواة النقل</div>
          </div>
          <Toggle
            checked={cfg.ebpf_tc_enabled ?? true}
            onChange={() => handleUpdate({ ebpf_tc_enabled: !cfg.ebpf_tc_enabled })}
            color="var(--accent)"
          />
        </div>

        <div className="ids-config-row">
          <div>
            <div style={{ fontWeight: 700 }}>توجيه المهاجمين إلى المصائد الخداعية (Decoy Traps)</div>
            <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>تحويل مسح المنافذ ومحاولات الاختراق إلى مصائد Honeypot وهمية لدراسة السلوك</div>
          </div>
          <Toggle
            checked={cfg.decoy_trap_enabled ?? true}
            onChange={() => handleUpdate({ decoy_trap_enabled: !cfg.decoy_trap_enabled })}
            color="var(--warning)"
          />
        </div>
      </SectionCard>

      {/* PHANTOM Status Panel */}
      {phantomStatus && phantomStatus.available && (
        <SectionCard title="حالة وإحصائيات محرك PHANTOM" icon={Cpu}>
          <div className="ids-stats-grid">
            <div className="ids-stat-card">
              <div className="ids-stat-label">المنافذ النشطة في الرسم البياني</div>
              <div className="ids-stat-value mono">{phantomStatus.ctgb?.active_nodes ?? 0}</div>
            </div>
            <div className="ids-stat-card">
              <div className="ids-stat-label">العلاقات السببية المكتشفة</div>
              <div className="ids-stat-value mono">{phantomStatus.ctgb?.active_edges ?? 0}</div>
            </div>
            <div className="ids-stat-card">
              <div className="ids-stat-label">الكثافة السببية الحالية</div>
              <div className="ids-stat-value mono">{(phantomStatus.ctgb?.causal_density ?? 0).toFixed(4)}</div>
            </div>
            <div className="ids-stat-card">
              <div className="ids-stat-label">محرك الاستدلال (Backend)</div>
              <div className="ids-stat-value mono" style={{ textTransform: 'uppercase', fontSize: '1.1rem', color: 'var(--accent)' }}>
                {phantomStatus.phantom_backend ?? 'none'}
              </div>
            </div>
          </div>

          <div className="ids-stats-grid" style={{ marginTop: 'var(--sp-3)' }}>
            <div className="ids-stat-card">
              <div className="ids-stat-label">إجمالي الحزم المفحوصة</div>
              <div className="ids-stat-value mono">{phantomStatus.total_inspected ?? 0}</div>
            </div>
            <div className="ids-stat-card">
              <div className="ids-stat-label">إجمالي الحجب المطبق</div>
              <div className="ids-stat-value mono">{phantomStatus.total_blocked ?? 0}</div>
            </div>
            <div className="ids-stat-card">
              <div className="ids-stat-label">التهديدات المكتشفة بـ PHANTOM</div>
              <div className="ids-stat-value mono" style={{ color: 'var(--danger)' }}>{phantomStatus.total_phantom_threats ?? 0}</div>
            </div>
            <div className="ids-stat-card">
              <div className="ids-stat-label">حالة ترميز الطيف (SBE)</div>
              <div className="ids-stat-value mono" style={{ color: phantomStatus.sbe_available ? 'var(--success)' : 'var(--text-muted)' }}>
                {phantomStatus.sbe_available ? 'نشط' : 'غير متوفر'}
              </div>
            </div>
          </div>

          {/* Concept Drift & OCL Panel */}
          {phantomDrift && phantomDrift.available && (
            <div className="ids-drift-panel" style={{ marginTop: 'var(--sp-4)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
                <Activity size={16} style={{ color: 'var(--accent)' }} />
                <div style={{ fontWeight: 700 }}>حالة التعلم المستمر وضبط المفهوم (OCL & Drift)</div>
              </div>
              <div className="ids-stats-grid">
                <div className="ids-stat-card">
                  <div className="ids-stat-label">انحراف المفهوم المكتشف (Drift)</div>
                  <div className="ids-stat-value mono" style={{ color: phantomDrift.drift_detected ? 'var(--danger)' : 'var(--success)' }}>
                    {phantomDrift.drift_detected ? '⚠️ انحراف نشط' : '✅ مستقر'}
                  </div>
                </div>
                <div className="ids-stat-card">
                  <div className="ids-stat-label">معدل خطأ نافذة التقييم</div>
                  <div className="ids-stat-value mono">{(phantomDrift.window_error_rate ?? 0).toFixed(4)}</div>
                </div>
                <div className="ids-stat-card">
                  <div className="ids-stat-label">إجمالي أحداث الانحراف</div>
                  <div className="ids-stat-value mono">{phantomDrift.total_drifts ?? 0}</div>
                </div>
                <div className="ids-stat-card">
                  <div className="ids-stat-label">حجم الذاكرة العرضية (Memory)</div>
                  <div className="ids-stat-value mono">{phantomDrift.memory_size ?? 0} عينات</div>
                </div>
              </div>
            </div>
          )}
        </SectionCard>
      )}

      {/* Deception Engine */}
      <SectionCard title="محرك الخداع السببي" icon={Zap}>
        <div className="ids-config-row">
          <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
            <span style={{ fontSize: '1.4rem' }}>🪤</span>
            <div>
              <div style={{ fontWeight: 700 }}>دفاع نشط — فخاخ شبكية سببية</div>
              <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>براءة اختراع قيد الإيداع</div>
            </div>
          </div>
          <Toggle
            checked={cfg.deception_enabled ?? true}
            onChange={() => handleUpdate({ deception_enabled: !cfg.deception_enabled })}
            color="var(--warning)"
          />
        </div>

        <div className="ids-traps-grid">
          {traps.map(t => (
            <div key={t.label} className="ids-trap-card">
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600 }}>{t.label}</div>
              <div className="mono" style={{ fontSize: '0.78rem', color: 'var(--warning)', direction: 'ltr', textAlign: 'right' }}>{t.value}</div>
            </div>
          ))}
        </div>

        <div className="ids-deception-note">
          <Zap size={14} style={{ flexShrink: 0, color: 'var(--warning)' }} />
          مدعوم بـ <strong>محرك الخداع السببي الموحد</strong> — تُغذي الفخاخ مجمع التحقق من النية المشتركة عبر الوحدات.
        </div>
      </SectionCard>
    </div>
  );
}

export default SettingsView;
