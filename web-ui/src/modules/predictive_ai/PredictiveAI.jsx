/**
 * Predictive AI — Central control plane for AI/ML defensive orchestration.
 * Refactored: Split into modular subcomponents, hooks, and decentralized API layer.
 */
import { motion, AnimatePresence } from 'framer-motion';
import {
  Zap, Activity, Target, ShieldCheck, Database, Brain,
  Search, RefreshCw, Crosshair, ShieldAlert, Layers, Network,
  TrendingUp, ArrowLeft, CheckCircle2, UserCheck, Eye, Cpu, Key, Upload
} from 'lucide-react';

import usePredictiveAI from './hooks/usePredictiveAI';
import RiskGauge from './components/RiskGauge';
import ModelBadge from './components/ModelBadge';
import DecisionRow from './components/DecisionRow';
import IpInspectorModal from './components/IpInspectorModal';
import { fmtDate, fmtTs, fmtIso } from './components/Helpers';
import './PredictiveAI.css';

const SEV_META = {
  HIGH: { cls: 'pai-sev--hi', label: 'حرجة' },
  MEDIUM: { cls: 'pai-sev--mid', label: 'متوسطة' },
  LOW: { cls: 'pai-sev--lo', label: 'منخفضة' },
};

const TABS = [
  { id: 'overview', label: 'نظرة عامة (SOC)', icon: Activity },
  { id: 'intents', label: 'مخطط التهديد والنوايا', icon: Target },
  { id: 'decisions', label: 'قرارات AEGIS', icon: Eye },
  { id: 'safety', label: 'تدقيق السلامة (RL)', icon: ShieldCheck },
  { id: 'logs', label: 'السجلات التاريخية', icon: Database },
  { id: 'models', label: 'المحركات والإعدادات', icon: Brain },
];

export default function PredictiveAI() {
  const {
    tab,
    setTab,
    uploading,
    setUploading,
    showIpInspector,
    setShowIpInspector,
    logsTab,
    setLogsTab,
    cfg,
    models,
    modelsLoading,
    budget,
    intents,
    graphInfo,
    kcStats,
    auditLogs,
    decisions,
    decLoading,
    decoys,
    ueba,
    tpe,
    logDecisions,
    logIntent,
    logDecoy,
    AEGISHealth,
    updateMut,
    uploadMut,
    refreshAll,
  } = usePredictiveAI();

  const TOGGLES = [
    { id: 'is_active', label: 'التبديل الرئيسي للذكاء التنبؤي', desc: 'تمكين خط الأنابيب الشامل لتدفقات التعلم الآلي' },
    { id: 'enable_forecast_gate', label: 'الاستباق المستند على التنبؤات', desc: 'تخصيص الموارد وقيود السرعة للاتصالات مبكراً' },
    { id: 'enable_killchain_graph', label: 'نظام Killchain الاحتمالي', desc: 'استخدام سلاسل ماركوف لربط الشذوذ متعدد الخطوات' },
    { id: 'enable_intent_predictor', label: 'التنبؤ بنوايا المهاجمين', desc: 'توقع الهجمة اللاحقة بناءً على النمط السلوكي' },
    { id: 'enable_lateral_movement_detection', label: 'كشف الحركة الأفقية (Lateral Movement GNN)', desc: 'تتبع انتشار التهديد داخل الشبكة الداخلية عبر الشبكات العصبية للرسم البياني' },
    { id: 'enable_AEGIS_calibration', label: 'معايرة ثقة AEGIS التلقائية', desc: 'ضبط درجة ثقة التنبؤ بتهديد المستقبل ديناميكياً لتجنب الإنذارات الكاذبة' },
    { id: 'prevent_cpci_override_on_threats', label: 'حماية قرارات الحظر من التجاوز التلقائي (Threat-Aware CPCI)', desc: 'منع محرك AEGIS من إلغاء قرارات الحظر إلى وضع المراقبة (MONITOR) عند رصد هجمات صريحة' },
    { id: 'enable_rl_agent', label: 'وكيل الرد التلقائي (RL)', desc: 'السماح لوكيل التعلم المعزز بتطبيق سياسات شبكية' },
    { id: 'auto_apply_rl_policy', label: 'التنفيذ المستقل المباشر (L4)', desc: 'تجاوز المراجعة البشرية إذا سمحت دقة الأمان به' },
  ];

  return (
    <div className="pai-root" dir="rtl">
      {/* ── Hero ── */}
      <div className="pai-hero">
        <div className="pai-hero-glow" />
        <div className="pai-hero-inner">
          <div className="pai-hero-left">
            <div className="pai-hero-icon">
              <Zap size={28} style={{ color: '#fbbf24' }} />
            </div>
            <div>
              <h1 className="pai-hero-title">الذكاء الاصطناعي التنبؤي والدفاع التكيفي</h1>
              <p className="pai-hero-sub">
                AEGIS v3 · Kill-chain Graph · RL Agent · Intent Predictor · UEBA · GNN Lateral
              </p>
            </div>
          </div>
          <div className="pai-hero-right">
            {decoys.length > 0 && (
              <span className="pai-active-badge" style={{ background: 'rgba(251,191,36,.08)', border: '1px solid rgba(251,191,36,.2)', color: '#fbbf24' }}>
                🪤 {decoys.length} فخ نشط
              </span>
            )}
            <span className={`pai-active-badge ${cfg.is_active ? 'pai-active-badge--on' : 'pai-active-badge--off'}`}>
              {cfg.is_active ? '● الذكاء نشط' : '○ الذكاء معطل'}
            </span>
            <button className="pai-refresh-btn" onClick={() => setShowIpInspector(true)} title="فحص IP">
              <Search size={14} />
            </button>
            <button className="pai-refresh-btn" onClick={refreshAll} title="تحديث الكل">
              <RefreshCw size={14} className={modelsLoading ? 'pai-spin' : ''} />
            </button>
          </div>
        </div>
      </div>

      {/* ── IP Inspector Modal ── */}
      {showIpInspector && <IpInspectorModal onClose={() => setShowIpInspector(false)} />}

      {/* ── Tabs ── */}
      <div className="pai-tabs">
        {TABS.map(t => {
          const Icon = t.icon;
          return (
            <button
              key={t.id}
              className={`pai-tab ${tab === t.id ? 'pai-tab--active' : ''}`}
              onClick={() => setTab(t.id)}
            >
              <Icon size={14} /> {t.label}
            </button>
          );
        })}
      </div>

      {/* ══ Content ══ */}
      <AnimatePresence mode="wait">
        <motion.div
          key={tab}
          initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }}
          transition={{ duration: .18 }}
        >
          {/* ── Overview ── */}
          {tab === 'overview' && (
            <div className="pai-overview-grid">
              <div className="pai-panel pai-gauge-card">
                <RiskGauge remaining={budget.current_budget} max={budget.max_budget} />
                <div className="pai-gauge-info">
                  <div className="pai-gauge-info-title">ميزانية مخاطر الوكيل (RL)</div>
                  <p className="pai-gauge-info-desc">
                    تحد من سياسات النظام المستقل لتجنب اختلال المكافآت.
                    معدل التجديد: <span className="pai-mono">{budget.regen_rate ?? '---'}</span>
                  </p>
                  <div className="pai-budget-chips">
                    <span className="pai-chip">حد صارم: −20</span>
                    <span className="pai-chip">إجراء الحظر: −35</span>
                    <span className="pai-chip" style={{ color: 'rgba(255,255,255,.3)' }}>
                      استخدام: {budget.utilization_pct ?? 0}%
                    </span>
                  </div>
                </div>
              </div>

              <div className="pai-panel pai-kpi-card" style={{ '--bk': '#818cf8' }}>
                <div className="pai-kpi-inner">
                  <div>
                    <div className="pai-kpi-lbl">النوايا التهديدية النشطة</div>
                    <div className="pai-kpi-val" style={{ color: '#818cf8' }}>{intents.length}</div>
                  </div>
                  <Crosshair size={36} style={{ opacity: .12, color: '#818cf8' }} />
                </div>
                <div className="pai-kpi-desc">المراحل الحالية المتوقعة التي تتطلب اتخاذ تدابير استباقية.</div>
              </div>

              <div className="pai-panel pai-kpi-card" style={{ '--bk': cfg.auto_apply_rl_policy ? '#28c76f' : '#64748b' }}>
                <div className="pai-kpi-inner">
                  <div>
                    <div className="pai-kpi-lbl">الإنفاذ الاستباقي التلقائي</div>
                    <div className="pai-kpi-val" style={{ color: cfg.auto_apply_rl_policy ? '#28c76f' : '#64748b' }}>
                      {cfg.auto_apply_rl_policy ? 'نشط' : 'مراقبة'}
                    </div>
                  </div>
                  <ShieldAlert size={36} style={{ opacity: .12, color: cfg.auto_apply_rl_policy ? '#28c76f' : '#64748b' }} />
                </div>
                <div className="pai-kpi-desc">
                  {cfg.auto_apply_rl_policy
                    ? 'وكيل RL يقوم بتغيير السياسات وتطبيقها تلقائياً.'
                    : 'إجراءات الوكيل تتطلب المراجعة البشرية أولاً.'}
                </div>
              </div>

              {tpe && tpe.threat_score != null && (
                <div className="pai-panel pai-panel--full" style={{ '--strip': '#ef4444' }}>
                  <div className="pai-panel-header">
                    <div className="pai-panel-title"><TrendingUp size={14} style={{ color: '#ef4444' }} /> نتيجة تقييم التهديد المسبق (TPE Stage 1)</div>
                    <span className={`pai-active-badge ${tpe.risk_level === 'HIGH' ? 'pai-active-badge--err' : tpe.risk_level === 'MEDIUM' ? 'pai-active-badge--warn' : 'pai-active-badge--on'}`}
                      style={tpe.risk_level === 'MEDIUM' ? { background: 'rgba(251,191,36,.1)', border: '1px solid rgba(251,191,36,.2)', color: '#fbbf24' } : {}}>
                      {typeof tpe.risk_level === 'object' ? JSON.stringify(tpe.risk_level) : tpe.risk_level}
                    </span>
                  </div>
                  <div className="pai-tpe-strip">
                    <div className="pai-tpe-kpi">
                      <div className="pai-tpe-kpi-lbl">نقاط الخطر</div>
                      <div className="pai-tpe-kpi-val pai-mono">{(Number(tpe.threat_score || 0) * 100).toFixed(1)}%</div>
                    </div>
                    <div className="pai-tpe-kpi">
                      <div className="pai-tpe-kpi-lbl">أسلوب الهجوم الأرجح</div>
                      <div className="pai-tpe-kpi-val" style={{ fontSize: '.8rem' }}>
                        {typeof tpe.most_likely_vector === 'object' ? (tpe.most_likely_vector?.name || tpe.most_likely_vector?.value || JSON.stringify(tpe.most_likely_vector)) : String(tpe.most_likely_vector ?? '—')}
                      </div>
                    </div>
                    <div className="pai-tpe-kpi">
                      <div className="pai-tpe-kpi-lbl">الجهة التهديدية</div>
                      <div className="pai-tpe-kpi-val" style={{ fontSize: '.8rem' }}>
                        {typeof tpe.most_likely_actor === 'object' ? (tpe.most_likely_actor?.name || JSON.stringify(tpe.most_likely_actor)) : String(tpe.most_likely_actor ?? '—')}
                      </div>
                    </div>
                    <div className="pai-tpe-kpi">
                      <div className="pai-tpe-kpi-lbl">TTPs المتوقعة</div>
                      <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginTop: 4 }}>
                        {(Array.isArray(tpe.expected_ttps) ? tpe.expected_ttps : []).map((t, i) => (
                          <span key={i} className="pai-stage-badge" style={{ fontSize: '.68rem' }}>
                            {typeof t === 'object' ? (t?.ttp || t?.name || t?.id || JSON.stringify(t)) : String(t)}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {Array.isArray(decoys) && decoys.length > 0 && (
                <div className="pai-panel pai-panel--full" style={{ '--strip': '#fbbf24' }}>
                  <div className="pai-panel-header">
                    <div className="pai-panel-title" style={{ color: '#fbbf24' }}>🪤 الفخاخ والمصائد النشطة (DIE)</div>
                    <span className="pai-count-pill">{decoys.length} فخ</span>
                  </div>
                  <div className="pai-decoy-grid">
                    {decoys.slice(0, 6).map((d, i) => (
                      <div key={i} className="pai-decoy-card">
                        <div className="pai-decoy-svc">{String(d.fake_service ?? 'UNKNOWN')} :{String(d.fake_port ?? '—')}</div>
                        <div className="pai-mono" dir="ltr" style={{ fontSize: '.75rem', color: 'rgba(255,255,255,.5)' }}>{String(d.decoy_ip ?? '—')}</div>
                        <div style={{ fontSize: '.7rem', color: 'rgba(255,255,255,.3)' }}>هدف: <span dir="ltr">{String(d.target_ip ?? d.src_ip ?? '—')}</span></div>
                        <div style={{ fontSize: '.7rem', color: 'rgba(255,255,255,.25)' }}>مرحلة: {typeof d.stage === 'object' ? JSON.stringify(d.stage) : String(d.stage ?? '—')}</div>
                        <div className="pai-decoy-hits">
                          {d.interaction_count ?? 0} تفاعل
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {Array.isArray(intents) && intents.length > 0 && (
                <div className="pai-panel pai-panel--full">
                  <div className="pai-panel-header">
                    <div className="pai-panel-title"><Activity size={14} style={{ color: '#fbbf24' }} /> أهم التنبيهات الاستباقية</div>
                  </div>
                  <div className="pai-intent-feed">
                    {intents.slice(0, 5).map((intent, idx) => {
                      const curStage = typeof intent.current_stage === 'object' ? (intent.current_stage?.name || JSON.stringify(intent.current_stage)) : String(intent.current_stage ?? '—');
                      const predNext = typeof intent.predicted_next === 'object' ? (intent.predicted_next?.name || JSON.stringify(intent.predicted_next)) : String(intent.predicted_next ?? '—');
                      const sev = typeof intent.severity === 'string' ? intent.severity : 'MEDIUM';
                      return (
                        <div key={idx} className="pai-intent-row">
                          <span className="pai-mono pai-intent-ip" dir="ltr">{String(intent.src_ip ?? '—')}</span>
                          <div className="pai-intent-stages">
                            <span className="pai-stage-badge">{curStage}</span>
                            <ArrowLeft size={13} style={{ opacity: .3 }} />
                            <span className={`pai-stage-badge pai-stage-badge--predicted ${sev === 'HIGH' ? 'pai-stage-badge--hi' : 'pai-stage-badge--mid'}`}>
                              {predNext}
                            </span>
                            <span className="pai-confidence">احتمالية {(Number(intent.confidence || 0) * 100).toFixed(0)}%</span>
                          </div>
                          <span className={`pai-sev ${(SEV_META[sev] || SEV_META.MEDIUM).cls}`}>
                            {(SEV_META[sev] || SEV_META.MEDIUM).label}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ── Intents / Killchain ── */}
          {tab === 'intents' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              {kcStats && Object.keys(kcStats).length > 0 && (
                <div className="pai-kcstats-row">
                  {[
                    { label: 'تقدم طبيعي', val: kcStats.forward_edges_pct, color: '#28c76f' },
                    { label: 'رجوع للخلف', val: kcStats.back_edges_pct, color: '#fbbf24' },
                    { label: 'قفز مراحل', val: kcStats.skip_edges_pct, color: '#ef4444' },
                  ].map((s, i) => (
                    <div key={i} className="pai-kc-stat-card">
                      <div className="pai-kc-stat-lbl">{s.label}</div>
                      <div className="pai-kc-stat-val pai-mono" style={{ color: s.color }}>{s.val ?? 0}%</div>
                    </div>
                  ))}
                  <div className="pai-kc-stat-card">
                    <div className="pai-kc-stat-lbl">مجموع الانتقالات</div>
                    <div className="pai-kc-stat-val pai-mono" style={{ color: '#818cf8' }}>{kcStats.total_transitions ?? 0}</div>
                  </div>
                </div>
              )}

              <div className="pai-panel">
                <div className="pai-panel-header">
                  <div className="pai-panel-title"><Layers size={14} /> مخطط سلسلة القتل الاحتمالي (Killchain Graph)</div>
                  <span className="pai-count-pill">عتبة {String(graphInfo.threshold ?? '—')}</span>
                </div>
                {graphInfo.available ? (
                  <div className="pai-table-wrap">
                    <table className="pai-table">
                      <thead>
                        <tr>
                          <th>الانتقال (أ ← ب)</th>
                          <th>الاحتمالية</th>
                          <th>الأحداث المرصودة</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(Array.isArray(graphInfo.top_edges) ? graphInfo.top_edges : []).map((edge, i) => (
                          <tr key={i} className="pai-row">
                            <td>
                              <div className="pai-edge-stages">
                                <span className="pai-stage-badge">{typeof edge.from === 'object' ? JSON.stringify(edge.from) : String(edge.from ?? '')}</span>
                                <ArrowLeft size={11} style={{ opacity: .25 }} />
                                <span className="pai-stage-badge">{typeof edge.to === 'object' ? JSON.stringify(edge.to) : String(edge.to ?? '')}</span>
                              </div>
                            </td>
                            <td>
                              <div className="pai-prob-cell">
                                <span className="pai-mono" style={{ color: '#818cf8' }} dir="ltr">
                                  {(Number(edge.probability || 0) * 100).toFixed(1)}%
                                </span>
                                <div className="pai-prob-track">
                                  <div className="pai-prob-fill" style={{ width: `${(Number(edge.probability || 0) * 100)}%` }} />
                                </div>
                              </div>
                            </td>
                            <td className="pai-mono" style={{ color: 'rgba(255,255,255,.4)' }}>{String(edge.observations ?? 0)}</td>
                          </tr>
                        ))}
                        {(!graphInfo.top_edges || !graphInfo.top_edges.length) && (
                          <tr><td colSpan={3}>
                            <div className="pai-empty"><Layers size={26} style={{ opacity: .08 }} /><span>لم يتم تحديد مسارات بعد.</span></div>
                          </td></tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="pai-unavail">محرك رسم مسارات الهجوم غير متصل أو قيد التهيئة.</div>
                )}
              </div>

              <div className="pai-panel">
                <div className="pai-panel-header">
                  <div className="pai-panel-title"><Target size={14} /> التنبؤ بنوايا المهاجمين (Intents)</div>
                  <span className="pai-count-pill">{intents.length} نوايا</span>
                </div>
                <div style={{ padding: '4px 0' }}>
                  {intents.length === 0 ? (
                    <div className="pai-empty"><Target size={26} style={{ opacity: .08 }} /><span>لا توجد نوايا تهديد نشطة حالياً.</span></div>
                  ) : intents.map((intent, i) => {
                    const sev = typeof intent.severity === 'string' ? intent.severity : 'MEDIUM';
                    const cmStr = typeof intent.countermeasure === 'object' && intent.countermeasure !== null
                      ? (intent.countermeasure.action || intent.countermeasure.name || JSON.stringify(intent.countermeasure))
                      : String(intent.countermeasure ?? '—');
                    return (
                      <div key={i} className="pai-intent-card">
                        <div className="pai-intent-card-left">
                          <div className="pai-mono" dir="ltr">{String(intent.src_ip ?? '—')}</div>
                          <span className={`pai-sev ${(SEV_META[sev] || SEV_META.MEDIUM).cls}`}>
                            {(SEV_META[sev] || SEV_META.MEDIUM).label}
                          </span>
                        </div>
                        <div className="pai-intent-card-right">
                          <div className="pai-intent-stages">
                            <div>
                              <div className="pai-xs-lbl">المرحلة الحالية</div>
                              <span className="pai-stage-badge">{typeof intent.current_stage === 'object' ? JSON.stringify(intent.current_stage) : String(intent.current_stage ?? '—')}</span>
                            </div>
                            <ArrowLeft size={14} style={{ opacity: .2 }} />
                            <div>
                              <div className="pai-xs-lbl">المرحلة المتوقعة</div>
                              <span className="pai-stage-badge pai-stage-badge--predicted pai-stage-badge--hi">{typeof intent.predicted_next === 'object' ? JSON.stringify(intent.predicted_next) : String(intent.predicted_next ?? '—')}</span>
                            </div>
                            <div>
                              <div className="pai-xs-lbl">الثقة</div>
                              <span className="pai-mono" style={{ fontWeight: 800, color: '#fbbf24' }} dir="ltr">{(Number(intent.confidence || 0) * 100).toFixed(1)}%</span>
                            </div>
                          </div>
                          <div className="pai-countermeasure">
                            <div className="pai-cm-lbl">التدبير المضاد المقترح</div>
                            <div className="pai-cm-text">{cmStr}</div>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}

          {/* ── AEGIS Decisions ── */}
          {tab === 'decisions' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div className="pai-panel">
                <div className="pai-panel-header">
                  <div className="pai-panel-title"><Eye size={14} style={{ color: '#818cf8' }} /> قرارات محرك AEGIS الحي (آخر 30)</div>
                  <span className="pai-count-pill">{decisions.length} قرار</span>
                </div>
                {decLoading ? (
                  <div className="pai-empty"><RefreshCw size={26} className="pai-spin" style={{ opacity: .3 }} /><span>تحميل القرارات...</span></div>
                ) : (!Array.isArray(decisions) || decisions.length === 0) ? (
                  <div className="pai-empty"><Eye size={26} style={{ opacity: .08 }} /><span>لم يتم تسجيل قرارات AEGIS بعد. ستظهر تلقائياً عند معالجة الأحداث.</span></div>
                ) : (
                  <div style={{ padding: '6px 0' }}>
                    {decisions.slice().reverse().map((dec, i) => (
                      <DecisionRow key={i} dec={dec} />
                    ))}
                  </div>
                )}
              </div>

              {AEGISHealth?.health && typeof AEGISHealth.health === 'object' && (
                <div className="pai-panel" style={{ '--strip': '#28c76f' }}>
                  <div className="pai-panel-header">
                    <div className="pai-panel-title"><Network size={14} style={{ color: '#28c76f' }} /> تشخيص محرك AEGIS</div>
                  </div>
                  <div className="pai-health-grid">
                    {Object.entries(AEGISHealth.health).map(([key, val], i) => (
                      <div key={i} className="pai-health-item">
                        <div className="pai-health-key">{key}</div>
                        <div className="pai-health-val pai-mono">{typeof val === 'object' ? JSON.stringify(val).slice(0, 60) : String(val)}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ── Safety audit ── */}
          {tab === 'safety' && (
            <div className="pai-panel">
              <div className="pai-panel-header">
                <div className="pai-panel-title"><ShieldCheck size={14} /> مسار تدقيق طبقة السلامة (RL Safety Layer)</div>
                <ShieldCheck size={20} style={{ opacity: .15, color: '#28c76f' }} />
              </div>
              <div className="pai-table-wrap">
                <table className="pai-table">
                  <thead>
                    <tr>
                      <th>وقت التنفيذ</th>
                      <th>الهدف</th>
                      <th>اقتراح RL</th>
                      <th>قرار الحاجز</th>
                      <th>الوزن الصافي</th>
                      <th>السبب</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(!Array.isArray(auditLogs) || auditLogs.length === 0) && (
                      <tr><td colSpan={6}>
                        <div className="pai-empty"><ShieldCheck size={26} style={{ opacity: .08 }} /><span>لم يتم تسجيل قرارات RL حديثاً.</span></div>
                      </td></tr>
                    )}
                    {(Array.isArray(auditLogs) ? auditLogs : []).map((log, i) => {
                      const propStr = typeof log.proposed === 'object' && log.proposed !== null ? (log.proposed.action || JSON.stringify(log.proposed)) : String(log.proposed ?? '—');
                      const apprStr = typeof log.approved === 'object' && log.approved !== null ? (log.approved.action || JSON.stringify(log.approved)) : String(log.approved ?? '—');
                      const reasonStr = typeof log.reason === 'object' && log.reason !== null ? JSON.stringify(log.reason) : String(log.reason ?? '');
                      return (
                        <tr key={i} className={`pai-row ${log.constrained ? 'pai-row--warn' : ''}`}>
                          <td>
                            <span className="pai-mono" style={{ fontSize: '.72rem', color: 'rgba(255,255,255,.3)' }} dir="ltr">
                              {fmtTs(log.timestamp)}
                            </span>
                          </td>
                          <td>
                            <div className="pai-mono" style={{ color: 'rgba(255,255,255,.65)' }} dir="ltr">{String(log.target_ip ?? '—')}</div>
                            <div style={{ fontSize: '.68rem', color: 'rgba(255,255,255,.22)', textTransform: 'uppercase' }}>{String(log.target_type ?? '')}</div>
                          </td>
                          <td><span className="pai-stage-badge" dir="ltr">{propStr}</span></td>
                          <td>
                            {log.constrained ? (
                              <div style={{ display: 'flex', alignItems: 'center', gap: 5, color: '#fbbf24', fontWeight: 700, fontSize: '.8rem' }}>
                                <ShieldAlert size={13} /> {apprStr}
                              </div>
                            ) : (
                              <div style={{ display: 'flex', alignItems: 'center', gap: 5, color: '#28c76f', fontWeight: 700, fontSize: '.8rem' }}>
                                <CheckCircle2 size={13} /> {apprStr}
                              </div>
                            )}
                          </td>
                          <td>
                            <span className="pai-mono" style={{ fontWeight: 800, color: (Number(log.net_reward || 0)) < 0 ? '#ff5f5f' : '#28c76f' }} dir="ltr">
                              {(Number(log.net_reward || 0)) > 0 ? '+' : ''}{Number(log.net_reward || 0).toFixed(2)}
                            </span>
                          </td>
                          <td style={{ fontSize: '.78rem', color: 'rgba(255,255,255,.3)' }}>
                            {log.requires_human
                              ? <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: '#60a5fa' }}><UserCheck size={13} /> التدقيق البشري مطلوب</span>
                              : reasonStr}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ── Historical Logs ── */}
          {tab === 'logs' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div className="pai-tabs" style={{ width: 'fit-content' }}>
                {[
                  { id: 'decisions', label: 'قرارات AEGIS', icon: Eye },
                  { id: 'intent', label: 'سجل النوايا', icon: Target },
                  { id: 'decoy', label: 'سجل الفخاخ', icon: ShieldAlert },
                ].map(t => {
                  const Icon = t.icon;
                  return (
                    <button
                      key={t.id}
                      className={`pai-tab ${logsTab === t.id ? 'pai-tab--active' : ''}`}
                      onClick={() => setLogsTab(t.id)}
                      style={{ fontSize: '.8rem' }}
                    >
                      <Icon size={13} /> {t.label}
                    </button>
                  );
                })}
              </div>

              {logsTab === 'decisions' && (
                <div className="pai-panel">
                  <div className="pai-panel-header">
                    <div className="pai-panel-title"><Database size={14} /> قرارات AEGIS من قاعدة البيانات</div>
                    <span className="pai-count-pill">{logDecisions?.count ?? 0} سجل</span>
                  </div>
                  <div className="pai-table-wrap">
                    <table className="pai-table">
                      <thead>
                        <tr><th>الوقت</th><th>IP</th><th>الحدث</th><th>الاستراتيجية</th><th>فخ</th></tr>
                      </thead>
                      <tbody>
                        {(logDecisions?.logs ?? []).length === 0 && (
                          <tr><td colSpan={5}><div className="pai-empty"><Database size={26} style={{ opacity: .08 }} /><span>لا توجد سجلات في قاعدة البيانات بعد.</span></div></td></tr>
                        )}
                        {(logDecisions?.logs ?? []).map((l, i) => {
                          const stratStr = typeof l.counter_strategy === 'object' && l.counter_strategy !== null ? (l.counter_strategy.action || JSON.stringify(l.counter_strategy)) : String(l.counter_strategy ?? '—');
                          return (
                            <tr key={i} className="pai-row">
                              <td><span className="pai-mono" dir="ltr" style={{ fontSize: '.72rem', color: 'rgba(255,255,255,.3)' }}>{fmtIso(l.timestamp)}</span></td>
                              <td><span className="pai-mono" dir="ltr" style={{ color: '#818cf8' }}>{String(l.src_ip ?? '—')}</span></td>
                              <td><span className="pai-stage-badge" style={{ fontSize: '.7rem' }}>{typeof l.event_type === 'object' ? JSON.stringify(l.event_type) : String(l.event_type ?? '—')}</span></td>
                              <td><span className="pai-stage-badge pai-stage-badge--predicted" style={{ fontSize: '.7rem' }}>{stratStr}</span></td>
                              <td>{l.decoy_deployed ? <span style={{ color: '#fbbf24' }}>🪤</span> : '—'}</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {logsTab === 'intent' && (
                <div className="pai-panel">
                  <div className="pai-panel-header">
                    <div className="pai-panel-title"><Target size={14} /> سجل توقعات النوايا من قاعدة البيانات</div>
                    <span className="pai-count-pill">{logIntent?.count ?? 0} سجل</span>
                  </div>
                  <div className="pai-table-wrap">
                    <table className="pai-table">
                      <thead>
                        <tr><th>الوقت</th><th>IP</th><th>TTP المتوقع</th><th>الثقة</th><th>الإجراء</th></tr>
                      </thead>
                      <tbody>
                        {(logIntent?.logs ?? []).length === 0 && (
                          <tr><td colSpan={5}><div className="pai-empty"><Target size={26} style={{ opacity: .08 }} /><span>لا توجد سجلات.</span></div></td></tr>
                        )}
                        {(logIntent?.logs ?? []).map((l, i) => {
                          const predTtp = typeof l.predicted_ttp === 'object' && l.predicted_ttp !== null ? (l.predicted_ttp.ttp || l.predicted_ttp.name || JSON.stringify(l.predicted_ttp)) : String(l.predicted_ttp ?? '—');
                          const actStr = typeof l.action === 'object' && l.action !== null ? (l.action.action || JSON.stringify(l.action)) : String(l.action ?? '—');
                          return (
                            <tr key={i} className="pai-row">
                              <td><span className="pai-mono" dir="ltr" style={{ fontSize: '.72rem', color: 'rgba(255,255,255,.3)' }}>{fmtIso(l.timestamp)}</span></td>
                              <td><span className="pai-mono" dir="ltr" style={{ color: '#818cf8' }}>{String(l.src_ip ?? '—')}</span></td>
                              <td><span className="pai-stage-badge" style={{ fontSize: '.7rem' }}>{predTtp}</span></td>
                              <td><span className="pai-mono" dir="ltr" style={{ color: '#fbbf24' }}>{((Number(l.confidence || 0)) * 100).toFixed(1)}%</span></td>
                              <td><span className="pai-stage-badge pai-stage-badge--predicted" style={{ fontSize: '.7rem' }}>{actStr}</span></td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {logsTab === 'decoy' && (
                <div className="pai-panel">
                  <div className="pai-panel-header">
                    <div className="pai-panel-title"><ShieldAlert size={14} style={{ color: '#fbbf24' }} /> سجل الفخاخ والمصائد من قاعدة البيانات</div>
                    <span className="pai-count-pill">{logDecoy?.count ?? 0} سجل</span>
                  </div>
                  <div className="pai-table-wrap">
                    <table className="pai-table">
                      <thead>
                        <tr><th>الوقت</th><th>IP المهاجم</th><th>الخدمة الوهمية</th><th>IP الوهمي</th><th>المرحلة</th><th>التفاعلات</th><th>منتهي</th></tr>
                      </thead>
                      <tbody>
                        {(logDecoy?.logs ?? []).length === 0 && (
                          <tr><td colSpan={7}><div className="pai-empty"><ShieldAlert size={26} style={{ opacity: .08 }} /><span>لا توجد سجلات فخاخ.</span></div></td></tr>
                        )}
                        {(logDecoy?.logs ?? []).map((l, i) => (
                          <tr key={i} className="pai-row">
                            <td><span className="pai-mono" dir="ltr" style={{ fontSize: '.72rem', color: 'rgba(255,255,255,.3)' }}>{fmtIso(l.timestamp)}</span></td>
                            <td><span className="pai-mono" dir="ltr" style={{ color: '#818cf8' }}>{String(l.src_ip ?? '—')}</span></td>
                            <td><span className="pai-stage-badge" style={{ fontSize: '.7rem', color: '#fbbf24' }}>{String(l.fake_service ?? '')}:{String(l.fake_port ?? '')}</span></td>
                            <td><span className="pai-mono" dir="ltr" style={{ fontSize: '.72rem' }}>{String(l.decoy_ip ?? '—')}</span></td>
                            <td><span style={{ fontSize: '.72rem', color: 'rgba(255,255,255,.4)' }}>{typeof l.stage === 'object' ? JSON.stringify(l.stage) : String(l.stage ?? '—')}</span></td>
                            <td><span className="pai-mono" style={{ color: (l.interaction_count || 0) > 0 ? '#ef4444' : 'rgba(255,255,255,.3)' }}>{l.interaction_count ?? 0}</span></td>
                            <td>{l.is_expired ? <span style={{ color: 'rgba(255,255,255,.25)' }}>✓</span> : <span style={{ color: '#28c76f' }}>●</span>}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ── Models / Settings ── */}
          {tab === 'models' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              {ueba && Object.keys(ueba).length > 0 && (
                <div className="pai-panel" style={{ '--strip': '#818cf8' }}>
                  <div className="pai-panel-header">
                    <div className="pai-panel-title"><UserCheck size={14} style={{ color: '#818cf8' }} /> مقاييس UEBA (تحليل سلوك الكيانات)</div>
                    <span className="pai-active-badge pai-active-badge--on" style={{ background: 'rgba(129,140,248,.1)', border: '1px solid rgba(129,140,248,.2)', color: '#818cf8' }}>
                      نشط
                    </span>
                  </div>
                  <div className="pai-ueba-grid">
                    {Object.entries(ueba).map(([key, val], i) => (
                      <div key={i} className="pai-ueba-kpi">
                        <div className="pai-ueba-kpi-lbl">{key.replace(/_/g, ' ')}</div>
                        <div className="pai-ueba-kpi-val pai-mono">
                          {typeof val === 'number' ? (Number.isInteger(val) ? val : (val * 100).toFixed(1) + '%') : String(val)}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="pai-panel" style={{ '--strip': '#fbbf24' }}>
                <div className="pai-panel-header">
                  <div className="pai-panel-title"><Key size={14} /> التكوين البحثي العام</div>
                </div>
                {TOGGLES.map(f => {
                  const active = cfg[f.id];
                  return (
                    <div key={f.id} className={`pai-setting-row ${active ? 'pai-setting-row--on' : ''}`}>
                      <div>
                        <div className="pai-setting-key" style={active ? { color: '#fbbf24' } : {}}>{f.label}</div>
                        <div className="pai-setting-desc">{f.desc}</div>
                      </div>
                      <label className="pai-switch">
                        <input type="checkbox" checked={!!active}
                          onChange={() => updateMut.mutate({ ...cfg, [f.id]: !active })} />
                        <span className="pai-switch-track" />
                      </label>
                    </div>
                  );
                })}
              </div>

              {/* Autonomous Response Level & AEGIS Calibration */}
              <div className="pai-panel" style={{ '--strip': '#06b6d4' }}>
                <div className="pai-panel-header">
                  <div className="pai-panel-title"><ShieldAlert size={14} /> مستوى الاستجابة التلقائية ومعايرة AEGIS</div>
                </div>
                <div className="pai-setting-row">
                  <div>
                    <div className="pai-setting-key">مستوى الاستجابة التنبؤية الذاتية</div>
                    <div className="pai-setting-desc">تحديد مستوى تدخل الذكاء الاصطناعي في إغلاق المنافذ وعزل الأهداف تلقائياً</div>
                  </div>
                  <div style={{ display: 'flex', gap: 6 }}>
                    {[
                      { val: 'OFF', label: 'إيقاف (OFF)', color: '#64748b' },
                      { val: 'ADVISORY', label: 'استشاري (ADVISORY)', color: '#f59e0b' },
                      { val: 'AUTONOMOUS', label: 'تلقائي (AUTONOMOUS)', color: '#ef4444' }
                    ].map(lvl => (
                      <button
                        key={lvl.val}
                        onClick={() => updateMut.mutate({ ...cfg, autonomous_response_level: lvl.val })}
                        style={{
                          padding: '6px 12px',
                          borderRadius: '6px',
                          fontSize: '0.78rem',
                          fontWeight: 700,
                          cursor: 'pointer',
                          background: (cfg.autonomous_response_level === lvl.val) ? `${lvl.color}26` : 'rgba(255,255,255,0.04)',
                          border: `1px solid ${(cfg.autonomous_response_level === lvl.val) ? lvl.color : 'rgba(255,255,255,0.1)'}`,
                          color: (cfg.autonomous_response_level === lvl.val) ? lvl.color : '#aaa'
                        }}
                      >
                        {lvl.label}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="pai-setting-row">
                  <div>
                    <div className="pai-setting-key">عتبة ثقة AEGIS للإنذار الاستباقي</div>
                    <div className="pai-setting-desc">الحد الأدنى لاحتمالية التنبؤ بحدوث هجوم قبل تفعيل التدابير الوقائية</div>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                    <span className="pai-mono" style={{ color: '#06b6d4', fontWeight: 800 }}>
                      {((cfg.AEGIS_confidence_threshold ?? 0.85) * 100).toFixed(0)}%
                    </span>
                    <input
                      type="range" min={50} max={99} step={1}
                      value={(cfg.AEGIS_confidence_threshold ?? 0.85) * 100}
                      onChange={e => updateMut.mutate({ ...cfg, AEGIS_confidence_threshold: e.target.value / 100 })}
                      style={{ cursor: 'pointer' }}
                    />
                  </div>
                </div>
              </div>

              <div className="pai-panel">
                <div className="pai-panel-header">
                  <div className="pai-panel-title"><Cpu size={14} /> نماذج التعلم الآلي المُحمَّلة</div>
                  <span className="pai-count-pill">{models.length} نماذج</span>
                </div>
                {models.length === 0 ? (
                  <div className="pai-empty"><Brain size={26} style={{ opacity: .08 }} /><span>لا توجد نماذج محملة.</span></div>
                ) : (
                  <div style={{ padding: '8px 0' }}>
                    {models.map(model => (
                      <div key={model.id} className="pai-model-row">
                        <div className="pai-model-info">
                          <div className="pai-model-name-row">
                            <span className="pai-model-name">{model.name}</span>
                            <ModelBadge status={model.status} />
                          </div>
                          <div className="pai-model-desc">{model.description}</div>
                        </div>
                        <div className="pai-model-right">
                          <div className="pai-model-date" dir="ltr">آخر تحديث: {fmtDate(model.last_updated)}</div>
                          <label className="pai-upload-btn">
                            <input type="file" style={{ display: 'none' }}
                              onChange={e => { const f = e.target.files[0]; if (f) { setUploading(model.id); uploadMut.mutate({ id: model.id, file: f }); } }}
                              accept={model.supported_extensions?.join(',')} />
                            {uploading === model.id
                              ? <><RefreshCw size={13} className="pai-spin" /> جاري الرفع...</>
                              : <><Upload size={13} /> تحديث النموذج</>}
                          </label>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </motion.div>
      </AnimatePresence>
    </div>
  );
}
