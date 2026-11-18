import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Globe, Settings, Plus, RefreshCw, Zap, CheckCircle2, ShieldAlert } from 'lucide-react';
import { useHTTPInspection } from './hooks/useHTTPInspection';
import { PatternsTable } from './components/PatternsTable';
import { HttpLogs } from './components/HttpLogs';
import './HTTPInspection.css';

const TABS = [
  { id: 'patterns', label: 'أنماط المطابقة', icon: Globe },
  { id: 'logs',     label: 'سجلات الهجمات',   icon: Globe },
  { id: 'config',   label: 'الإعدادات',       icon: Settings },
];

const SIGNATURE_PRESETS = [
  { target: 'url', pattern: '(?i)(\\bunion\\b.*\\bselect\\b|\\bselect\\b.*\\bfrom\\b|\' OR \'1\'=\'1|exec\\s*\\()', severity: 'HIGH', description: 'كشف محاولات حقن SQL (SQL Injection)' },
  { target: 'url', pattern: '(?i)(<script.*?>|javascript:|onload\\s*=|onerror\\s*=)', severity: 'HIGH', description: 'كشف هجمات السكريبتات الخبيثة (Cross-Site Scripting)' },
  { target: 'url', pattern: '(\\.\\.\\/|\\.\\.\\\\|%2e%2e%2f|%2e%2e\\/)', severity: 'HIGH', description: 'كشف محاولات تخطي المسارات (Directory Traversal)' },
  { target: 'body', pattern: '(?i)(;\\s*(cat|ls|whoami|id|bash|nc|curl|wget)\\b|\\|\\||\\&\\&)', severity: 'HIGH', description: 'كشف حقن أوامر النظام (Command Injection)' },
  { target: 'header', pattern: '\\(\\)\\s*\\{\\s*:;\\s*\\};\\s*', severity: 'HIGH', description: 'كشف ثغرة Shellshock في الترويسات' },
];

export default function HTTPInspection() {
  const [tab, setTab] = useState('patterns');
  const [form, setForm] = useState({ target: 'url', pattern: '', severity: 'MEDIUM', description: '' });
  const [showPresetsModal, setShowPresetsModal] = useState(false);
  const [toast, setToast] = useState(null);

  const {
    patterns,
    patternsLoading,
    refetchPatterns,
    config,
    configLoading,
    refetchConfig,
    logs,
    logsLoading,
    refetchLogs,
    updateConfig,
    addPattern,
    deletePattern,
    updatePattern
  } = useHTTPInspection();

  // Controlled states for config inputs
  const cfg = config ?? {};
  const [maxUploadMb, setMaxUploadMb] = useState(cfg.max_upload_size_mb || 10);
  const [cacheTtlSec, setCacheTtlSec] = useState(cfg.cache_ttl_seconds ?? 5);

  useEffect(() => {
    if (cfg.max_upload_size_mb !== undefined) setMaxUploadMb(cfg.max_upload_size_mb);
    if (cfg.cache_ttl_seconds !== undefined) setCacheTtlSec(cfg.cache_ttl_seconds);
  }, [cfg.max_upload_size_mb, cfg.cache_ttl_seconds]);

  const showToastMsg = (msg, type = 'success') => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3000);
  };

  const set = k => e => setForm(f => ({ ...f, [k]: e.target.value }));

  const handleAddPattern = () => {
    if (!form.pattern.trim()) return;
    addPattern(form).then(() => {
      setForm({ target: 'url', pattern: '', severity: 'MEDIUM', description: '' });
      showToastMsg('تم إضافة نمط المطابقة بنجاح');
    }).catch(err => {
      showToastMsg('فشل إضافة النمط: ' + (err.message || 'خطأ غير معروف'), 'error');
    });
  };

  const handleAddPreset = (preset) => {
    addPattern(preset).then(() => {
      showToastMsg(`تم تحميل النمط الجاهز: ${preset.description}`);
    }).catch(err => {
      showToastMsg('تعذر إضافة النمط: ' + (err.message || 'خطأ'), 'error');
    });
  };

  const handleAddAllPresets = async () => {
    let addedCount = 0;
    for (const preset of SIGNATURE_PRESETS) {
      const exists = patterns.some(p => p.pattern === preset.pattern);
      if (!exists) {
        await addPattern(preset);
        addedCount++;
      }
    }
    showToastMsg(`تم نشر ${addedCount} نمط حماية جاهز في القاعدة`);
    setShowPresetsModal(false);
  };

  const handleSaveMaxUpload = (val) => {
    const parsed = parseInt(val) || 10;
    setMaxUploadMb(parsed);
    updateConfig({ ...cfg, max_upload_size_mb: parsed }).then(() => {
      showToastMsg('تم تحديث حد حجم الفحص');
    });
  };

  const handleSaveCacheTtl = (val) => {
    const parsed = parseInt(val) || 5;
    setCacheTtlSec(parsed);
    updateConfig({ ...cfg, cache_ttl_seconds: parsed }).then(() => {
      showToastMsg('تم تحديث مدة بقاء الكاش');
    });
  };

  const CONFIG_TOGGLES = [
    { id: 'is_active',              label: 'المفتاح الرئيسي لفحص HTTP',    desc: 'تفعيل الفحص العميق الشامل لحركة مرور HTTP' },
    { id: 'block_dangerous_methods',label: 'حظر الطرق (Methods) الخطرة',   desc: 'الحظر التلقائي لطلبات مثل PUT وDELETE وTRACE' },
    { id: 'scan_headers',           label: 'فحص الترويسات',                 desc: 'فحص ترويسات الطلبات والاستجابات لاكتشاف التهديدات' },
    { id: 'scan_body',              label: 'فحص جسم الطلب',                 desc: 'فحص بيانات POST للبحث عن تطابق الأنماط الخبيثة' },
    { id: 'inspect_tls',            label: 'تفتيش حركة المرور المشفرة (TLS Inspection)', desc: 'فك وفحص الحزم المشفرة عبر وكيل الشهادات' },
    { id: 'verify_certificates',    label: 'التحقق من صحة شهادات SSL/TLS', desc: 'تدقيق صلاحية الشهادات الرقمية للخوادم والعملاء' },
    { id: 'block_invalid_certs',    label: 'حظر الشهادات غير الصالحة أو المنتهية', desc: 'إسقاط الاتصال فوراً عند اكتشاف شهادة غير موثوقة' },
  ];

  return (
    <div className="http-root" dir="rtl">

      {/* Toast notification */}
      {toast && (
        <div className={`http-toast ${toast.type === 'error' ? 'http-toast--error' : 'http-toast--success'}`}>
          {toast.type === 'error' ? <ShieldAlert size={14} /> : <CheckCircle2 size={14} />}
          <span>{toast.msg}</span>
        </div>
      )}

      {/* ── Hero ── */}
      <div className="http-hero">
        <div className="http-hero-glow" />
        <div className="http-hero-inner">
          <div className="http-hero-left">
            <div className="http-hero-icon">
              <Globe size={26} style={{ color: '#818cf8' }} />
            </div>
            <div>
              <h1 className="http-hero-title">فحص HTTP العميق</h1>
              <p className="http-hero-sub">Deep Payload Analysis · Header Sanitization · Regex Pattern Matching</p>
            </div>
          </div>
          <div className="http-hero-right">
            <button
              className="http-btn http-btn--ghost"
              onClick={() => {
                refetchPatterns();
                refetchConfig();
                refetchLogs();
                showToastMsg('تم تحديث البيانات من السيرفر');
              }}
              title="تحديث البيانات يدويًا"
            >
              <RefreshCw size={13} /> تحديث
            </button>
            <span className={`http-status-pill ${cfg.is_active ? 'http-status-pill--on' : 'http-status-pill--off'}`}>
              <span className="http-status-dot" />
              {cfg.is_active ? 'الفحص نشط' : 'الفحص معطل'}
            </span>
            <div className="http-stat-chips">
              <div className="http-stat-chip">
                <span className="http-stat-n" style={{ color: '#818cf8' }}>{patterns?.length ?? 0}</span>
                <span className="http-stat-l">نمط نشط</span>
              </div>
              <div className="http-stat-chip">
                <span className="http-stat-n" style={{ color: '#ff5f5f' }}>
                  {patterns?.filter(p => p.severity === 'HIGH').length ?? 0}
                </span>
                <span className="http-stat-l">خطورة عالية</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ── Tabs ── */}
      <div className="http-tabs">
        {TABS.map(t => {
          return (
            <button
              key={t.id}
              className={`http-tab ${tab === t.id ? 'http-tab--active' : ''}`}
              onClick={() => setTab(t.id)}
            >
              {t.label}
            </button>
          );
        })}
      </div>

      <AnimatePresence mode="wait">
        <motion.div
          key={tab}
          initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }}
          transition={{ duration: .18 }}
        >

          {/* ══ PATTERNS ══ */}
          {tab === 'patterns' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>

              {/* Add form */}
              <div className="http-panel">
                <div className="http-panel-header" style={{ justifyContent: 'space-between' }}>
                  <div className="http-panel-title"><Plus size={14} /> إنشاء نمط مطابقة جديد</div>
                  <button
                    className="http-btn http-btn--preset"
                    onClick={() => setShowPresetsModal(true)}
                  >
                    <Zap size={13} style={{ color: '#fbbf24' }} /> حزمة الأنماط الجاهزة (Presets)
                  </button>
                </div>

                <div className="http-add-form">
                  <select className="http-select" value={form.target} onChange={set('target')}>
                    <option value="url">مسار URL</option>
                    <option value="header">ترويسة HTTP</option>
                    <option value="body">جسم الطلب (Body)</option>
                  </select>
                  <input
                    className="http-input http-input--flex"
                    dir="ltr"
                    placeholder="نمط Regex (مثال: \.\.\/\.\.\/)"
                    value={form.pattern}
                    onChange={set('pattern')}
                  />
                  <input
                    className="http-input http-input--flex"
                    placeholder="وصف مختصر للنمط (اختياري)"
                    value={form.description}
                    onChange={set('description')}
                  />
                  <select className="http-select" value={form.severity} onChange={set('severity')}>
                    <option value="HIGH">خطورة عالية</option>
                    <option value="MEDIUM">خطورة متوسطة</option>
                    <option value="LOW">خطورة منخفضة</option>
                  </select>
                  <button
                    className="http-btn http-btn--primary"
                    onClick={handleAddPattern}
                    disabled={!form.pattern.trim()}
                  >
                    <Plus size={13} /> إضافة
                  </button>
                </div>
              </div>

              {/* Table */}
              <PatternsTable
                patterns={patterns}
                isLoading={patternsLoading}
                updatePattern={(args) => updatePattern(args).then(() => showToastMsg('تم تحديث حالة النمط'))}
                deletePattern={(id) => deletePattern(id).then(() => showToastMsg('تم حذف النمط'))}
              />
            </div>
          )}

          {/* ══ LOGS ══ */}
          {tab === 'logs' && (
            <HttpLogs logs={logs} logsLoading={logsLoading} />
          )}

          {/* ══ CONFIG ══ */}
          {tab === 'config' && (
            <div className="http-panel">
              <div className="http-panel-header">
                <div className="http-panel-title"><Settings size={14} /> إعدادات محرك الفحص</div>
              </div>

              {CONFIG_TOGGLES.map(f => {
                const active = !!cfg[f.id];
                return (
                  <div key={f.id} className={`http-setting-row ${active ? 'http-setting-row--on' : ''}`}>
                    <div>
                      <div className="http-setting-key" style={active ? { color: '#818cf8' } : {}}>{f.label}</div>
                      <div className="http-setting-desc">{f.desc}</div>
                    </div>
                    <label className="http-switch">
                      <input type="checkbox" checked={active}
                        onChange={() => updateConfig({ ...cfg, [f.id]: !active }).then(() => showToastMsg(`تم تغيير ${f.label}`))} />
                      <span className="http-switch-track" />
                    </label>
                  </div>
                );
              })}

              {/* Max upload size */}
              <div className="http-setting-row">
                <div>
                  <div className="http-setting-key">الحد الأقصى لحجم الفحص</div>
                  <div className="http-setting-desc">استبعاد الملفات التي تتجاوز هذا الحجم لحماية الذاكرة</div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <input
                    className="http-input http-input--num"
                    type="number" dir="ltr"
                    value={maxUploadMb}
                    onChange={e => setMaxUploadMb(e.target.value)}
                    onBlur={e => handleSaveMaxUpload(e.target.value)}
                  />
                  <span style={{ fontSize: '.8rem', color: 'rgba(255,255,255,.25)', fontFamily: 'Fira Code,monospace' }}>MB</span>
                </div>
              </div>

              {/* Inspection Mode */}
              <div className="http-setting-row">
                <div>
                  <div className="http-setting-key">وضعية التشغيل (Mode)</div>
                  <div className="http-setting-desc">تحديد ما إذا كان سيتم اعتراض الهجمات أو تسجيلها فقط (Enforce vs Monitor)</div>
                </div>
                <div>
                  <select
                    className="http-select"
                    value={cfg.mode || 'enforce'}
                    onChange={e => updateConfig({ ...cfg, mode: e.target.value }).then(() => showToastMsg('تم تغيير وضعية التشغيل'))}
                  >
                    <option value="enforce">الحظر الفوري (Enforce)</option>
                    <option value="monitor">المراقبة والتسجيل (Monitor)</option>
                  </select>
                </div>
              </div>

              {/* Cache TTL */}
              <div className="http-setting-row">
                <div>
                  <div className="http-setting-key">مدة بقاء الكاش (Cache TTL)</div>
                  <div className="http-setting-desc">مدة صلاحية الأنماط المخزنة مؤقتاً بالثواني قبل إعادة التحميل من قاعدة البيانات</div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <input
                    className="http-input http-input--num"
                    type="number" dir="ltr"
                    value={cacheTtlSec}
                    onChange={e => setCacheTtlSec(e.target.value)}
                    onBlur={e => handleSaveCacheTtl(e.target.value)}
                  />
                  <span style={{ fontSize: '.8rem', color: 'rgba(255,255,255,.25)', fontFamily: 'Fira Code,monospace' }}>ثوانٍ</span>
                </div>
              </div>
            </div>
          )}
        </motion.div>
      </AnimatePresence>

      {/* Presets Modal */}
      {showPresetsModal && (
        <div className="http-modal-backdrop" onClick={() => setShowPresetsModal(false)}>
          <div className="http-modal-card" onClick={e => e.stopPropagation()}>
            <div className="http-modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontWeight: 800, fontSize: '1rem', color: '#f0f0f5' }}>
                <Zap size={18} style={{ color: '#fbbf24' }} /> أنماط حماية HTTP القياسية (OWASP Top 10)
              </div>
              <button className="http-modal-close" onClick={() => setShowPresetsModal(false)}>✕</button>
            </div>

            <div className="http-modal-body">
              <p style={{ fontSize: '0.82rem', color: 'rgba(255,255,255,0.4)', marginBottom: 14 }}>
                يمكنك إضافة هذه الأنماط المعدة مسبقًا لتفعيل حماية فورية ضد أهم الثغرات الشائعة:
              </p>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {SIGNATURE_PRESETS.map((p, idx) => {
                  const isAlreadyAdded = patterns.some(existing => existing.pattern === p.pattern);
                  return (
                    <div key={idx} className="http-preset-item">
                      <div style={{ flex: 1 }}>
                        <div style={{ fontWeight: 700, fontSize: '0.85rem', color: '#f0f0f5', marginBottom: 2 }}>{p.description}</div>
                        <div className="http-mono" style={{ fontSize: '0.75rem', color: '#818cf8' }} dir="ltr">{p.pattern}</div>
                      </div>
                      <button
                        className="http-btn http-btn--ghost"
                        style={{ padding: '6px 12px', fontSize: '0.78rem' }}
                        disabled={isAlreadyAdded}
                        onClick={() => handleAddPreset(p)}
                      >
                        {isAlreadyAdded ? 'مُضاف مسبقاً ✔' : '+ إضافة'}
                      </button>
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="http-modal-footer">
              <button className="http-btn http-btn--primary" onClick={handleAddAllPresets}>
                إضافة كافة الأنماط غير المضافة تلقائيًا
              </button>
              <button className="http-btn http-btn--ghost" onClick={() => setShowPresetsModal(false)}>
                إغلاق
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}

