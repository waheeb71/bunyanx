import { useState } from 'react';
import { Settings, SlidersHorizontal, Brain, Shield, Link, Paperclip, Mail, Filter, Zap } from 'lucide-react';

/* ── Scanner toggles ──────────────────────────────────────────────── */
const SCANNERS = [
  { key: 'phishing',          label: 'كاشف التصيّد الاحتيالي (ML/NLP)',  desc: 'يكتشف أنماط الاستعجال، تزييف العلامات التجارية، والانحرافات المعجمية.', color: '#818cf8' },
  { key: 'url_scanner',       label: 'فاحص الروابط الخبيثة',              desc: 'يتحقق من الروابط ضد استخبارات التهديدات وخدمات تقصير الروابط.',            color: '#fbbf24' },
  { key: 'spam_filter',       label: 'فلتر البريد المزعج (ثنائي اللغة)',  desc: 'يحدد الكلمات المفتاحية للـ Spam، النصوص المخفية، وألاعيب الكتابة.',        color: '#f97316' },
  { key: 'attachment_guard',  label: 'حارس المرفقات',                      desc: 'يحظر الملفات القابلة للتنفيذ ويقيس الملفات المضغوطة ذات الإنتروبيا العالية.', color: '#ff5f5f' },
  { key: 'sender_reputation', label: 'سمعة المُرسل',                       desc: 'يتحقق من DMARC وSPF والنطاقات البريدية المؤقتة.',                             color: '#28c76f' },
  { key: 'plsf_config',       label: 'محرك التحليل النفسي اللغوي (PLSF)',  desc: 'يكتشف انتحال الشخصية (BEC) والتوليد الآلي للرسائل بالذكاء الاصطناعي.',    color: '#a78bfa' },
  { key: 'vsde_config',       label: 'محرك التزامن البصري الدلالي (VSDE)', desc: 'يكتشف محاولات إخفاء النصوص وتهريب الـ HTML/CSS.',                            color: '#fb923c' },
];

/* ── Global risk thresholds ───────────────────────────────────────── */
const GLOBAL_THRESHOLDS = [
  { key: 'allow',      label: 'السماح إذا أقل من', desc: 'يُسلَّم البريد بشكل طبيعي.',           color: '#28c76f' },
  { key: 'quarantine', label: 'العزل عند',          desc: 'يُوجَّه إلى مجلد Spam/العزل.',          color: '#fbbf24' },
  { key: 'block',      label: 'حظر صارم عند',       desc: 'يُرفض فوراً بواسطة SMTP 550 REJECT.',  color: '#ff5f5f' },
];

/* ── Numeric field helper ─────────────────────────────────────────── */
function NumField({ label, desc, value, step = 0.05, min = 0, max = 1, color = '#818cf8', onChange }) {
  return (
    <div className="em-thresh-row">
      <div>
        <div className="em-thresh-key" style={{ color }}>{label}</div>
        {desc && <div className="em-thresh-desc">{desc}</div>}
      </div>
      <input
        type="number"
        className="em-input em-input-sm"
        step={step} min={min} max={max} dir="ltr"
        defaultValue={value ?? ''}
        key={value}
        onBlur={e => {
          const v = parseFloat(e.target.value);
          if (!isNaN(v)) onChange(v);
        }}
        style={{ color, fontWeight: 700, borderColor: `${color}33` }}
      />
    </div>
  );
}

/* ── Collapsible advanced section ─────────────────────────────────── */
function AdvancedSection({ title, color, children }) {
  const [open, setOpen] = useState(false);
  return (
    <div style={{ marginTop: 4 }}>
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          background: 'none', border: 'none', cursor: 'pointer',
          color: `${color}bb`, fontSize: '.72rem', fontFamily: 'Fira Code, monospace',
          padding: '4px 0', display: 'flex', alignItems: 'center', gap: 4,
        }}
      >
        <span style={{ transition: 'transform .2s', transform: open ? 'rotate(90deg)' : 'none', display: 'inline-block' }}>▶</span>
        {open ? 'إخفاء' : 'إعدادات متقدمة'} — {title}
      </button>
      {open && (
        <div style={{
          borderLeft: `2px solid ${color}33`, marginLeft: 8, paddingLeft: 12,
          marginTop: 4, display: 'flex', flexDirection: 'column', gap: 4,
        }}>
          {children}
        </div>
      )}
    </div>
  );
}

/* ══════════════════════════════════════════════════════════════════ */
export default function EmailSettings({ config, updateConfig, resetConfig }) {
  const mutate    = (key, val)           => updateConfig.mutate({ [key]: val });
  const mutateSub = (section, key, val) => {
    const updated = { ...(config[section] || {}), [key]: val };
    updateConfig.mutate({ [section]: updated });
  };

  const ph  = config.phishing          || {};
  const us  = config.url_scanner       || {};
  const ag  = config.attachment_guard  || {};
  const sr  = config.sender_reputation || {};
  const sf  = config.spam_filter       || {};
  const sc  = config.smtp_commands     || {};
  const thr = config.thresholds        || {};
  const rs  = config.risk_scoring      || {};
  const pl  = config.plsf_config       || {};
  const vs  = config.vsde_config       || {};

  return (
    <div className="em-settings-body">

      {/* ── Policy ───────────────────────────────────────────────── */}
      <div className="em-section-card" style={{ '--strip': '#818cf8' }}>
        <div className="em-panel-header">
          <div className="em-panel-title"><Settings size={14} /> سياسة التطبيق</div>
        </div>
        <div className="em-section-body">
          <div className="em-setting-row">
            <div>
              <div className="em-setting-key">وضع الفحص</div>
              <div className="em-setting-desc">Enforce يحظر فعلياً — Monitor يسجل فقط — Learning يتعلم بصمت</div>
            </div>
            <select
              className="em-select"
              value={config.mode || 'monitor'}
              onChange={e => mutate('mode', e.target.value)}
            >
              <option value="enforce">تطبيق الحظر (Enforce)</option>
              <option value="monitor">مراقبة فقط (Monitor)</option>
              <option value="learning">وضع التعلم (Learning)</option>
            </select>
          </div>

          <div className="em-setting-row">
            <div>
              <div className="em-setting-key">المنافذ المُراقبة</div>
              <div className="em-setting-desc">POP3 · IMAP · SMTP — مفصولة بفاصلة</div>
            </div>
            <input
              className="em-input em-ports-input"
              dir="ltr"
              defaultValue={config.monitored_ports?.join(', ')}
              onBlur={e => mutate('monitored_ports', e.target.value.split(',').map(s => parseInt(s.trim())).filter(Boolean))}
              placeholder="25, 587, 465, 143, 993"
            />
          </div>
        </div>
      </div>

      {/* ── AI Scanner engines (toggles) ──────────────────────────── */}
      <div className="em-section-card" style={{ '--strip': '#28c76f' }}>
        <div className="em-panel-header">
          <div className="em-panel-title"><Brain size={14} /> محركات الكشف بالذكاء الاصطناعي</div>
          <span style={{ fontSize: '.72rem', color: 'rgba(255,255,255,0.25)', fontFamily: 'Fira Code, monospace' }}>
            {SCANNERS.filter(s => config[s.key]?.enabled).length}/{SCANNERS.length} نشط
          </span>
        </div>
        <div className="em-section-body">
          {SCANNERS.map(({ key, label, desc, color }) => {
            const enabled = !!config[key]?.enabled;
            return (
              <div
                key={key}
                className={`em-setting-row ${enabled ? 'em-setting-row--active' : ''}`}
                style={enabled ? { borderRight: `2px solid ${color}` } : {}}
              >
                <div>
                  <div className="em-setting-key-hi" style={{ color: enabled ? color : 'rgba(255,255,255,0.55)' }}>
                    {label}
                  </div>
                  <div className="em-setting-desc">{desc}</div>
                </div>
                <label className="em-switch">
                  <input
                    type="checkbox"
                    checked={enabled}
                    onChange={() => mutateSub(key, 'enabled', !enabled)}
                    style={{ '--sc': color }}
                  />
                  <span
                    className="em-switch-track"
                    style={enabled ? { background: color, borderColor: color, boxShadow: `0 0 10px ${color}44` } : {}}
                  />
                </label>
              </div>
            );
          })}
        </div>
      </div>

      {/* ── Global Risk Thresholds ────────────────────────────────── */}
      <div className="em-section-card" style={{ '--strip': '#fbbf24' }}>
        <div className="em-panel-header">
          <div className="em-panel-title"><SlidersHorizontal size={14} /> عتبات تقييم الخطر الإجمالية (0.00 – 1.00)</div>
        </div>
        <div className="em-section-body">
          {GLOBAL_THRESHOLDS.map(({ key, label, desc, color }) => (
            <NumField key={key} label={label} desc={desc} color={color}
              value={thr[key]}
              onChange={v => mutateSub('thresholds', key, v)}
            />
          ))}
        </div>
      </div>

      {/* ── Per-Scanner Override Thresholds ──────────────────────── */}
      <div className="em-section-card" style={{ '--strip': '#a78bfa' }}>
        <div className="em-panel-header">
          <div className="em-panel-title"><Zap size={14} /> عتبات التجاوز لكل محرك (Override)</div>
          <span style={{ fontSize: '.70rem', color: 'rgba(255,255,255,0.22)', fontFamily: 'Fira Code, monospace' }}>risk_scoring</span>
        </div>
        <div className="em-section-body">
          <NumField label="حظر فوري — التصيّد (phishing_block)" color="#818cf8"
            desc="إذا تجاوزت درجة التصيّد هذه القيمة يُحظر البريد فوراً"
            value={rs.phishing_block_threshold ?? 0.70}
            onChange={v => mutateSub('risk_scoring', 'phishing_block_threshold', v)}
          />
          <NumField label="عزل — التصيّد (phishing_quarantine)" color="#818cf8"
            value={rs.phishing_quarantine_threshold ?? 0.40}
            onChange={v => mutateSub('risk_scoring', 'phishing_quarantine_threshold', v)}
          />
          <NumField label="حظر فوري — روابط خبيثة (url_block)" color="#fbbf24"
            value={rs.url_block_threshold ?? 0.70}
            onChange={v => mutateSub('risk_scoring', 'url_block_threshold', v)}
          />
          <NumField label="عزل — روابط مشبوهة (url_quarantine)" color="#fbbf24"
            value={rs.url_quarantine_threshold ?? 0.40}
            onChange={v => mutateSub('risk_scoring', 'url_quarantine_threshold', v)}
          />
          <NumField label="عزل — مرفق مشبوه (attachment_quarantine)" color="#ff5f5f"
            value={rs.attachment_quarantine_threshold ?? 0.40}
            onChange={v => mutateSub('risk_scoring', 'attachment_quarantine_threshold', v)}
          />
          <NumField label="حظر — تهريب بصري VSDE (vsde_block)" color="#fb923c" step={0.01}
            desc="عتبة Jaccard desync ratio R الموصى بها: 0.35"
            value={rs.vsde_block_threshold ?? 0.35}
            onChange={v => mutateSub('risk_scoring', 'vsde_block_threshold', v)}
          />
          <NumField label="عزل — انتحال PLSF λ_opt (plsf_quarantine)" color="#a78bfa" step={0.01}
            desc="عتبة Youden's J المُعايَرة من الورقة البحثية (الموصى بها: 0.442)"
            value={rs.plsf_quarantine_threshold ?? 0.442}
            onChange={v => mutateSub('risk_scoring', 'plsf_quarantine_threshold', v)}
          />
          <NumField label="حظر — انتحال PLSF عالي الثقة (plsf_block)" color="#a78bfa" step={0.01}
            value={rs.plsf_block_threshold ?? 0.70}
            onChange={v => mutateSub('risk_scoring', 'plsf_block_threshold', v)}
          />
        </div>
      </div>

      {/* ── Phishing Advanced ─────────────────────────────────────── */}
      <div className="em-section-card" style={{ '--strip': '#818cf8' }}>
        <div className="em-panel-header">
          <div className="em-panel-title"><Shield size={14} /> كاشف التصيّد — معاملات التسجيل</div>
          <span style={{ fontSize: '.70rem', color: 'rgba(255,255,255,0.22)', fontFamily: 'Fira Code, monospace' }}>phishing</span>
        </div>
        <div className="em-section-body">
          <NumField label="وزن الكلمات المفتاحية (keyword_weight)" color="#818cf8"
            value={ph.keyword_weight ?? 0.40} onChange={v => mutateSub('phishing', 'keyword_weight', v)} />
          <NumField label="وزن الاستعجال (urgency_weight)" color="#818cf8"
            value={ph.urgency_weight ?? 0.25} onChange={v => mutateSub('phishing', 'urgency_weight', v)} />
          <NumField label="وزن انتحال العلامة التجارية (spoof_weight)" color="#818cf8"
            value={ph.spoof_weight ?? 0.25} onChange={v => mutateSub('phishing', 'spoof_weight', v)} />
          <AdvancedSection title="phishing" color="#818cf8">
            <NumField label="درجة الاستعجال لكل إشارة (urgency_score_per_hit)" color="#818cf8" step={0.01}
              value={ph.urgency_score_per_hit ?? 0.20} onChange={v => mutateSub('phishing', 'urgency_score_per_hit', v)} />
            <NumField label="حد درجة الاستعجال (urgency_score_cap)" color="#818cf8" step={0.01}
              value={ph.urgency_score_cap ?? 0.60} onChange={v => mutateSub('phishing', 'urgency_score_cap', v)} />
            <NumField label="درجة انتحال العلامة التجارية (spoof_score_value)" color="#818cf8" step={0.01}
              value={ph.spoof_score_value ?? 0.70} onChange={v => mutateSub('phishing', 'spoof_score_value', v)} />
            <NumField label="عتبة الحظر الصارم (phishing_hard_threshold)" color="#ff5f5f" step={0.01}
              value={ph.phishing_hard_threshold ?? 0.70} onChange={v => mutateSub('phishing', 'phishing_hard_threshold', v)} />
            <NumField label="عتبة الاشتباه (phishing_soft_threshold)" color="#fbbf24" step={0.01}
              value={ph.phishing_soft_threshold ?? 0.40} onChange={v => mutateSub('phishing', 'phishing_soft_threshold', v)} />
          </AdvancedSection>
        </div>
      </div>

      {/* ── URL Scanner Advanced ──────────────────────────────────── */}
      <div className="em-section-card" style={{ '--strip': '#fbbf24' }}>
        <div className="em-panel-header">
          <div className="em-panel-title"><Link size={14} /> فاحص الروابط — درجات الإشارات</div>
          <span style={{ fontSize: '.70rem', color: 'rgba(255,255,255,0.22)', fontFamily: 'Fira Code, monospace' }}>url_scanner</span>
        </div>
        <div className="em-section-body">
          <NumField label="درجة رابط IP مباشر (score_ip_literal)" color="#fbbf24"
            value={us.score_ip_literal ?? 0.50} onChange={v => mutateSub('url_scanner', 'score_ip_literal', v)} />
          <NumField label="درجة مختصر الروابط (score_shortener)" color="#fbbf24"
            value={us.score_shortener ?? 0.30} onChange={v => mutateSub('url_scanner', 'score_shortener', v)} />
          <NumField label="درجة TLD مشبوه (score_suspicious_tld)" color="#fbbf24"
            value={us.score_suspicious_tld ?? 0.30} onChange={v => mutateSub('url_scanner', 'score_suspicious_tld', v)} />
          <AdvancedSection title="url_scanner" color="#fbbf24">
            <NumField label="درجة نطاقات فرعية مفرطة (score_excessive_subdomains)" color="#fbbf24" step={0.01}
              value={us.score_excessive_subdomains ?? 0.20} onChange={v => mutateSub('url_scanner', 'score_excessive_subdomains', v)} />
            <NumField label="درجة رابط طويل جداً (score_very_long_url)" color="#fbbf24" step={0.01}
              value={us.score_very_long_url ?? 0.10} onChange={v => mutateSub('url_scanner', 'score_very_long_url', v)} />
            <NumField label="درجة HTTP بدون HTTPS (score_no_https)" color="#fbbf24" step={0.01}
              value={us.score_no_https ?? 0.10} onChange={v => mutateSub('url_scanner', 'score_no_https', v)} />
            <NumField label="وزن استخبارات التهديدات (threat_intel_weight)" color="#fbbf24" step={0.01}
              value={us.threat_intel_weight ?? 0.50} onChange={v => mutateSub('url_scanner', 'threat_intel_weight', v)} />
            <NumField label="غرامة عدد روابط مفرط (excessive_url_penalty)" color="#fbbf24" step={0.01}
              value={us.excessive_url_penalty ?? 0.20} onChange={v => mutateSub('url_scanner', 'excessive_url_penalty', v)} />
          </AdvancedSection>
        </div>
      </div>

      {/* ── Attachment Guard Advanced ─────────────────────────────── */}
      <div className="em-section-card" style={{ '--strip': '#ff5f5f' }}>
        <div className="em-panel-header">
          <div className="em-panel-title"><Paperclip size={14} /> حارس المرفقات — درجات الإشارات</div>
          <span style={{ fontSize: '.70rem', color: 'rgba(255,255,255,0.22)', fontFamily: 'Fira Code, monospace' }}>attachment_guard</span>
        </div>
        <div className="em-section-body">
          <NumField label="درجة امتداد خطير (score_dangerous_ext_blocked)" color="#ff5f5f"
            value={ag.score_dangerous_ext_blocked ?? 1.00} onChange={v => mutateSub('attachment_guard', 'score_dangerous_ext_blocked', v)} />
          <NumField label="درجة امتداد مشبوه (score_suspicious_ext)" color="#f97316"
            value={ag.score_suspicious_ext ?? 0.40} onChange={v => mutateSub('attachment_guard', 'score_suspicious_ext', v)} />
          <NumField label="عتبة الإنتروبيا (entropy_threshold)" color="#ff5f5f" step={0.01}
            value={ag.entropy_threshold ?? 0.92} onChange={v => mutateSub('attachment_guard', 'entropy_threshold', v)} />
          <AdvancedSection title="attachment_guard" color="#ff5f5f">
            <NumField label="درجة إنتروبيا عالية (score_high_entropy)" color="#ff5f5f" step={0.01}
              value={ag.score_high_entropy ?? 0.35} onChange={v => mutateSub('attachment_guard', 'score_high_entropy', v)} />
            <NumField label="درجة عدم تطابق MIME (score_mime_mismatch)" color="#ff5f5f" step={0.01}
              value={ag.score_mime_mismatch ?? 0.30} onChange={v => mutateSub('attachment_guard', 'score_mime_mismatch', v)} />
            <NumField label="درجة حجم مفرط (score_oversized)" color="#ff5f5f" step={0.01}
              value={ag.score_oversized ?? 0.20} onChange={v => mutateSub('attachment_guard', 'score_oversized', v)} />
            <NumField label="عتبة الحظر الفوري (action_block_threshold)" color="#ff5f5f" step={0.01}
              value={ag.action_block_threshold ?? 0.80} onChange={v => mutateSub('attachment_guard', 'action_block_threshold', v)} />
            <NumField label="عتبة التعليم (action_flag_threshold)" color="#fbbf24" step={0.01}
              value={ag.action_flag_threshold ?? 0.40} onChange={v => mutateSub('attachment_guard', 'action_flag_threshold', v)} />
          </AdvancedSection>
        </div>
      </div>

      {/* ── Sender Reputation Advanced ────────────────────────────── */}
      <div className="em-section-card" style={{ '--strip': '#28c76f' }}>
        <div className="em-panel-header">
          <div className="em-panel-title"><Mail size={14} /> سمعة المُرسل — درجات الإشارات</div>
          <span style={{ fontSize: '.70rem', color: 'rgba(255,255,255,0.22)', fontFamily: 'Fira Code, monospace' }}>sender_reputation</span>
        </div>
        <div className="em-section-body">
          <NumField label="درجة فشل SPF (score_spf_fail)" color="#ff5f5f"
            value={sr.score_spf_fail ?? 0.40} onChange={v => mutateSub('sender_reputation', 'score_spf_fail', v)} />
          <NumField label="درجة SPF softfail (score_spf_softfail)" color="#fbbf24"
            value={sr.score_spf_softfail ?? 0.20} onChange={v => mutateSub('sender_reputation', 'score_spf_softfail', v)} />
          <NumField label="درجة غياب DKIM (score_no_dkim)" color="#fbbf24" step={0.01}
            value={sr.score_no_dkim ?? 0.15} onChange={v => mutateSub('sender_reputation', 'score_no_dkim', v)} />
          <AdvancedSection title="sender_reputation" color="#28c76f">
            <NumField label="درجة DKIM غير صالح (score_dkim_invalid)" color="#ff5f5f" step={0.01}
              value={sr.score_dkim_invalid ?? 0.35} onChange={v => mutateSub('sender_reputation', 'score_dkim_invalid', v)} />
            <NumField label="درجة DMARC=none (score_dmarc_none)" color="#fbbf24" step={0.01}
              value={sr.score_dmarc_none ?? 0.10} onChange={v => mutateSub('sender_reputation', 'score_dmarc_none', v)} />
            <NumField label="درجة نطاق مؤقت (score_disposable)" color="#ff5f5f" step={0.01}
              value={sr.score_disposable ?? 0.50} onChange={v => mutateSub('sender_reputation', 'score_disposable', v)} />
            <NumField label="وزن سمعة IP (ip_reputation_weight)" color="#28c76f" step={0.01}
              value={sr.ip_reputation_weight ?? 0.40} onChange={v => mutateSub('sender_reputation', 'ip_reputation_weight', v)} />
            <NumField label="مهلة DNS (dns_timeout_seconds)" color="#28c76f" step={0.5} min={0.5} max={10}
              value={sr.dns_timeout_seconds ?? 2.0} onChange={v => mutateSub('sender_reputation', 'dns_timeout_seconds', v)} />
          </AdvancedSection>
        </div>
      </div>

      {/* ── Spam Filter Advanced ──────────────────────────────────── */}
      <div className="em-section-card" style={{ '--strip': '#f97316' }}>
        <div className="em-panel-header">
          <div className="em-panel-title"><Filter size={14} /> فلتر البريد المزعج — معاملات التسجيل</div>
          <span style={{ fontSize: '.70rem', color: 'rgba(255,255,255,0.22)', fontFamily: 'Fira Code, monospace' }}>spam_filter</span>
        </div>
        <div className="em-section-body">
          <NumField label="وزن الكلمات المفتاحية (kw_weight)" color="#f97316"
            value={sf.kw_weight ?? 0.50} onChange={v => mutateSub('spam_filter', 'kw_weight', v)} />
          <NumField label="وزن الأحرف الكبيرة (caps_weight)" color="#f97316"
            value={sf.caps_weight ?? 0.20} onChange={v => mutateSub('spam_filter', 'caps_weight', v)} />
          <NumField label="وزن علامات الترقيم المفرطة (punct_weight)" color="#f97316"
            value={sf.punct_weight ?? 0.15} onChange={v => mutateSub('spam_filter', 'punct_weight', v)} />
          <NumField label="وزن النص المخفي (hidden_weight)" color="#f97316"
            value={sf.hidden_weight ?? 0.15} onChange={v => mutateSub('spam_filter', 'hidden_weight', v)} />
          <AdvancedSection title="spam_filter" color="#f97316">
            <NumField label="درجة كل حرف كبير (caps_score_per_hit)" color="#f97316" step={0.01}
              value={sf.caps_score_per_hit ?? 0.08} onChange={v => mutateSub('spam_filter', 'caps_score_per_hit', v)} />
            <NumField label="حد درجة الأحرف الكبيرة (caps_score_cap)" color="#f97316" step={0.01}
              value={sf.caps_score_cap ?? 0.30} onChange={v => mutateSub('spam_filter', 'caps_score_cap', v)} />
            <NumField label="درجة نص مخفي لكل إشارة (hidden_score_per_hit)" color="#f97316" step={0.01}
              value={sf.hidden_score_per_hit ?? 0.15} onChange={v => mutateSub('spam_filter', 'hidden_score_per_hit', v)} />
            <NumField label="درجة بادئة موضوع Spam (spam_subject_prefix_score)" color="#f97316" step={0.01}
              value={sf.spam_subject_prefix_score ?? 0.30} onChange={v => mutateSub('spam_filter', 'spam_subject_prefix_score', v)} />
            <NumField label="درجة HTML مفرط بلا نص (minimal_text_html_score)" color="#f97316" step={0.01}
              value={sf.minimal_text_html_score ?? 0.15} onChange={v => mutateSub('spam_filter', 'minimal_text_html_score', v)} />
          </AdvancedSection>
        </div>
      </div>

      {/* ── Preprocessing ─────────────────────────────────────────── */}
      <div className="em-section-card" style={{ '--strip': '#06b6d4' }}>
        <div className="em-panel-header">
          <div className="em-panel-title"><Settings size={14} /> المعالجة المسبقة (Preprocessing)</div>
        </div>
        <div className="em-section-body">
          {[
            { key: 'decode_base64_body',     label: 'فك ترميز Base64',             desc: 'فك ترميز نص البريد المُشفَّر بـ Base64 قبل الفحص' },
            { key: 'decode_quoted_printable', label: 'فك ترميز Quoted-Printable',  desc: 'فك ترميز النصوص المُشفَّرة بـ QP' },
            { key: 'extract_plain_text',      label: 'استخراج النص الخام',          desc: 'استخراج النص الصريح من HTML لتحليله' },
          ].map(({ key, label, desc }) => (
            <div key={key} className="em-setting-row">
              <div>
                <div className="em-setting-key">{label}</div>
                <div className="em-setting-desc">{desc}</div>
              </div>
              <label className="em-switch">
                <input
                  type="checkbox"
                  checked={config.preprocessing?.[key] ?? true}
                  onChange={e => mutateSub('preprocessing', key, e.target.checked)}
                  style={{ '--sc': '#06b6d4' }}
                />
                <span className="em-switch-track" />
              </label>
            </div>
          ))}
          <NumField label="الحجم الأقصى للجسم (max_body_bytes)" color="#06b6d4" step={65536} min={65536} max={5242880}
            desc="الحجم الأقصى لجسم البريد الذي يُعالَج (بالبايت)"
            value={config.preprocessing?.max_body_bytes ?? 524288}
            onChange={v => mutateSub('preprocessing', 'max_body_bytes', v)}
          />
        </div>
      </div>

      {/* ── Actions ───────────────────────────────────────────────── */}
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 8 }}>
        <button
          onClick={() => {
            if (window.confirm('هل أنت متأكد من إعادة ضبط جميع الإعدادات إلى القيم الافتراضية للنظام؟')) {
              resetConfig.mutate();
            }
          }}
          disabled={resetConfig.isPending}
          style={{
            background: 'rgba(255,95,95,0.1)',
            border: '1px solid rgba(255,95,95,0.2)',
            color: '#ff5f5f',
            fontSize: '.8rem',
            padding: '8px 16px',
            borderRadius: '8px',
            cursor: 'pointer',
          }}
        >
          إعادة تعيين الإعدادات الافتراضية
        </button>
      </div>

    </div>
  );
}
