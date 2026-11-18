import React from 'react';
import { Settings, Activity, CheckCircle2, XCircle, ShieldAlert, RefreshCw, Info } from 'lucide-react';

export function SettingsPanel({
  config,
  configLoading,
  status,
  statusLoading,
  updateConfig,
  trainModel,
  trainingModel
}) {
  if (configLoading || statusLoading) return (
    <div className="wf-loading"><RefreshCw size={18} className="wf-spin" /> جاري تحميل الإعدادات...</div>
  );

  const SettingRow = ({ label, desc, children }) => (
    <div className="wf-setting-row">
      <div>
        <div className="wf-setting-key">{label}</div>
        {desc && <div className="wf-setting-desc">{desc}</div>}
      </div>
      <div className="wf-setting-ctrl">{children}</div>
    </div>
  );

  const ml = status.ml_analytics || {};
  const isMlOnline = ml.engine_status === 'ONLINE';
  const hasModel = ml.last_trained && ml.last_trained !== 'Never';

  return (
    <div className="wf-settings-body">
      <div className="wf-panel">
        <div className="wf-panel-header">
          <div className="wf-panel-title"><Settings size={15} /> إعدادات المحرك العامة</div>
        </div>

        <SettingRow label="تفعيل الوحدة" desc="المفتاح الرئيسي لتشغيل أو إيقاف محرك تصفية الويب">
          <label className="wf-switch">
            <input type="checkbox" checked={config.enabled ?? false}
              onChange={e => updateConfig({ enabled: e.target.checked })} />
            <span className="wf-switch-track" />
          </label>
        </SettingRow>

        <SettingRow
          label="وضع التطبيق"
          desc="المراقبة تسجل الأحداث فقط — التطبيق يقوم بحظر وإسقاط حركة المرور فعلياً."
        >
          <select className="wf-select" value={config.mode || 'monitor'}
            onChange={e => updateConfig({ mode: e.target.value })}>
            <option value="monitor">مراقبة فقط (Monitor)</option>
            <option value="enforce">تطبيق الحظر (Enforce)</option>
          </select>
        </SettingRow>

        <SettingRow
          label="البحث الآمن التلقائي (Safe Search)"
          desc="إجبار تفعيل البحث الآمن في Google وBing وDuckDuckGo"
        >
          <label className="wf-switch">
            <input type="checkbox" checked={config.safe_search_enabled ?? false}
              onChange={e => updateConfig({ safe_search_enabled: e.target.checked })} />
            <span className="wf-switch-track" />
          </label>
        </SettingRow>

        <SettingRow
          label="الإجراء الافتراضي للروابط غير المصنفة"
          desc="ماذا يحدث للنطاقات التي لا تندرج تحت أي تصنيف أو قاعدة تجاوز؟"
        >
          <select className="wf-select" value={config.default_action || 'ALLOW'}
            onChange={e => updateConfig({ default_action: e.target.value })}>
            <option value="ALLOW">سماح وتمرير (Allow)</option>
            <option value="BLOCK">حظر وإسقاط (Block)</option>
          </select>
        </SettingRow>

        <SettingRow label="الحد الأقصى للذاكرة المخبئية" desc="الحد الأقصى لعدد النطاقات المحفوظة في ذاكرة الكاش السريعة">
          <input
            type="number"
            className="wf-select"
            style={{ width: '100px', textAlign: 'center' }}
            value={config.cache?.max_size ?? 50000}
            onChange={e => updateConfig({ cache: { ...(config.cache || {}), max_size: parseInt(e.target.value) || 0 } })}
          />
        </SettingRow>

        <SettingRow label="وقت صلاحية ذاكرة الكاش (TTL)" desc="الوقت بالثواني قبل إعادة التحقق من النطاقات في الكاش">
          <input
            type="number"
            className="wf-select"
            style={{ width: '100px', textAlign: 'center' }}
            value={config.cache?.ttl_seconds ?? 300}
            onChange={e => updateConfig({ cache: { ...(config.cache || {}), ttl_seconds: parseInt(e.target.value) || 0 } })}
          />
        </SettingRow>
      </div>

      {/* HoloFilter AI Panel */}
      <div className="wf-panel">
        <div className="wf-panel-header">
          <div className="wf-panel-title"><Activity size={15} /> إعدادات وتليميتري الذكاء الاصطناعي (HoloFilter AI)</div>
        </div>

        <SettingRow label="حالة محرك AI" desc="حالة تشغيل محرك التصنيف بالتعلم الآلي عالي الأبعاد">
          <span className={`wf-status-badge ${isMlOnline ? 'wf-status-badge--on' : 'wf-status-badge--off'}`}>
            {isMlOnline ? <CheckCircle2 size={12} /> : <XCircle size={12} />}
            {isMlOnline ? 'متصل (ONLINE)' : 'غير متصل (OFFLINE)'}
          </span>
        </SettingRow>

        <SettingRow label="مؤشر صحة النموذج" desc="حالة ملف المتجهات وجاهزية النموذج للتنبؤ الفوري">
          {hasModel ? (
            <span className="wf-status-badge wf-status-badge--on">
              <CheckCircle2 size={12} />
              جاهز ومثبت
            </span>
          ) : (
            <span className="wf-status-badge wf-status-badge--off" style={{ background: 'rgba(239, 68, 68, 0.1)', borderColor: '#ef4444', color: '#ef4444' }}>
              <ShieldAlert size={12} />
              نموذج مفقود / غير مدرب
            </span>
          )}
        </SettingRow>

        <SettingRow label="تفعيل فحص الذكاء الاصطناعي" desc="استخدام نموذج الحوسبة فائقة الأبعاد لتصنيف النطاقات غير المعروفة">
          <label className="wf-switch">
            <input type="checkbox" checked={config.ai_holofilter?.enabled ?? true}
              onChange={e => updateConfig({ ai_holofilter: { ...(config.ai_holofilter || {}), enabled: e.target.checked } })} />
            <span className="wf-switch-track" />
          </label>
        </SettingRow>

        <SettingRow label="حد الخطر للحظر (Threshold)" desc="الحد الأدنى لنسبة تقييم الخطر لحجب النطاق تلقائياً (0 - 100)">
          <input
            type="number"
            className="wf-select"
            style={{ width: '100px', textAlign: 'center' }}
            min="0"
            max="100"
            value={config.ai_holofilter?.action_threshold_score ?? 70}
            onChange={e => updateConfig({
              ai_holofilter: {
                ...(config.ai_holofilter || {}),
                action_threshold_score: parseInt(e.target.value) || 0
              }
            })}
          />
        </SettingRow>

        <SettingRow label="انحياز النموذج (Sigmoid Bias)" desc="قيمة الانحياز لضبط دالة التفعيل غير الخطية للنموذج">
          <input
            type="number"
            step="0.1"
            className="wf-select"
            style={{ width: '100px', textAlign: 'center' }}
            value={config.ai_holofilter?.bias ?? -3.5}
            onChange={e => updateConfig({
              ai_holofilter: {
                ...(config.ai_holofilter || {}),
                bias: parseFloat(e.target.value) || 0
              }
            })}
          />
        </SettingRow>

        <SettingRow label="أوزان النموذج (Weights)" desc="الأوزان لعائلات النطاقات المختلفة (DGA, Phish, Benign)">
          <div style={{ display: 'flex', gap: '12px' }}>
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
              <span style={{ fontSize: '11px', color: '#888', marginBottom: '4px' }}>DGA</span>
              <input
                type="number"
                step="0.1"
                className="wf-select"
                style={{ width: '70px', textAlign: 'center' }}
                value={config.ai_holofilter?.weights?.w_dga ?? 12.0}
                onChange={e => updateConfig({
                  ai_holofilter: {
                    ...(config.ai_holofilter || {}),
                    weights: { ...(config.ai_holofilter?.weights || {}), w_dga: parseFloat(e.target.value) || 0 }
                  }
                })}
              />
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
              <span style={{ fontSize: '11px', color: '#888', marginBottom: '4px' }}>Phish</span>
              <input
                type="number"
                step="0.1"
                className="wf-select"
                style={{ width: '70px', textAlign: 'center' }}
                value={config.ai_holofilter?.weights?.w_phish ?? 8.0}
                onChange={e => updateConfig({
                  ai_holofilter: {
                    ...(config.ai_holofilter || {}),
                    weights: { ...(config.ai_holofilter?.weights || {}), w_phish: parseFloat(e.target.value) || 0 }
                  }
                })}
              />
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
              <span style={{ fontSize: '11px', color: '#888', marginBottom: '4px' }}>Benign</span>
              <input
                type="number"
                step="0.1"
                className="wf-select"
                style={{ width: '70px', textAlign: 'center' }}
                value={config.ai_holofilter?.weights?.w_benign ?? 15.0}
                onChange={e => updateConfig({
                  ai_holofilter: {
                    ...(config.ai_holofilter || {}),
                    weights: { ...(config.ai_holofilter?.weights || {}), w_benign: parseFloat(e.target.value) || 0 }
                  }
                })}
              />
            </div>
          </div>
        </SettingRow>

        <SettingRow label="أبعاد فضاء المتجهات" desc="عدد أبعاد الـ Hypervector المستخدمة لتمثيل النطاقات">
          <span className="wf-mono" style={{ color: '#aaa', fontSize: '13px' }}>{ml.vector_dimensions || 10048} ديسيبل</span>
        </SettingRow>

        <SettingRow label="آخر تدريب للنموذج" desc="تاريخ ووقت آخر تحديث لملف المتجهات offline_hv.npz">
          <span className="wf-mono" style={{ color: '#aaa', fontSize: '13px' }}>{ml.last_trained || 'Never'}</span>
        </SettingRow>

        <div className="wf-setting-row" style={{ borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: '16px' }}>
          <div>
            <div className="wf-setting-key">إعادة تدريب النموذج</div>
            <div className="wf-setting-desc">تحديث النموذج وتدريبه على أحدث النطاقات الضارة والمسموحة بالخلفية</div>
          </div>
          <div className="wf-setting-ctrl">
            <button
              className="wf-btn wf-btn--primary wf-btn--sm"
              disabled={trainingModel}
              onClick={() => trainModel()}
            >
              {trainingModel ? <><RefreshCw size={13} className="wf-spin" /> جاري التدريب...</> : <><RefreshCw size={13} /> تدريب النموذج الآن</>}
            </button>
          </div>
        </div>
      </div>

      {/* DNS Sinkhole & Logging Panel */}
      <div className="wf-panel">
        <div className="wf-panel-header">
          <div className="wf-panel-title"><ShieldAlert size={15} /> إعدادات حوض بالوعة النطاقات والتسجيل (DNS Sinkhole & Logging)</div>
        </div>

        <SettingRow
          label="تفعيل إعادة التوجيه إلى Sinkhole"
          desc="توجيه استعلامات النطاقات المحظورة إلى عنوان الـ Sinkhole بدلاً من رفضها بصمت"
        >
          <label className="wf-switch">
            <input type="checkbox" checked={config.dns_sinkhole?.enabled ?? true}
              onChange={e => updateConfig({ dns_sinkhole: { ...(config.dns_sinkhole || {}), enabled: e.target.checked } })} />
            <span className="wf-switch-track" />
          </label>
        </SettingRow>

        <SettingRow
          label="عنوان Sinkhole IP"
          desc="عنوان الخادم الذي يستقبل الطلبات المحجوبة ويعرض صفحة التنبيه"
        >
          <input
            type="text"
            className="wf-select"
            dir="ltr"
            defaultValue={config.dns_sinkhole?.sinkhole_ip || '10.0.0.1'}
            onBlur={e => updateConfig({ dns_sinkhole: { ...(config.dns_sinkhole || {}), sinkhole_ip: e.target.value } })}
            style={{ width: '130px', textAlign: 'center', fontFamily: 'monospace' }}
          />
        </SettingRow>

        <SettingRow
          label="تسجيل كافة طلبات الويب (Detailed Logging)"
          desc="تسجيل النطاقات المسموحة والمحظورة لتحليل التهديدات لاحقاً"
        >
          <label className="wf-switch">
            <input type="checkbox" checked={config.logging?.log_decisions ?? true}
              onChange={e => updateConfig({ logging: { ...(config.logging || {}), log_decisions: e.target.checked } })} />
            <span className="wf-switch-track" />
          </label>
        </SettingRow>
      </div>

      {/* Info note */}
      <div className="wf-info-note">
        <Info size={16} style={{ flexShrink: 0, color: '#60a5fa' }} />
        <span>
          <strong>ملاحظة:</strong> يستخدم المحرك ذاكرة تخزين مؤقت LRU ذات عمر زمني TTL.
          التغييرات في قواعد التصنيفات قد تستغرق حتى 5 دقائق لتدخل حيز التنفيذ على جميع الأجهزة.
        </span>
      </div>
    </div>
  );
}
