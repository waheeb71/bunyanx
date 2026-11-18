import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { systemApi } from '../../../services/api';
import { RefreshCw, FileCode2, ChevronLeft, RotateCcw, Zap, Settings, HelpCircle, BookOpen, AlertCircle, Layers } from 'lucide-react';
import { getCategoryGuide, getFieldGuide } from './YamlGuide';
import './yaml.css';

/* وصف كل ملف إعدادات */
const FILE_DESCRIPTIONS = {
  'base.yaml':                 'الإعدادات الأساسية — الوكيل، المنافذ، وخوادم الأسماء',
  'settings.yaml':             'إعدادات الفحص المشتركة وشبكات المؤسسة والسياسات العامة',
  'features.yaml':             'مُبدِّلات الميزات التفصيلية ومفاتيح التفعيل التجريبية',
  'identity_correlation.yaml': 'إعدادات محرك ربط الهوية (LDAP/AD, RADIUS, VPN, Captive Portal)',
  'sysctl-optimization.conf':   'معاملات تحسين النواة للشبكة ومخازن Socket',
};

/* أيقونات وألوان لكل تصنيف */
const CATEGORY_ICONS = {
  proxy:              { icon: '🔀', color: '#7c8cf8' },
  modules:            { icon: '🧩', color: '#00e5a0' },
  network:            { icon: '🌐', color: '#00b4d8' },
  security:           { icon: '🔒', color: '#ff5f5f' },
  logging:            { icon: '📄', color: '#ffc107' },
  performance:        { icon: '⚡', color: '#ff9f43' },
  ids_ips:            { icon: '🛡️', color: '#ff5f5f' },
  waf:                { icon: '🧱', color: '#7c8cf8' },
  dns_security:       { icon: '🌐', color: '#00b4d8' },
  ml:                 { icon: '🧠', color: '#c084fc' },
  ha:                 { icon: '🔁', color: '#34d399' },
  vpn:                { icon: '🔑', color: '#f59e0b' },
  cache:              { icon: '⚡', color: '#38bdf8' },
  ldap_sync:          { icon: '📇', color: '#a78bfa' },
  radius_accounting: { icon: '📡', color: '#f472b6' },
  vpn_bridge:         { icon: '🔑', color: '#fb7185' },
  captive_portal:     { icon: '🌐', color: '#34d399' },
  manual_api:         { icon: '🛠️', color: '#f59e0b' },
  source_priority:    { icon: '📊', color: '#c084fc' },
  ngfw:               { icon: '🛡️', color: '#00e5a0' },
  inspection:         { icon: '🔍', color: '#60a5fa' },
  sysctl:             { icon: '⚙️', color: '#34d399' },
  default:            { icon: '⚙️', color: '#9da0b3' },
};

function getCategoryMeta(category) {
  return CATEGORY_ICONS[category] || CATEGORY_ICONS.default;
}

export default function GenericYamlEditor({ fileName }) {
  const qc = useQueryClient();
  const [selectedCategory, setSelectedCategory] = useState(null);

  const { data: config, isLoading, isError, refetch } = useQuery({
    queryKey: ['config', fileName],
    queryFn: async () => {
      const res = await systemApi.config(fileName);
      return res.data;
    }
  });

  const updateMutation = useMutation({
    mutationFn: ({ category, key, value }) => systemApi.updateConfig({ category, key, value }, fileName),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['config'] })
  });

  const resetMutation = useMutation({
    mutationFn: () => systemApi.resetConfig(fileName),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['config'] });
      alert(`✅ تمت استعادة ${fileName} إلى الإعدادات الافتراضية.`);
    },
    onError: (err) => alert(`❌ فشل في الاستعادة: ${err.message}`)
  });

  const handleReset = () => {
    if (window.confirm(`هل أنت متأكد من استعادة ${fileName} إلى إعداداته الافتراضية؟ ستُفقد جميع التغييرات الحالية.`)) {
      resetMutation.mutate();
    }
  };

  const handleDeepChange = (path, newVal) => {
    if (!config) return;
    const newConfig = JSON.parse(JSON.stringify(config));
    let current = newConfig;
    for (let i = 0; i < path.length - 1; i++) {
      current = current[path[i]];
    }
    current[path[path.length - 1]] = newVal;

    const category = path[0];
    const key = path[1];
    if (path.length >= 2) {
      const apiValue = newConfig[category][key];
      updateMutation.mutate({ category, key, value: apiValue });
      qc.setQueryData(['config', fileName], newConfig);
    }
  };

  /* مكوّن الإرشاد للمفاتيح (Help Icon + Popover) */
  const KeyWithGuide = ({ name, path, iconOnly = false }) => {
    const guide = getFieldGuide(path);
    const displayName = guide ? guide.title : name;
    
    return (
      <div className="modern-key-wrap">
        <div className="modern-key-label">
          {displayName}
          {guide && (
            <span className="modern-help-icon">
              <HelpCircle size={14} />
              <div className="yaml-popover">
                <div className="yaml-popover-title">{guide.title}</div>
                <div className="yaml-popover-desc">{guide.desc}</div>
                {guide.example && (
                  <div className="yaml-popover-ex">مثال: {guide.example}</div>
                )}
              </div>
            </span>
          )}
        </div>
        {!iconOnly && <div className="modern-key-subtitle">{name}</div>}
      </div>
    );
  };

  /* حقل إدخال محلي للنصوص والأرقام */
  const PrimitiveValueInput = ({ initialData, type, path }) => {
    const [val, setVal] = useState(initialData ?? '');
    
    useEffect(() => {
      setVal(initialData ?? '');
    }, [initialData]);

    const handleBlur = () => {
      let finalVal = val;
      if (type === 'number') {
        const parsed = Number(val);
        if (isNaN(parsed)) finalVal = initialData;
        else finalVal = parsed;
        setVal(finalVal);
      }
      if (finalVal !== initialData) handleDeepChange(path, finalVal);
    };

    return (
      <input
        type="text"
        value={val}
        onChange={(e) => setVal(e.target.value)}
        onBlur={handleBlur}
        className={`modern-input ${type === 'number' ? 'modern-number' : ''}`}
        disabled={updateMutation.isPending}
        placeholder={initialData !== null ? String(initialData) : '—'}
        dir="ltr"
      />
    );
  };

  /* عرض مصفوفة بشكل أفضل */
  const ArrayEditor = ({ data, path }) => {
    return (
      <div className="modern-array-container">
        {data.length === 0 && <span className="modern-hint">فارغة</span>}
        {data.map((item, idx) => (
          <div key={idx} className="modern-array-item">
            <span className="array-badge">{idx + 1}</span>
            <div className="array-content">
              {typeof item === 'object' && item !== null ? (
                <FormSectionGroup data={item} path={[...path, idx]} noBorder />
              ) : (
                <PrimitiveValueInput 
                  initialData={item}
                  type={typeof item === 'number' ? 'number' : 'text'}
                  path={[...path, idx]}
                />
              )}
            </div>
          </div>
        ))}
      </div>
    );
  };

  /* مكوّن يعرض صفاً لخاصية يمكن إعطاؤها قيمة (نص، رقم، منطقي) */
  const FormFieldRow = ({ name, data, path }) => {
    const isBool = typeof data === 'boolean';
    
    if (Array.isArray(data)) {
      return (
        <div className="modern-form-array-row">
           <div className="modern-array-header">
             <KeyWithGuide name={name} path={path} />
           </div>
           <ArrayEditor data={data} path={path} />
        </div>
      );
    }

    return (
      <div className="modern-form-row">
        <KeyWithGuide name={name} path={path} />
        <div className="modern-form-control">
          {isBool ? (
             <label className="modern-toggle">
               <input
                 type="checkbox"
                 checked={data}
                 onChange={(e) => handleDeepChange(path, e.target.checked)}
                 disabled={updateMutation.isPending}
               />
               <span className="slider" />
             </label>
          ) : path.join('.') === 'proxy.mode' ? (
             <select
               className="modern-input"
               value={data ?? 'transparent'}
               onChange={(e) => handleDeepChange(path, e.target.value)}
               disabled={updateMutation.isPending}
               dir="ltr"
               style={{ cursor: 'pointer' }}
             >
               <option value="transparent">TransparentProxy (بروكسي شفاف)</option>
               <option value="forward">ForwardProxy (توجيه أمامي)</option>
               <option value="reverse">ReverseProxy (بروكسي عكسي)</option>
               <option value="none">بدون / معطل (None)</option>
             </select>
          ) : (
            <PrimitiveValueInput
              initialData={data}
              type={typeof data === 'number' ? 'number' : 'text'}
              path={path}
            />
          )}
        </div>
      </div>
    );
  };

  /* مكوّن يعرض مجموعة من الحقول (Section) */
  const FormSectionGroup = ({ data, path, noBorder = false }) => {
    const entries = Object.entries(data);
    
    // تصنيف الخصائص إلى بدائية ومعقدة (كائنات أخرى)
    const primitivesAndArrays = entries.filter(([, v]) => typeof v !== 'object' || v === null || Array.isArray(v));
    const nestedObjects = entries.filter(([, v]) => typeof v === 'object' && v !== null && !Array.isArray(v));

    return (
      <div className={`modern-form-group ${noBorder ? 'no-border' : ''}`}>
        {primitivesAndArrays.map(([k, v]) => (
          <FormFieldRow key={k} name={k} data={v} path={[...path, k]} />
        ))}

        {nestedObjects.map(([k, v]) => (
          <div className="modern-form-subsection" key={k}>
            <div className="subsection-header">
              <Layers size={14} className="subsection-icon" />
              <KeyWithGuide name={k} path={[...path, k]} iconOnly={true} />
            </div>
            <div className="subsection-body">
              <FormSectionGroup data={v} path={[...path, k]} />
            </div>
          </div>
        ))}
      </div>
    );
  };

  /* الواجهة الذكية الجديدة: تولد الاستمارات بدل الشجرة التكرارية */
  const SmartEditor = ({ category, data }) => {
    const entries = Object.entries(data);
    const primitivesAndArrays = entries.filter(([, v]) => typeof v !== 'object' || v === null || Array.isArray(v));
    const nestedObjects = entries.filter(([, v]) => typeof v === 'object' && v !== null && !Array.isArray(v));

    return (
      <div className="smart-editor-container">
        {primitivesAndArrays.length > 0 && (
          <div className="modern-card-section full-width">
            <h3 className="modern-section-title">إعدادات عامة</h3>
            <FormSectionGroup data={Object.fromEntries(primitivesAndArrays)} path={[category]} />
          </div>
        )}
        
        {nestedObjects.map(([k, v]) => {
          const guide = getFieldGuide([category, k]);
          return (
            <div className="modern-card-section" key={k}>
              <h3 className="modern-section-title">
                 {guide ? guide.title : k}
                 <span className="modern-section-subtitle">{k}</span>
              </h3>
              <FormSectionGroup data={v} path={[category, k]} />
            </div>
          );
        })}
      </div>
    );
  };


  const categories = config ? Object.entries(config) : [];
  const fileDesc = FILE_DESCRIPTIONS[fileName] || 'ملف إعدادات النظام';
  
  // بيانات اللوحة الجانبية
  const currentGuide = selectedCategory ? getCategoryGuide(selectedCategory) : null;
  const currentMeta = selectedCategory ? getCategoryMeta(selectedCategory) : null;

  return (
    <div className="yaml-editor-pane" dir="rtl">

      {/* ── شريط التحكم ─────────────────────────────────────── */}
      <div className="yaml-controls">
        <div className="yaml-controls-left">
          <div className="yaml-file-icon">
            <FileCode2 size={18} />
          </div>
          <div>
            <div className="yaml-file-name">{fileName}</div>
            <div className="yaml-file-desc">{fileDesc}</div>
          </div>
        </div>

        <div className="yaml-actions">
          <button
            className="btn-refresh"
            onClick={() => refetch()}
            disabled={isLoading}
            title="تحديث من السيرفر"
          >
            <RefreshCw size={14} className={isLoading ? 'spin' : ''} />
            تحديث
          </button>
          <button
            className="btn-refresh"
            onClick={handleReset}
            disabled={resetMutation.isPending}
            style={{ borderColor: 'rgba(255,95,95,0.3)', color: '#ff5f5f' }}
            title="استعادة الافتراضيات"
          >
            <RotateCcw size={14} />
            استعادة
          </button>
        </div>
      </div>

      {/* ── المحتوى الرئيسي ─────────────────────────────────── */}
      <div className="yaml-cards-wrapper">
        {isLoading ? (
          <div className="yaml-loading">
            <RefreshCw className="spin" size={18} />
            جاري تحميل الإعدادات...
          </div>
        ) : isError ? (
          <div className="yaml-error">
            ❌ فشل تحميل {fileName} — تأكد من أن الواجهة الخلفية تعمل.
          </div>
        ) : (
          <>
            <div style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              marginBottom: '18px', paddingBottom: '14px',
              borderBottom: '1px solid rgba(255,255,255,0.06)'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Settings size={15} style={{ opacity: 0.5 }} />
                <span style={{ fontSize: '0.8rem', color: 'var(--s-text-3, #5c5f75)' }}>
                  {categories.length} تصنيف &nbsp;·&nbsp;
                  {categories.reduce((s, [, v]) => s + Object.keys(v || {}).length, 0)} خاصية
                </span>
              </div>
              <span style={{
                fontSize: '0.7rem', padding: '3px 8px', borderRadius: '4px',
                background: 'rgba(0,229,160,0.1)', color: '#00e5a0', fontFamily: 'monospace'
              }}>
                نموذج ذكي مدعوم
              </span>
            </div>

            <div className="yaml-cards-grid">
              {categories.map(([category, sectionData]) => {
                const meta = getCategoryMeta(category);
                const propCount = Object.keys(sectionData || {}).length;
                return (
                  <div
                    key={category}
                    className="yaml-category-card"
                    onClick={() => setSelectedCategory(category)}
                  >
                    <div className="yaml-card-top">
                      <div className="yaml-card-icon-wrap" style={{ background: `${meta.color}18` }}>
                        <span style={{ fontSize: '1.2rem' }}>{meta.icon}</span>
                      </div>
                      <ChevronLeft size={16} className="yaml-card-arrow" />
                    </div>
                    <h4 className="yaml-card-title">{category}</h4>
                    <p className="yaml-card-subtitle">
                      <span className="yaml-card-prop-badge">{propCount} قسم</span>
                      إعدادات النظام الفرعي
                    </p>
                  </div>
                );
              })}
            </div>
          </>
        )}
      </div>

      {/* النافذة الشاملة (Modal مع النموذج الجديد) */}
      {selectedCategory && config && config[selectedCategory] && (
        <div
          className="yaml-modal-overlay"
          onClick={() => setSelectedCategory(null)}
        >
          <div
            className="yaml-modal-container modern-modal"
            onClick={(e) => e.stopPropagation()}
          >
            {/* اللوحة الجانبية */}
            {currentGuide && (
              <div className="yaml-guide-panel">
                <div className="guide-panel-sticky">
                  <div className="guide-category-icon-bg" style={{background:`${currentMeta.color}15`, color:currentMeta.color}}>
                    {currentMeta.icon}
                  </div>
                  <h3 className="guide-title">{currentGuide.title}</h3>
                  <p className="guide-desc">{currentGuide.desc}</p>
                  
                  <div className="guide-divider" />
                  
                  <div className="guide-info-box" style={{background:'rgba(245,158,11,0.05)', borderColor:'rgba(245,158,11,0.15)'}}>
                    <h5 style={{color:'#f59e0b'}}><AlertCircle size={14}/> تنويه هام</h5>
                    <p style={{color:'rgba(255,255,255,0.4)'}}>يتم حفظ الإعدادات وتطبيقها فوراً على النظام. أي خطأ في التهيئة قد يؤدي إلى انقطاع الخدمة.</p>
                  </div>
                </div>
              </div>
            )}

            {/* قسم المحرر والتعديل */}
            <div className="yaml-modal-content">
              {/* رأس النافذة */}
              <div className="yaml-modal-header">
                <div className="yaml-modal-header-left">
                  <div>
                    <h2 className="yaml-modal-title">إعدادات {selectedCategory}</h2>
                    <div className="yaml-modal-subtitle">
                      ملف: {fileName}
                    </div>
                  </div>
                </div>
                <button
                  className="yaml-modal-close"
                  onClick={() => setSelectedCategory(null)}
                  title="إغلاق"
                >
                  ✕
                </button>
              </div>

              {/* جسم التعديل باستخدام التصميم الجديد */}
              <div className="yaml-modal-body modern-modal-body">
                <SmartEditor category={selectedCategory} data={config[selectedCategory]} />
              </div>

              {/* تذييل النافذة */}
              <div className="yaml-modal-footer">
                <div className="yaml-modal-footer-info">
                  <Zap size={12} style={{ color: '#00e5a0' }} />
                  حفظ تلقائي وفوري متصل بـ API
                </div>
                <button
                  className="btn-refresh"
                  style={{background: 'rgba(0,229,160,0.1)', borderColor: 'rgba(0,229,160,0.3)', color: '#00e5a0'}}
                  onClick={() => setSelectedCategory(null)}
                >
                  الانتهاء
                </button>
              </div>
            </div>

          </div>
        </div>
      )}

      {/* إشعار الحفظ */}
      {updateMutation.isPending && (
        <div className="saving-overlay">
          <RefreshCw size={14} className="spin" />
          جاري تطبيق التغييرات...
        </div>
      )}
    </div>
  );
}
