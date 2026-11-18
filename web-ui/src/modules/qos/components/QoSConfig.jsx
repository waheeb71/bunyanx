import React, { useState } from 'react';
import { Settings2, Edit, Save, X, Zap } from 'lucide-react';
import { SectionCard, SkeletonLines } from '../../../components/Shared';

function ConfigRow({ label, value, color }) {
  return (
    <div className="qos-config-row">
      <span className="qos-config-label">{label}</span>
      <span className="qos-config-value" style={color ? { color } : undefined}>
        {value}
      </span>
    </div>
  );
}

function TrafficClassesManager({ classes, onChange, editMode, fmtBytes }) {
  const [newClass, setNewClass] = useState({ dscp: '', priority: 'Medium', rate_bytes: '' });
  const [errorMsg, setErrorMsg] = useState('');

  const PRESETS = [
    { label: 'الاتصالات الصوتية (VoIP - EF/46)', dscp: 46, priority: 'High', rate_bytes: 1250000 },
    { label: 'مؤتمرات الفيديو (Video - AF41/34)', dscp: 34, priority: 'High', rate_bytes: 5000000 },
    { label: 'تصفح الويب (Web - AF21/18)', dscp: 18, priority: 'Medium', rate_bytes: 2500000 },
    { label: 'التنزيلات الثقيلة (Bulk - CS1/8)', dscp: 8, priority: 'Low', rate_bytes: 625000 },
  ];

  const handleAdd = () => {
    setErrorMsg('');
    const d = parseInt(newClass.dscp);
    const r = parseInt(newClass.rate_bytes);
    if (isNaN(d) || d < 0 || d > 63) {
      setErrorMsg("رمز DSCP يجب أن يكون رقماً بين 0 و 63");
      return;
    }
    if (isNaN(r) || r <= 0) {
      setErrorMsg("السرعة يجب أن تكون أكبر من 0");
      return;
    }
    if (classes.some(cls => cls.dscp === d)) {
      setErrorMsg(`رمز DSCP (${d}) مضاف بالفعل`);
      return;
    }
    onChange([...classes, { dscp: d, priority: newClass.priority, rate_bytes: r }]);
    setNewClass({ dscp: '', priority: 'Medium', rate_bytes: '' });
  };

  const applyPreset = (preset) => {
    if (classes.some(cls => cls.dscp === preset.dscp)) {
      setErrorMsg(`الرمز ${preset.dscp} مضاف بالفعل`);
      return;
    }
    setErrorMsg('');
    onChange([...classes, { dscp: preset.dscp, priority: preset.priority, rate_bytes: preset.rate_bytes }]);
  };

  const handleRemove = (index) => {
    onChange(classes.filter((_, idx) => idx !== index));
  };

  return (
    <div className="traffic-classes-manager" style={{ direction: 'rtl' }}>
      <div style={{ overflowX: 'auto', maxHeight: '200px', marginBottom: editMode ? '12px' : '0' }}>
        <table className="data-table" style={{ width: '100%', fontSize: '0.78rem' }}>
          <thead>
            <tr>
              <th>رمز DSCP</th>
              <th>الأولوية</th>
              <th>السرعة القصوى</th>
              {editMode && <th>إجراء</th>}
            </tr>
          </thead>
          <tbody>
            {classes.length === 0 ? (
              <tr>
                <td colSpan={editMode ? 4 : 3} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '16px' }}>
                  لا توجد فئات مرور مخصصة حالياً.
                </td>
              </tr>
            ) : (
              classes.map((cls, idx) => (
                <tr key={idx}>
                  <td className="mono" style={{ color: 'var(--info)' }}>CS{cls.dscp} ({cls.dscp})</td>
                  <td>
                    <span 
                      className="badge" 
                      style={{ 
                        background: cls.priority === 'High' ? 'rgba(255,95,95,0.15)' : cls.priority === 'Medium' ? 'rgba(251,191,36,0.15)' : 'rgba(40,199,111,0.15)', 
                        color: cls.priority === 'High' ? '#ff5f5f' : cls.priority === 'Medium' ? '#fbbf24' : '#28c76f',
                        fontSize: '0.7rem',
                        fontWeight: 600
                      }}
                    >
                      {cls.priority}
                    </span>
                  </td>
                  <td className="mono">{fmtBytes(cls.rate_bytes)}</td>
                  {editMode && (
                    <td>
                      <button 
                        type="button" 
                        className="btn btn-ghost" 
                        style={{ padding: '2px 8px', color: '#ff4d6a', fontSize: '0.72rem' }} 
                        onClick={() => handleRemove(idx)}
                      >
                        حذف
                      </button>
                    </td>
                  )}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {editMode && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', marginTop: '12px', background: 'var(--bg-overlay)', padding: '10px', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
          {errorMsg && (
            <div style={{ fontSize: '0.75rem', color: '#ff4d6a', background: 'rgba(255,77,106,0.1)', padding: '6px 10px', borderRadius: '4px' }}>
              ⚠️ {errorMsg}
            </div>
          )}

          {/* Presets */}
          <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', alignItems: 'center' }}>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>إعدادات جاهزة:</span>
            {PRESETS.map((p, idx) => (
              <button
                key={idx}
                type="button"
                className="btn btn-ghost btn-xs"
                style={{ fontSize: '0.68rem', padding: '2px 8px', border: '1px solid var(--border-color)' }}
                onClick={() => applyPreset(p)}
              >
                + {p.label}
              </button>
            ))}
          </div>

          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            <input
              type="number"
              placeholder="DSCP (0-63)"
              value={newClass.dscp}
              onChange={e => setNewClass(prev => ({ ...prev, dscp: e.target.value }))}
              className="qos-input"
              style={{ width: '100px', padding: '4px 8px', fontSize: '0.78rem' }}
              min="0"
              max="63"
            />
            <select
              value={newClass.priority}
              onChange={e => setNewClass(prev => ({ ...prev, priority: e.target.value }))}
              className="qos-input"
              style={{ padding: '4px 8px', fontSize: '0.78rem', background: 'var(--bg-card)', color: 'var(--text-main)', border: '1px solid var(--border-color)', borderRadius: 4 }}
            >
              <option value="High">عالية (High)</option>
              <option value="Medium">متوسطة (Medium)</option>
              <option value="Low">منخفضة (Low)</option>
            </select>
            <input
              type="number"
              placeholder="السرعة (B/s)"
              value={newClass.rate_bytes}
              onChange={e => setNewClass(prev => ({ ...prev, rate_bytes: e.target.value }))}
              className="qos-input"
              style={{ flex: 1, padding: '4px 8px', fontSize: '0.78rem' }}
              min="1"
            />
            <button 
              type="button" 
              className="btn btn-accent btn-sm" 
              style={{ padding: '4px 12px', fontSize: '0.78rem' }}
              onClick={handleAdd}
            >
              إضافة الفئة
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export function QoSConfig({
  config,
  configLoading,
  editMode,
  setEditMode,
  formData,
  setFormData,
  handleInputChange,
  handleSave,
  handleCancel,
  updatingConfig,
  fmtBytes,
  fmtBits
}) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-6)' }}>
      <SectionCard
        title="لوحة التعديل والتهيئة"
        icon={Settings2}
        actions={
          !editMode && config && (
            <button className="btn btn-ghost btn-xs" onClick={() => setEditMode(true)}>
              <Edit size={14} style={{ marginLeft: 4 }} /> تعديل
            </button>
          )
        }
      >
        {configLoading ? (
          <SkeletonLines count={5} />
        ) : editMode ? (
          <form onSubmit={handleSave} className="qos-form">
            <div className="qos-form-group">
              <label className="qos-toggle-label">
                <input
                  type="checkbox"
                  name="enabled"
                  checked={formData.enabled}
                  onChange={handleInputChange}
                />
                <span className="qos-form-label">تفعيل تقييد حركة المرور (QoS Shaping)</span>
              </label>
            </div>

            <div className="qos-form-group">
              <label className="qos-toggle-label">
                <input
                  type="checkbox"
                  name="enable_ebpf_tc"
                  checked={formData.enable_ebpf_tc ?? true}
                  onChange={e => setFormData(p => ({ ...p, enable_ebpf_tc: e.target.checked }))}
                />
                <span className="qos-form-label">تسريع المعالجة عبر نواة eBPF TC (Kernel Bypass)</span>
              </label>
            </div>

            <div className="qos-form-group">
              <label className="qos-toggle-label">
                <input
                  type="checkbox"
                  name="enable_app_priority_boost"
                  checked={formData.enable_app_priority_boost ?? true}
                  onChange={e => setFormData(p => ({ ...p, enable_app_priority_boost: e.target.checked }))}
                />
                <span className="qos-form-label">إعطاء أولوية ديناميكية للتطبيقات الحساسة للتأخير</span>
              </label>
            </div>

            <div className="qos-form-group">
              <label className="qos-form-label">وضع التشغيل (Mode):</label>
              <select
                name="mode"
                value={formData.mode}
                onChange={handleInputChange}
                className="qos-input"
                style={{ background: 'var(--bg-card)', color: 'var(--text-main)', border: '1px solid var(--border-color)', borderRadius: 4, padding: '4px 8px' }}
              >
                <option value="monitor">المراقبة والتسجيل (Monitor)</option>
                <option value="enforce">الحظر والتنفيذ (Enforce)</option>
              </select>
            </div>

            <div className="qos-form-group">
              <label className="qos-form-label">
                معدل التنزيل الافتراضي للعميل (B/s):
                <span className="badge badge-info mono" style={{ marginRight: 8 }}>
                  {fmtBits(formData.default_user_rate_bytes * 8)}
                </span>
              </label>
              <input
                type="number"
                name="default_user_rate_bytes"
                value={formData.default_user_rate_bytes}
                onChange={handleInputChange}
                className="qos-input"
                min="1"
                max="125000000"
              />
            </div>

            <div className="qos-form-group">
              <label className="qos-form-label">
                حد الانفجار الافتراضي للعميل (Bytes):
                <span className="badge badge-accent mono" style={{ marginRight: 8 }}>
                  {fmtBytes(formData.default_user_burst_bytes)}
                </span>
              </label>
              <input
                type="number"
                name="default_user_burst_bytes"
                value={formData.default_user_burst_bytes}
                onChange={handleInputChange}
                className="qos-input"
                min="1"
                max="250000000"
              />
            </div>

            <div className="qos-form-group">
              <label className="qos-form-label">
                السقف العالمي للشبكة (B/s, 0 = غير محدود):
                <span className="badge badge-warning mono" style={{ marginRight: 8 }}>
                  {formData.global_rate_bytes === 0 ? 'غير محدود' : fmtBits(formData.global_rate_bytes * 8)}
                </span>
              </label>
              <input
                type="number"
                name="global_rate_bytes"
                value={formData.global_rate_bytes}
                onChange={handleInputChange}
                className="qos-input"
                min="0"
              />
            </div>

            <div className="qos-btn-group">
              <button type="submit" className="btn btn-accent btn-sm" disabled={updatingConfig}>
                <Save size={14} style={{ marginLeft: 4 }} /> حفظ التغييرات
              </button>
              <button type="button" className="btn btn-ghost btn-sm" onClick={handleCancel}>
                <X size={14} style={{ marginLeft: 4 }} /> إلغاء
              </button>
            </div>
          </form>
        ) : (
          <div className="qos-config-grid">
            <ConfigRow label="حالة الخدمة" value={config.enabled ? 'مُفعّلة (Active)' : 'مُعطّلة (Disabled)'} color={config.enabled ? 'var(--success)' : 'var(--danger)'} />
            <ConfigRow label="وضع التشغيل" value={config.mode === 'enforce' ? 'الحظر الفوري (Enforce)' : 'المراقبة فقط (Monitor)'} color={config.mode === 'enforce' ? 'var(--warning)' : 'var(--info)'} />
            <ConfigRow label="تسريع eBPF TC" value={config.enable_ebpf_tc !== false ? 'مفعل (Kernel)' : 'معطل'} color={config.enable_ebpf_tc !== false ? 'var(--success)' : 'var(--text-muted)'} />
            <ConfigRow label="الأولوية الديناميكية للتطبيقات" value={config.enable_app_priority_boost !== false ? 'نشط' : 'معطل'} />
            <ConfigRow label="السرعة الافتراضية" value={fmtBytes(config.default_user_rate_bytes)} />
            <ConfigRow label="سعة الانفجار الافتراضية" value={fmtBytes(config.default_user_burst_bytes)} />
            <ConfigRow label="السقف العالمي" value={config.global_rate_bytes === 0 ? 'غير محدود' : fmtBytes(config.global_rate_bytes)} />
            <ConfigRow label="آخر تحديث" value={config.updated_at ? new Date(config.updated_at).toLocaleString('ar-SA') : '—'} />
          </div>
        )}
      </SectionCard>

      <SectionCard title="فئات جودة الخدمة (Traffic Classes)" icon={Zap}>
        <TrafficClassesManager
          classes={formData.traffic_classes || []}
          onChange={(newClasses) => setFormData(prev => ({ ...prev, traffic_classes: newClasses }))}
          editMode={editMode}
          fmtBytes={fmtBytes}
        />
      </SectionCard>
    </div>
  );
}
