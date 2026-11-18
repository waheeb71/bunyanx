import { useState } from 'react';
import { motion } from 'framer-motion';
import { Key, Loader2, X } from 'lucide-react';
import { useToast } from '../../../components/Toast';

export function PKICSRModal({ onClose, onSubmit, isLoading }) {
  const [form, setForm] = useState({
    cn: '',
    org: 'bunyanx Systems',
    country: 'SA',
    san: '',
    keySize: '2048',
    days: '365',
  });
  const toast = useToast();

  const handleGenerate = () => {
    if (!form.cn.trim()) {
      return toast.error('يجب تحديد الاسم الشائع Common Name (CN)', 'حقل مطلوب');
    }
    onSubmit({
      ...form,
      keySize: parseInt(form.keySize, 10),
      days: parseInt(form.days, 10),
    });
  };

  const Field = ({ label, id, value, onChange, type = 'text', options, hint }) => (
    <div className="pki-field">
      <label className="pki-label" htmlFor={id}>
        {label}
      </label>
      {options ? (
        <select id={id} className="pki-input pki-select" value={value} onChange={(e) => onChange(e.target.value)}>
          {options.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
      ) : (
        <input
          id={id}
          className="pki-input"
          type={type}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={hint}
        />
      )}
    </div>
  );

  return (
    <div className="pki-modal-overlay" onClick={onClose}>
      <motion.div
        className="pki-modal"
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0, scale: 0.95 }}
        onClick={(e) => e.stopPropagation()}
        dir="rtl"
      >
        <div className="pki-modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Key size={18} style={{ color: '#00d4ff' }} />
            <span>إصدار شهادة جهاز جديدة (Device Certificate)</span>
          </div>
          <button className="pki-modal-close" onClick={onClose}>
            <X size={16} />
          </button>
        </div>

        <div className="pki-modal-body">
          <div className="pki-form-grid">
            <Field
              label="Common Name (CN)"
              id="cn"
              value={form.cn}
              onChange={(v) => setForm((p) => ({ ...p, cn: v }))}
              hint="مثال: firewall-core.local"
            />
            <Field
              label="المنظمة (Organization)"
              id="org"
              value={form.org}
              onChange={(v) => setForm((p) => ({ ...p, org: v }))}
            />
            <Field
              label="رمز الدولة (Country Code)"
              id="country"
              value={form.country}
              onChange={(v) => setForm((p) => ({ ...p, country: v }))}
            />
            <Field
              label="Subject Alt Names (SAN)"
              id="san"
              value={form.san}
              onChange={(v) => setForm((p) => ({ ...p, san: v }))}
              hint="مثال: 192.168.1.1, app.local"
            />
            <Field
              label="حجم المفتاح (Key Size)"
              id="ks"
              value={form.keySize}
              onChange={(v) => setForm((p) => ({ ...p, keySize: v }))}
              options={[
                { value: '2048', label: 'RSA-2048 (موصى به)' },
                { value: '4096', label: 'RSA-4096 (أمان عالٍ)' },
              ]}
            />
            <Field
              label="مدة الصلاحية (بالأيام)"
              id="days"
              value={form.days}
              onChange={(v) => setForm((p) => ({ ...p, days: v }))}
              type="number"
            />
          </div>
        </div>

        <div className="pki-modal-footer">
          <button
            className="pki-btn pki-btn-primary"
            onClick={handleGenerate}
            disabled={isLoading}
          >
            {isLoading ? <Loader2 size={14} className="animate-spin" /> : <Key size={14} />}
            {isLoading ? 'جاري الإصدار والتوقيع...' : 'إصدار وتوقيع الشهادة'}
          </button>
          <button className="pki-btn pki-btn-ghost" onClick={onClose}>
            إلغاء
          </button>
        </div>
      </motion.div>
    </div>
  );
}
