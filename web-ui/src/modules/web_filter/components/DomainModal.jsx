import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Globe, Plus } from 'lucide-react';
import { ACTION_META } from './ActionBadge';

export function DomainModal({ isOpen, onClose, onSubmit, isSubmitting, categories = [] }) {
  const [formData, setFormData] = useState({
    domain_pattern: '',
    category_name: '',
    action: 'BLOCK',
  });

  if (!isOpen) return null;

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!formData.domain_pattern.trim()) return;
    onSubmit({
      domain_pattern: formData.domain_pattern.trim(),
      category_name: formData.category_name.trim() || undefined,
      action: formData.action,
    });
    setFormData({ domain_pattern: '', category_name: '', action: 'BLOCK' });
  };

  return (
    <AnimatePresence>
      <div className="wf-modal-overlay">
        <motion.div
          className="wf-modal"
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          exit={{ opacity: 0, scale: 0.95 }}
          transition={{ duration: 0.2 }}
        >
          <div className="wf-modal-header">
            <div className="wf-modal-title">
              <Globe size={18} style={{ color: '#60a5fa' }} />
              إضافة قاعدة تجاوز نطاق (Domain Override Rule)
            </div>
            <button className="wf-modal-close" onClick={onClose}>
              <X size={16} />
            </button>
          </div>

          <form onSubmit={handleSubmit} className="wf-modal-body">
            <div className="wf-form-group">
              <label className="wf-label">نمط النطاق (Domain Pattern)</label>
              <input
                type="text"
                className="wf-input"
                dir="ltr"
                placeholder="مثال: *.malware-site.com أو 10.0.4.15"
                value={formData.domain_pattern}
                onChange={(e) => setFormData({ ...formData, domain_pattern: e.target.value })}
                required
              />
              <span className="wf-help-text">يدعم الأحرف الخاصة بالتعميم مثل * و ? أو العنوان الفعلي للنطاق</span>
            </div>

            <div className="wf-form-row" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
              <div className="wf-form-group">
                <label className="wf-label">التصنيف المرتبط (Category / Tag)</label>
                <input
                  type="text"
                  className="wf-input"
                  placeholder="اختياري (مثال: phishing)"
                  value={formData.category_name}
                  onChange={(e) => setFormData({ ...formData, category_name: e.target.value })}
                />
              </div>

              <div className="wf-form-group">
                <label className="wf-label">الإجراء (Action)</label>
                <select
                  className="wf-select"
                  style={{ width: '100%', color: ACTION_META[formData.action]?.color }}
                  value={formData.action}
                  onChange={(e) => setFormData({ ...formData, action: e.target.value })}
                >
                  <option value="BLOCK">حظر (BLOCK)</option>
                  <option value="ALLOW">سماح (ALLOW)</option>
                  <option value="MONITOR">مراقبة (MONITOR)</option>
                </select>
              </div>
            </div>

            <div className="wf-modal-footer">
              <button type="button" className="wf-btn wf-btn--secondary" onClick={onClose}>
                إلغاء
              </button>
              <button type="submit" className="wf-btn wf-btn--primary" disabled={isSubmitting}>
                {isSubmitting ? 'جاري الإضافة...' : <><Plus size={14} /> إضافة قاعدة التجاوز</>}
              </button>
            </div>
          </form>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}
