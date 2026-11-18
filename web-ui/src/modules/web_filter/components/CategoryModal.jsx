import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, ShieldAlert, Check } from 'lucide-react';
import { ACTION_META } from './ActionBadge';

export function CategoryModal({ isOpen, onClose, onSubmit, isSubmitting }) {
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    action: 'BLOCK',
    risk_score: 50,
  });

  if (!isOpen) return null;

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!formData.name.trim()) return;
    onSubmit({
      name: formData.name.trim(),
      description: formData.description.trim(),
      action: formData.action,
      risk_score: parseInt(formData.risk_score) || 50,
    });
    setFormData({ name: '', description: '', action: 'BLOCK', risk_score: 50 });
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
              <ShieldAlert size={18} style={{ color: '#f97316' }} />
              إضافة تصنيف مخصص جديد (Custom Category)
            </div>
            <button className="wf-modal-close" onClick={onClose}>
              <X size={16} />
            </button>
          </div>

          <form onSubmit={handleSubmit} className="wf-modal-body">
            <div className="wf-form-group">
              <label className="wf-label">اسم التصنيف (Category Name)</label>
              <input
                type="text"
                className="wf-input"
                placeholder="مثال: competitor_sites أو internal_finance"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                required
              />
            </div>

            <div className="wf-form-group">
              <label className="wf-label">الوصف التفصيلي (Description)</label>
              <textarea
                className="wf-input"
                style={{ height: '80px', resize: 'vertical' }}
                placeholder="توصيف الهدف والسياسة الأمنية المطبقة على هذا التصنيف..."
                value={formData.description}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              />
            </div>

            <div className="wf-form-row" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
              <div className="wf-form-group">
                <label className="wf-label">إجراء السياسة (Action)</label>
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

              <div className="wf-form-group">
                <label className="wf-label">مستوى الخطر (Risk Score: {formData.risk_score})</label>
                <input
                  type="range"
                  min="0"
                  max="100"
                  className="wf-slider"
                  value={formData.risk_score}
                  onChange={(e) => setFormData({ ...formData, risk_score: e.target.value })}
                  style={{ width: '100%', marginTop: '10px' }}
                />
              </div>
            </div>

            <div className="wf-modal-footer">
              <button type="button" className="wf-btn wf-btn--secondary" onClick={onClose}>
                إلغاء
              </button>
              <button type="submit" className="wf-btn wf-btn--primary" disabled={isSubmitting}>
                {isSubmitting ? 'جاري الحفظ...' : <><Check size={14} /> إضافة التصنيف</>}
              </button>
            </div>
          </form>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}
