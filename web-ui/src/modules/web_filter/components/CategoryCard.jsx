import React from 'react';
import { motion } from 'framer-motion';
import { Trash2 } from 'lucide-react';
import { ActionSelect, RiskBar } from './ActionBadge';

const CAT_EMOJI = {
  adult:'🔞', gambling:'🎰', malware:'🪲', phishing:'🎣', social:'📱',
  streaming:'🎬', games:'🎮', news:'📰', education:'🎓', finance:'🏦',
  botnet:'🕷️', ransomware:'☠️', c2:'📡',
};

function getCatIcon(name) {
  const n = name.toLowerCase();
  for (const [k, v] of Object.entries(CAT_EMOJI)) if (n.includes(k)) return v;
  return '📂';
}

export function CategoryCard({ cat, onUpdateAction, onDelete }) {
  const stripColor = cat.action === 'BLOCK' ? '#ff5f5f' : cat.action === 'ALLOW' ? '#28c76f' : '#60a5fa';
  return (
    <motion.div
      className="wf-cat-card"
      style={{ '--strip': stripColor }}
      layout
      initial={{ opacity: 0, scale: 0.97 }}
      animate={{ opacity: 1, scale: 1 }}
      exit={{ opacity: 0, scale: 0.95 }}
      whileHover={{ y: -3 }}
      transition={{ duration: 0.2 }}
    >
      <div className="wf-cat-top">
        <div className="wf-cat-brand">
          <span className="wf-cat-emoji">{getCatIcon(cat.name)}</span>
          <div>
            <div className="wf-cat-name" dir="ltr">{cat.name.replace(/_/g, ' ')}</div>
            <div className="wf-cat-risk-label">مستوى الخطر</div>
          </div>
        </div>
        {cat.is_custom && (
          <button
            className="wf-del-btn"
            onClick={() => window.confirm('حذف هذا التصنيف؟') && onDelete(cat.id)}
            title="حذف"
          >
            <Trash2 size={12} />
          </button>
        )}
      </div>

      <RiskBar score={cat.risk_score || 0} />

      <div className="wf-cat-desc">{cat.description || 'لم يتم توفير وصف لهذا التصنيف.'}</div>

      <div className="wf-cat-footer">
        <span className="wf-cat-footer-label">إجراء السياسة</span>
        <ActionSelect value={cat.action} onChange={v => onUpdateAction(cat.id, v)} />
      </div>
    </motion.div>
  );
}
