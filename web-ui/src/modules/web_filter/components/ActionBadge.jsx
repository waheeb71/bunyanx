import React from 'react';
import { motion } from 'framer-motion';
import { Eye, Megaphone, ShieldOff, ShieldCheck, Filter } from 'lucide-react';

export const ACTION_META = {
  BLOCK:   { label: 'حظر',    color: '#ff5f5f', bg: 'rgba(255,95,95,0.12)',   border: 'rgba(255,95,95,0.22)',   icon: ShieldOff  },
  ALLOW:   { label: 'سماح',   color: '#28c76f', bg: 'rgba(40,199,111,0.12)',  border: 'rgba(40,199,111,0.22)',  icon: ShieldCheck },
  MONITOR: { label: 'مراقبة', color: '#60a5fa', bg: 'rgba(96,165,250,0.12)',  border: 'rgba(96,165,250,0.22)',  icon: Eye         },
  WARN:    { label: 'تحذير',  color: '#ffc107', bg: 'rgba(255,193,7,0.12)',   border: 'rgba(255,193,7,0.22)',   icon: Megaphone   },
};

export function ActionBadge({ action }) {
  const m = ACTION_META[action] || { label: action, color: '#888', bg: 'rgba(100,100,100,0.12)', border: 'rgba(100,100,100,0.22)', icon: Filter };
  const Icon = m.icon;
  return (
    <span className="wf-action-badge" style={{ color: m.color, background: m.bg, borderColor: m.border }}>
      <Icon size={10} />
      {m.label}
    </span>
  );
}

export function ActionSelect({ value, onChange }) {
  const m = ACTION_META[value] || ACTION_META.BLOCK;
  return (
    <select
      className="wf-action-select"
      style={{ color: m.color }}
      value={value}
      onChange={e => onChange(e.target.value)}
    >
      <option value="BLOCK">حظر (BLOCK)</option>
      <option value="ALLOW">سماح (ALLOW)</option>
      <option value="MONITOR">مراقبة (MONITOR)</option>
    </select>
  );
}

export function RiskBar({ score }) {
  const color = score >= 80 ? '#ff5f5f' : score >= 50 ? '#ffc107' : '#28c76f';
  return (
    <div className="wf-risk-bar">
      <div className="wf-risk-track">
        <motion.div
          className="wf-risk-fill"
          style={{ background: color }}
          initial={{ width: 0 }}
          animate={{ width: `${score}%` }}
          transition={{ duration: 0.6, delay: 0.1 }}
        />
      </div>
      <span className="wf-risk-num" style={{ color }}>{score}</span>
    </div>
  );
}
