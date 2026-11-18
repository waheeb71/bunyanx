import React from 'react';
import { Eye, ShieldOff, Shield } from 'lucide-react';

const ACTION_META = {
  DECRYPT: { label: 'فك تشفير', color: '#ff5f5f', bg: 'rgba(255,95,95,0.12)',  border: 'rgba(255,95,95,0.22)',  icon: Eye       },
  BYPASS:  { label: 'تجاوز',    color: '#ffc107', bg: 'rgba(255,193,7,0.12)',  border: 'rgba(255,193,7,0.22)',  icon: ShieldOff  },
  BLOCK:   { label: 'حظر',      color: '#64748b', bg: 'rgba(100,116,139,0.12)',border: 'rgba(100,116,139,0.22)',icon: Shield     },
};

export function ActionBadge({ action }) {
  const m = ACTION_META[action] || ACTION_META.BLOCK;
  const Icon = m.icon;
  return (
    <span className="ssl-action-badge" style={{ color: m.color, background: m.bg, borderColor: m.border }}>
      <Icon size={10} />
      {m.label}
    </span>
  );
}

export default ActionBadge;
