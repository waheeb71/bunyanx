import React from 'react';

export function ActionBadge({ action }) {
  const map = {
    BLOCK: { cls: 'badge-danger', text: 'حظر' },
    ALLOW: { cls: 'badge-success', text: 'سماح' },
    REDIRECT: { cls: 'badge-warning', text: 'توجيه' },
    MONITOR: { cls: 'badge-accent', text: 'مراقبة' },
  };
  const m = map[action] || { cls: 'badge-accent', text: action };
  return <span className={`badge ${m.cls}`}>{m.text}</span>;
}

export default ActionBadge;
