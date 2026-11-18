import React from 'react';

export function Toggle({ checked, onChange, color = 'var(--accent)' }) {
  return (
    <label className="ids-toggle">
      <input type="checkbox" checked={!!checked} onChange={onChange} />
      <span className="ids-toggle-slider" style={{ '--tg-color': color }} />
    </label>
  );
}

export default Toggle;
