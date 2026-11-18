import React from 'react';

export function Toggle({ checked, onChange }) {
  return (
    <label className="dns-toggle">
      <input type="checkbox" checked={!!checked} onChange={onChange} />
      <span className="dns-toggle-slider" />
    </label>
  );
}

export default Toggle;
