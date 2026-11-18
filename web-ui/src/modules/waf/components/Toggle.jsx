import React from 'react';

export function Toggle({ checked, onChange, color = 'var(--accent)' }) {
  return (
    <label className="waf-toggle">
      <input type="checkbox" checked={!!checked} onChange={e => onChange(e.target.checked)} />
      <span className="waf-toggle-slider" style={{ '--tg-color': color }} />
    </label>
  );
}

export function FeatureToggleRow({ label, desc, enabled, onChange, icon: Icon, color = 'var(--accent)' }) {
  return (
    <div className={`waf-feature-row ${enabled ? 'active' : ''}`}>
      <div className="waf-feature-left">
        {Icon && (
          <div className="waf-feature-icon" style={{ color: enabled ? color : 'var(--text-muted)', background: enabled ? `${color}22` : 'var(--bg-overlay)' }}>
            <Icon size={16} />
          </div>
        )}
        <div>
          <div className="waf-feature-label">{label}</div>
          <div className="waf-feature-desc">{desc}</div>
        </div>
      </div>
      <Toggle checked={enabled} onChange={val => onChange(val)} color={color} />
    </div>
  );
}
