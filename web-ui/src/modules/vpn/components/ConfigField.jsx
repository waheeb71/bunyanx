import React from 'react';

export function ConfigField({ label, icon: Icon, children, hint }) {
  return (
    <div className="vpn-field">
      <div className="vpn-field-label">
        {Icon && <Icon size={13} style={{ color: 'rgba(255,255,255,0.3)' }} />}
        {label}
      </div>
      {children}
      {hint && <div className="vpn-field-hint">{hint}</div>}
    </div>
  );
}

export default ConfigField;
