import React from 'react';

export function VpnStatChip({ label, value, color }) {
  return (
    <div className="vpn-stat-chip" style={{ '--vc': color }}>
      <div className="vpn-stat-val" style={{ color }}>{value}</div>
      <div className="vpn-stat-lbl">{label}</div>
    </div>
  );
}

export default VpnStatChip;
