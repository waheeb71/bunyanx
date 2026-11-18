export function UserStatCard({ label, value, color, icon: Icon }) {
  return (
    <div className="usr-stat-card" style={{ '--stat-color': color }}>
      <div className="usr-stat-icon" style={{ background: `${color}15`, border: `1px solid ${color}25` }}>
        <Icon size={18} style={{ color }} />
      </div>
      <div>
        <div className="usr-stat-value" style={{ color }}>{value}</div>
        <div className="usr-stat-label">{label}</div>
      </div>
    </div>
  );
}

export default UserStatCard;
