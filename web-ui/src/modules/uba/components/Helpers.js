export function fmtScore(score) {
  if (score === undefined || score === null) return '0%';
  return `${(parseFloat(score) * 100).toFixed(0)}%`;
}

export function getRiskColor(level) {
  switch (level?.toLowerCase()) {
    case 'critical': return '#ef4444';
    case 'high':     return '#f59e0b';
    case 'medium':   return '#3b82f6';
    case 'low':      return '#10b981';
    default:         return '#64748b';
  }
}

export function translateRiskLevel(l) {
  switch (l?.toLowerCase()) {
    case 'critical': return 'حرج';
    case 'high': return 'عالي';
    case 'medium': return 'متوسط';
    case 'low': return 'منخفض';
    default: return l || 'غير محدد';
  }
}
