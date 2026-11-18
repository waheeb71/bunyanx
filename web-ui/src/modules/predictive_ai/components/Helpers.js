export function fmtDate(iso) {
  if (!iso) return '---';
  return new Date(iso).toLocaleString('ar-SA');
}

export function fmtTs(ts) {
  if (!ts) return '---';
  return new Date(ts * 1000).toLocaleTimeString('ar-SA');
}

export function fmtIso(iso) {
  if (!iso) return '---';
  return new Date(iso).toLocaleTimeString('ar-SA');
}
