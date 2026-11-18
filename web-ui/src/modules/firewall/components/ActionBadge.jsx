import { CheckCircle2, XCircle } from 'lucide-react';

export function ActionBadge({ action }) {
  const isAllow = action === 'ALLOW';
  return (
    <span className={`badge ${isAllow ? 'badge-success' : 'badge-danger'}`} style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
      {isAllow ? <CheckCircle2 size={11} /> : <XCircle size={11} />}
      {isAllow ? 'سماح' : 'حجب'}
    </span>
  );
}

export default ActionBadge;
