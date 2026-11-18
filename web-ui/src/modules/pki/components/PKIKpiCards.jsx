import { ShieldCheck, Clock, XCircle, Key, Award } from 'lucide-react';
import { KpiCard } from '../../../components/Shared';
import { usePKIStore } from '../store/usePKIStore';

export function PKIKpiCards({ certs = [], isLoading, caInfo, daysUntil }) {
  const { setStatusFilter } = usePKIStore();

  const expiringSoon = certs.filter((c) => {
    const d = daysUntil(c.expiry);
    return d >= 0 && d < 30;
  }).length;

  const expired = certs.filter((c) => daysUntil(c.expiry) < 0).length;
  const valid = certs.length - expiringSoon - expired;
  const caStatusText = caInfo?.exists ? 'نشط (Active)' : 'غير مهيأ';

  return (
    <div className="pki-kpi-grid">
      <div onClick={() => setStatusFilter('VALID')} style={{ cursor: 'pointer' }}>
        <KpiCard
          icon={<ShieldCheck size={18} />}
          value={isLoading ? '...' : valid}
          label="شهادات صالحة"
          color="#28c76f"
          delay={0}
        />
      </div>

      <div onClick={() => setStatusFilter('EXPIRING')} style={{ cursor: 'pointer' }}>
        <KpiCard
          icon={<Clock size={18} />}
          value={isLoading ? '...' : expiringSoon}
          label="تنتهي خلال 30 يوم"
          color="#ffc107"
          delay={0.07}
        />
      </div>

      <div onClick={() => setStatusFilter('EXPIRED')} style={{ cursor: 'pointer' }}>
        <KpiCard
          icon={<XCircle size={18} />}
          value={isLoading ? '...' : expired}
          label="منتهية الصلاحية"
          color="#ff5f5f"
          delay={0.14}
        />
      </div>

      <div onClick={() => setStatusFilter('ALL')} style={{ cursor: 'pointer' }}>
        <KpiCard
          icon={<Key size={18} />}
          value={isLoading ? '...' : certs.length}
          label="إجمالي الشهادات"
          color="#00d4ff"
          delay={0.21}
        />
      </div>

      <div>
        <KpiCard
          icon={<Award size={18} />}
          value={caInfo ? caStatusText : '...'}
          label="سلطة Root CA"
          color={caInfo?.exists ? '#00d4ff' : '#ff9f43'}
          delay={0.28}
        />
      </div>
    </div>
  );
}
