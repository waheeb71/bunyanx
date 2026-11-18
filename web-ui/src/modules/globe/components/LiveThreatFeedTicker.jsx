import { AlertTriangle, ShieldAlert, CheckCircle2, ChevronRight } from 'lucide-react';
import { useGlobeStore } from '../stores/useGlobeStore';

export function LiveThreatFeedTicker({ threatFeed = [] }) {
  const setSelectedThreat = useGlobeStore((s) => s.setSelectedThreat);

  return (
    <div className="gtm-card gtm-ticker-card">
      <div className="gtm-card-header flex-row">
        <h3 className="gtm-card-title flex align-center gap-2">
          <ShieldAlert size={16} className="text-cyan" />
          <span>بث التهديدات المباشرة</span>
        </h3>
        <span className="gtm-feed-count">{threatFeed.length} أحداث</span>
      </div>

      <div className="gtm-ticker-list">
        {threatFeed.length === 0 ? (
          <div className="gtm-empty-state">لا توجد تنبيهات حية حالياً</div>
        ) : (
          threatFeed.map((item, idx) => {
            const sevClass = item.sev === 'critical' ? 'critical' : item.sev === 'high' ? 'high' : 'medium';
            const isBlocked = item.blocked || item.action === 'BLOCK';

            return (
              <div
                key={item.id || idx}
                className="gtm-ticker-item"
                onClick={() => setSelectedThreat(item)}
              >
                <div className="gtm-ticker-left">
                  <span className="gtm-flag">{item.flag || '🌐'}</span>
                  <div className="gtm-ip-info">
                    <span className="gtm-ip">{item.ip || '0.0.0.0'}</span>
                    <span className="gtm-type">{item.type || 'Intrusion'}</span>
                  </div>
                </div>

                <div className="gtm-ticker-right">
                  <span className={`gtm-sev-badge ${sevClass}`}>
                    {item.sev === 'critical' ? 'حرج' : item.sev === 'high' ? 'مرتفع' : 'متوسط'}
                  </span>
                  <span className={`gtm-action-badge ${isBlocked ? 'blocked' : 'allowed'}`}>
                    {isBlocked ? 'تم الحظر' : 'مرور'}
                  </span>
                  <ChevronRight size={14} className="gtm-inspect-arrow" />
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

export default LiveThreatFeedTicker;
