import { User, Activity, MapPin, UserX, Clock, Database, Search } from 'lucide-react';
import { RadarChart, PolarGrid, PolarAngleAxis, Radar, ResponsiveContainer } from 'recharts';
import { fmtScore, getRiskColor, translateRiskLevel } from './Helpers';

export function UserProfileCard({ selectedUser, profile, userEvents, onReset, isResetting }) {
  if (!selectedUser) {
    return (
      <div className="uba-panel uba-empty" style={{ flex: 1, justifyContent: 'center' }}>
        <Search size={54} strokeWidth={1} style={{ opacity: 0.1, marginBottom: 10 }} />
        <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 800, color: '#f0f0f5' }}>بروفايل الكيان وقياس البصمة</h3>
        <p style={{ margin: 0, maxWith: 380, color: 'rgba(255,255,255,0.4)', lineHeight: 1.6 }}>يرجى تحديد ومراقبة هوية معينة من اللوحة الجانبية لكشف السجل التفصيلي للتصرفات والأساس المعياري.</p>
      </div>
    );
  }

  if (!profile) {
    return (
      <div className="uba-panel uba-empty" style={{ flex: 1, justifyContent: 'center' }}>
        <div style={{ color: 'rgba(255,255,255,0.3)', fontSize: '0.85rem' }}>جاري تحميل الملف الشخصي...</div>
      </div>
    );
  }

  // Map profile metrics for Radar chart
  const radarData = Object.entries(profile.metrics || {}).map(([key, value]) => ({
    subject: key.replace(/_score/g, ''),
    A: value,
    fullMark: 1.0,
  }));

  return (
    <>
      {/* ── Left Sidebar: Profile Details ── */}
      <div className="uba-panel" style={{ width: 330, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 14 }}>
        <div className="uba-profile-header">
          <div className="uba-avatar"><User size={28} /></div>
          <div>
            <h3 className="uba-profile-name" dir="ltr">{profile.username}</h3>
            <span className="uba-mono" style={{ fontSize: '.75rem', opacity: .4 }} dir="ltr">{profile.ip}</span>
          </div>
          <button
            className="uba-reset-btn"
            onClick={() => onReset(profile.username)}
            disabled={isResetting}
          >
            {isResetting ? 'جاري إعادة التعيين...' : 'إعادة التعيين'}
          </button>
        </div>

        {/* Risk Score */}
        <div className="uba-risk-radial" style={{ '--color': getRiskColor(profile.risk_level) }}>
          <div className="uba-radial-center">
            <span className="uba-radial-val">{fmtScore(profile.risk_score)}</span>
            <span className="uba-radial-lbl">درجة الانحراف</span>
          </div>
        </div>

        {/* Info list */}
        <div className="uba-info-list uba-mono">
          {[
            { icon: <Activity size={13} />, label: 'مستوى الخطورة', val: translateRiskLevel(profile.risk_level), valColor: getRiskColor(profile.risk_level) },
            { 
              icon: <MapPin size={13} />, 
              label: 'الموقع الجغرافي', 
              val: profile.geoip 
                ? `${profile.geoip.flag ? profile.geoip.flag + ' ' : ''}${profile.geoip.country}${profile.geoip.city && profile.geoip.city !== 'محلي' && profile.geoip.city !== 'غير معروف' ? ' - ' + profile.geoip.city : ''}` 
                : 'شبكة محلية' 
            },
            { icon: <Clock size={13} />, label: 'آخر نشاط', val: (profile.last_active || profile.last_seen) ? new Date(profile.last_active || profile.last_seen).toLocaleTimeString('ar-SA') : 'الآن' },
            { icon: <Database size={13} />, label: 'إجمالي الأحداث', val: profile.events_count ?? profile.event_count ?? 0 },
            { icon: <UserX size={13} />, label: 'محاولات فاشلة', val: profile.failed_attempts || 0 },
          ].map((item, i) => (
            <div key={i} className="uba-info-item">
              <span className="uba-info-lbl">{item.icon} {item.label}</span>
              <span className="uba-info-val" style={item.valColor ? { color: item.valColor, fontWeight: 800 } : {}}>{item.val}</span>
            </div>
          ))}
        </div>

        {/* Radar profile */}
        {radarData.length > 0 && (
          <div style={{ flex: 1, maxHeight: 180, display: 'flex', justifyContent: 'center' }}>
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart cx="50%" cy="50%" outerRadius="70%" data={radarData}>
                <PolarGrid stroke="rgba(255,255,255,0.05)" />
                <PolarAngleAxis dataKey="subject" tick={{ fill: 'rgba(255,255,255,0.3)', fontSize: 9 }} />
                <Radar name={profile.username} dataKey="A" stroke="#06b6d4" fill="#06b6d4" fillOpacity={0.15} />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      {/* ── Right Panel: Entity Events list ── */}
      <div className="uba-panel" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
        <div className="uba-panel-header">
          <div>
            <div className="uba-panel-title">تفاصيل الأنشطة التاريخية للكيان</div>
            <div className="uba-panel-sub">جميع حركات الوصول المسجلة والتحليلات الخاصة بالمحققين.</div>
          </div>
        </div>

        <div className="uba-table-wrap" style={{ flex: 1 }}>
          <table className="uba-table">
            <thead>
              <tr>
                <th>الوقت</th>
                <th>الخدمة المستهدفة</th>
                <th>نتيجة الانحراف</th>
                <th>العدسات النشطة (Detectors)</th>
                <th>الإجراء المتخذ</th>
              </tr>
            </thead>
            <tbody>
              {userEvents?.events?.length === 0 && (
                <tr>
                  <td colSpan={5} style={{ textAlign: 'center', padding: 20, color: 'var(--text-muted)' }}>
                    لا توجد أحداث مسجلة لهذا الكيان.
                  </td>
                </tr>
              )}
              {userEvents?.events?.map((e, idx) => (
                <tr key={idx} className="uba-row">
                  <td className="uba-mono" style={{ color: 'rgba(255,255,255,0.35)', fontSize: '.75rem' }} dir="ltr">{new Date(e.event_time).toLocaleString('ar-SA')}</td>
                  <td className="uba-mono" style={{ fontSize: '.8rem' }} dir="ltr">{e.target_service}</td>
                  <td className="uba-mono" style={{ color: getRiskColor(e.anomaly_score > 0.7 ? 'critical' : e.anomaly_score > 0.4 ? 'high' : 'low'), fontWeight: 800 }} dir="ltr">{fmtScore(e.anomaly_score)}</td>
                  <td>
                    <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                      {(() => {
                        let ds = e.detectors_triggered;
                        if (typeof ds === 'string') {
                          try { ds = JSON.parse(ds); } catch { ds = [ds]; }
                        }
                        return (ds || []).map(d => <span key={d} className="uba-tag uba-mono" style={{ fontSize: '.65rem' }}>{d.replace('_detector', '')}</span>);
                      })()}
                    </div>
                  </td>
                  <td>
                    {e.action_taken === 7 || String(e.action_taken).includes('DECOY') ? <span className="uba-tag uba-tag-danger"><Activity size={11} /> الإيقاع بـLabyrinth</span>
                      : e.action_taken === 6 || String(e.action_taken).includes('PERTURB') ? <span className="uba-tag uba-tag-warn"><Activity size={11} /> تشويش واستهلاك موارد</span>
                        : <span className="uba-tag">{e.action_taken}</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}

export default UserProfileCard;
