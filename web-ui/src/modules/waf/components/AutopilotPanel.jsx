import React from 'react';
import { Eye, Activity, AlertOctagon, RefreshCw, Play, StopCircle, HardDrive } from 'lucide-react';
import { SectionCard, EmptyState, StatusBadge } from '../../../components/Shared';

export function AutopilotPanel({
  apStatus,
  startShadowMode,
  stopShadowMode,
  exportShadowSchema,
  startingShadowMode,
  stoppingShadowMode,
  exportingShadowSchema
}) {
  const isLearning = apStatus?.status === 'learning';
  const progress = apStatus?.progress_percent || 0;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
      <div className="waf-autopilot-hero">
        <div className={`waf-ap-orb ${isLearning ? 'active' : ''}`}>
          <Eye size={40} style={{ color: isLearning ? 'var(--accent)' : 'var(--text-muted)' }} />
        </div>
        <h2 style={{ fontSize: '1.4rem', fontWeight: 800, margin: '16px 0 8px' }}>الطيار الآلي في الظل</h2>
        <p style={{ color: 'var(--text-secondary)', maxWidth: 500, margin: '0 auto', lineHeight: 1.6 }}>
          يراقب حركة المرور الاعتيادية تلقائياً دون حجب، ويستخدم النمذجة الهيكلية لتوليد
          <strong style={{ color: 'var(--text-primary)' }}> مخطط API بمبدأ الثقة الصفرية</strong> مُعيَّن للبيئة الإنتاجية.
        </p>
      </div>

      {apStatus?.status === 'not_initialized' ? (
        <SectionCard>
          <EmptyState message="محرك الطيار الآلي غير مهيأ. راجع الإعدادات." icon={AlertOctagon} />
        </SectionCard>
      ) : (
        <SectionCard title="حالة الاستكشاف" icon={Activity}>
          <div className="waf-ap-stat-row">
            <span>حالة النظام</span>
            <StatusBadge status={isLearning ? 'monitor' : 'disabled'} />
          </div>
          <div className="waf-ap-stat-row">
            <span>نقاط النهاية المُنشئة الملف</span>
            <strong className="mono" style={{ fontSize: '1.2rem', color: 'var(--accent)' }}>{apStatus?.endpoints_profiled || 0}</strong>
          </div>

          {isLearning && (
            <div style={{ marginTop: 'var(--sp-4)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', marginBottom: 8, color: 'var(--text-muted)' }}>
                <span>نافذة التعلم المتبقية</span>
                <span className="mono">{apStatus?.hours_remaining?.toFixed(1) || 0} ساعة</span>
              </div>
              <div style={{ height: 8, background: 'var(--bg-overlay)', borderRadius: 4, overflow: 'hidden' }}>
                <div style={{ height: '100%', width: `${progress}%`, background: 'var(--accent)', transition: 'width 1s' }} />
              </div>
              <div style={{ textAlign: 'center', fontSize: '0.75rem', marginTop: 8, color: 'var(--text-muted)' }} className="mono">
                {progress.toFixed(1)}% مكتمل
              </div>
            </div>
          )}
        </SectionCard>
      )}

      <div style={{ display: 'flex', gap: 12, justifyContent: 'center', marginTop: 'var(--sp-4)' }}>
        {!isLearning ? (
          <button className="btn btn-primary" onClick={() => startShadowMode()} disabled={startingShadowMode}>
            {startingShadowMode ? <RefreshCw size={16} className="waf-spin" /> : <Play size={16} />} بدء مراقبة الظل (24 ساعة)
          </button>
        ) : (
          <button className="btn btn-danger" onClick={() => stopShadowMode()} disabled={stoppingShadowMode}>
            {stoppingShadowMode ? <RefreshCw size={16} className="waf-spin" /> : <StopCircle size={16} />} إيقاف المراقبة
          </button>
        )}
        <button className="btn btn-ghost" onClick={() => exportShadowSchema()} disabled={exportingShadowSchema || !apStatus?.endpoints_profiled}>
          {exportingShadowSchema ? <RefreshCw size={16} className="waf-spin" /> : <HardDrive size={16} />} تصدير المخطط المُجمَّع
        </button>
      </div>
    </div>
  );
}
