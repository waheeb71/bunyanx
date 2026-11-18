import React from 'react';
import { ShieldAlert, ShieldCheck, AlertTriangle } from 'lucide-react';

export default function SecurityDiagnosticsCard({ validation, warnings, isLoading }) {
  const allSecure = validation?.all_secure;

  return (
    <div className="sh-card" style={{ borderColor: allSecure ? 'rgba(40,199,111,0.2)' : 'rgba(255,95,95,0.2)' }}>
      <div className="sh-card-header">
        <div
          className="sh-card-icon"
          style={{
            background: allSecure ? 'rgba(40,199,111,0.1)' : 'rgba(255,95,95,0.1)',
            border: `1px solid ${allSecure ? 'rgba(40,199,111,0.25)' : 'rgba(255,95,95,0.25)'}`,
          }}
        >
          <ShieldAlert size={17} style={{ color: allSecure ? '#28c76f' : '#ff5f5f' }} />
        </div>
        <span className="sh-card-title">تشخيصات حماية البيئة والتشفير</span>
      </div>

      <div className="sh-card-body">
        {isLoading ? (
          <div style={{ color: 'rgba(255,255,255,0.4)', fontSize: '0.85rem' }}>
            جاري تشخيص ثغرات المفاتيح والمفاهيم التشفيرية...
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div
              style={{
                background: allSecure ? 'rgba(40,199,111,0.06)' : 'rgba(255,193,7,0.08)',
                border: `1px solid ${allSecure ? 'rgba(40,199,111,0.2)' : 'rgba(255,193,7,0.2)'}`,
                padding: '10px 12px',
                borderRadius: 6,
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                fontSize: '0.8rem',
              }}
            >
              {allSecure ? (
                <>
                  <ShieldCheck size={16} style={{ color: '#28c76f' }} />
                  <span style={{ color: '#28c76f', fontWeight: 700 }}>
                    جميع مفاتيح البيئة التشفيرية مهيأة بشكل آمن ومغلقة.
                  </span>
                </>
              ) : (
                <>
                  <AlertTriangle size={16} style={{ color: '#ffc107' }} />
                  <span style={{ color: '#ffc107', fontWeight: 700 }}>
                    تحذير: تم رصد مفاتيح تشفيرية ضعيفة أو افتراضية.
                  </span>
                </>
              )}
            </div>

            {/* Checks List */}
            <div style={{ maxHeight: 160, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 6 }}>
              {validation?.checks?.map((check) => (
                <div
                  key={check.key}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    fontSize: '0.78rem',
                    padding: '4px 6px',
                    borderBottom: '1px solid rgba(255,255,255,0.03)',
                  }}
                >
                  <span dir="ltr" className="mono" style={{ color: 'rgba(255,255,255,0.6)' }}>
                    {check.key}
                  </span>
                  <span
                    style={{
                      fontWeight: 700,
                      color: check.status === 'secure' ? '#28c76f' : check.status === 'weak' ? '#ffc107' : '#ff5f5f',
                    }}
                  >
                    {check.status === 'secure' ? 'آمن' : check.status === 'weak' ? 'ضعيف' : 'مفتوح/تلقائي'}
                  </span>
                </div>
              ))}
            </div>

            {/* Security Warnings */}
            {warnings && warnings.length > 0 && (
              <div style={{ marginTop: 6 }}>
                <div
                  style={{
                    fontSize: '0.75rem',
                    fontWeight: 700,
                    color: '#ff5f5f',
                    marginBottom: 4,
                    display: 'flex',
                    alignItems: 'center',
                    gap: 4,
                  }}
                >
                  <AlertTriangle size={12} /> تحذيرات الثغرات المحتملة:
                </div>
                {warnings.map((warn, i) => (
                  <div
                    key={i}
                    style={{
                      fontSize: '0.75rem',
                      color: 'rgba(255,255,255,0.6)',
                      background: 'rgba(255,95,95,0.05)',
                      padding: '6px 8px',
                      borderRadius: 4,
                      border: '1px solid rgba(255,95,95,0.1)',
                      marginBottom: 4,
                    }}
                  >
                    {warn.message}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
