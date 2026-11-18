import React from 'react';
import {
  ChevronDown, ChevronUp, RefreshCw, AlertTriangle, Eye, TrendingUp,
  Wifi, HardDrive, ShieldCheck, Activity, BrainCircuit, Zap
} from 'lucide-react';
import { useDLPStore } from '../store/dlpStore';
import { useDLPIpProfile, useDLPMsemProfile } from '../hooks/useDLP';

function HighRiskCard({ ip, expanded, onExpand }) {
  const { data: profile, isFetching: isFetchingProfile } = useDLPIpProfile(ip.src_ip, expanded);
  const { data: msemData } = useDLPMsemProfile(ip.src_ip, expanded);

  const riskColor =
    ip.total_bytes_24h >= 500 * 1024 * 1024
      ? '#ff4d6a'
      : ip.total_bytes_24h >= 200 * 1024 * 1024
      ? '#ffab40'
      : '#fbbf24';
  const mb = (ip.total_bytes_24h / (1024 * 1024)).toFixed(1);

  return (
    <div
      style={{
        background: 'rgba(10, 14, 26, 0.75)',
        backdropFilter: 'blur(12px)',
        borderRadius: '12px',
        border: `1px solid ${expanded ? riskColor : 'rgba(255, 255, 255, 0.08)'}`,
        overflow: 'hidden',
        transition: 'all 0.2s ease-in-out',
        boxShadow: expanded ? `0 4px 24px ${riskColor}20` : '0 2px 10px rgba(0, 0, 0, 0.3)',
      }}
    >
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          padding: '14px 18px',
          cursor: 'pointer',
          userSelect: 'none',
        }}
        onClick={onExpand}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div
            style={{
              width: 10,
              height: 10,
              borderRadius: '50%',
              background: riskColor,
              boxShadow: `0 0 10px ${riskColor}`,
            }}
          />
          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontWeight: 800, fontSize: '0.95rem', color: '#00c8ff' }} dir="ltr">
            {ip.src_ip}
          </span>
          <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
            {ip.destinations} {ip.destinations === 1 ? 'وجهة مستهدفة' : 'وجهات مستهدفة'}
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, direction: 'ltr' }}>
          <span style={{ fontWeight: 800, color: riskColor, fontFamily: 'JetBrains Mono, monospace', fontSize: '0.95rem' }}>
            {mb} MB
          </span>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>/ 24h</span>
          {expanded ? <ChevronUp size={16} style={{ color: 'var(--text-secondary)' }} /> : <ChevronDown size={16} style={{ color: 'var(--text-secondary)' }} />}
        </div>
      </div>

      {expanded && (
        <div style={{ padding: '0 18px 16px', borderTop: '1px solid rgba(255, 255, 255, 0.06)' }}>
          {isFetchingProfile ? (
            <div
              style={{
                padding: '16px 0',
                color: 'var(--text-secondary)',
                fontSize: '0.82rem',
                display: 'flex',
                alignItems: 'center',
                gap: 8,
              }}
            >
              <RefreshCw size={14} style={{ animation: 'spin 1s linear infinite', color: '#00c8ff' }} />
              جاري تحميل البصمة السلوكية للعنوان...
            </div>
          ) : profile ? (
            <div style={{ paddingTop: 14, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              <div style={{ padding: '12px 14px', background: 'rgba(255, 255, 255, 0.02)', borderRadius: 10, border: '1px solid rgba(255, 255, 255, 0.06)' }}>
                <div style={{ fontSize: '0.74rem', color: 'var(--text-secondary)', marginBottom: 4 }}>
                  معدل السرعة والتدفق الأساسي
                </div>
                <div style={{ fontFamily: 'JetBrains Mono, monospace', fontWeight: 800, fontSize: '1rem', color: '#00c8ff' }} dir="ltr">
                  {(profile.baseline_velocity_bps / 1024).toFixed(2)} KB/s
                </div>
              </div>

              <div style={{ padding: '12px 14px', background: 'rgba(255, 255, 255, 0.02)', borderRadius: 10, border: '1px solid rgba(255, 255, 255, 0.06)' }}>
                <div style={{ fontSize: '0.74rem', color: 'var(--text-secondary)', marginBottom: 4 }}>
                  العينات السلوكية المجمعة
                </div>
                <div style={{ fontFamily: 'JetBrains Mono, monospace', fontWeight: 800, fontSize: '1rem', color: '#00e676' }}>
                  {profile.baseline_samples} عينة
                </div>
              </div>

              {Object.entries(profile.accumulation_24h_bytes || {}).slice(0, 4).map(([dst, bytes]) => (
                <div key={dst} style={{ gridColumn: '1/-1', background: 'rgba(255, 255, 255, 0.02)', padding: '12px 14px', borderRadius: 10, border: '1px solid rgba(255, 255, 255, 0.05)' }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: 6, direction: 'ltr', textAlign: 'left', fontFamily: 'JetBrains Mono, monospace' }}>
                    {dst} ←
                  </div>
                  <div style={{ height: 6, background: 'rgba(255, 255, 255, 0.08)', borderRadius: 4, overflow: 'hidden' }}>
                    <div
                      style={{
                        height: '100%',
                        borderRadius: 4,
                        background: riskColor,
                        width: `${Math.min((bytes / (500 * 1024 * 1024)) * 100, 100)}%`,
                        transition: 'width 0.5s ease',
                      }}
                    />
                  </div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', marginTop: 4, textAlign: 'left', direction: 'ltr', fontFamily: 'JetBrains Mono, monospace', fontWeight: 700 }}>
                    {(bytes / (1024 * 1024)).toFixed(1)} MB
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', padding: '14px 0', margin: 0 }}>
              لا يوجد سجل تفصيلي متاح حالياً لهذا العنوان.
            </p>
          )}
        </div>
      )}
    </div>
  );
}

export default function DLPMonitorCard({ highRisk = [], isFetching = false, refetch }) {
  const { expandedIp, toggleExpandedIp } = useDLPStore();

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* High-Risk IPs Container */}
      <div
        className="card"
        style={{
          background: 'rgba(10, 14, 26, 0.75)',
          backdropFilter: 'blur(16px)',
          border: '1px solid rgba(0, 200, 255, 0.15)',
          borderRadius: 'var(--radius-lg)',
          overflow: 'hidden',
        }}
      >
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            padding: '18px 24px',
            borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div
              style={{
                width: 36,
                height: 36,
                borderRadius: 10,
                background: 'rgba(255, 77, 106, 0.12)',
                color: '#ff4d6a',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <AlertTriangle size={18} />
            </div>
            <div>
              <h3 style={{ fontWeight: 800, fontSize: '1rem', color: 'var(--text-primary)', margin: 0 }}>
                الملفات السلوكية شديدة الخطورة (BEFP High-Risk Targets)
              </h3>
              <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
                عناوين تتجاوز معدلات النقل العادية أو تنشئ اتصالات شاذة
              </span>
            </div>
          </div>

          <button
            className="btn btn-ghost"
            onClick={() => refetch && refetch()}
            style={{ padding: '6px 14px', fontSize: '0.8rem', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: 6 }}
          >
            <RefreshCw size={14} style={{ animation: isFetching ? 'spin 1s linear infinite' : 'none', color: '#00c8ff' }} />
            {isFetching ? 'جاري التحميل...' : 'تحديث القائمة'}
          </button>
        </div>

        <div style={{ padding: '20px 24px', display: 'flex', flexDirection: 'column', gap: 12 }}>
          {highRisk.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--text-secondary)' }}>
              <ShieldCheck size={44} style={{ display: 'block', margin: '0 auto 12px', color: '#00e676', opacity: 0.8 }} />
              <p style={{ fontSize: '0.9rem', fontWeight: 700, margin: '0 0 4px', color: 'var(--text-primary)' }}>
                لا توجد عناوين أو ملفات سلوكية مشبوهة حالياً
              </p>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', margin: 0 }}>
                محرك الذكاء السلوكي (BEFP) يراقب تدفق الحزم عبر الشبكة بشكل لحظي ومستقر.
              </p>
            </div>
          ) : (
            highRisk.map((ip) => (
              <HighRiskCard
                key={ip.src_ip}
                ip={ip}
                expanded={expandedIp === ip.src_ip}
                onExpand={() => toggleExpandedIp(ip.src_ip)}
              />
            ))
          )}
        </div>
      </div>

      {/* BEFP Signal Legend Reference */}
      <div
        className="card"
        style={{
          background: 'rgba(10, 14, 26, 0.75)',
          backdropFilter: 'blur(16px)',
          border: '1px solid rgba(0, 200, 255, 0.15)',
          borderRadius: 'var(--radius-lg)',
          padding: '22px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
          <div
            style={{
              width: 36,
              height: 36,
              borderRadius: 10,
              background: 'rgba(0, 200, 255, 0.12)',
              color: '#00c8ff',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <BrainCircuit size={18} />
          </div>
          <div>
            <h3 style={{ fontWeight: 800, fontSize: '1rem', color: 'var(--text-primary)', margin: 0 }}>
              دليل ومراجع إشارات التحليل السلوكي (BEFP Telemetry Signals)
            </h3>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
              الإشارات الـ 5 التي يعتمد عليها محرك الذكاء الاصطناعي لحساب درجة الخطر (ERS)
            </span>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12 }}>
          {[
            { icon: <Wifi size={16} />, label: 'العشوائية (Shannon Entropy)', desc: 'اكتشاف وتحديد الحمولات والملفات المشفرة أو المضغوطة.', color: '#ff4d6a' },
            { icon: <TrendingUp size={16} />, label: 'شذوذ السرعة والتدفق', desc: 'طفرة مفاجئة في معدل سرعة الشبكة لعنوان ما.', color: '#ffab40' },
            { icon: <HardDrive size={16} />, label: 'أنماط التقطيع الدقيق', desc: 'تباين منخفض عبر أحجام حزم متكررة وثابتة بشكل مريب.', color: '#fbbf24' },
            { icon: <AlertTriangle size={16} />, label: 'انحراف البروتوكول', desc: 'نمط غير طبيعي أو أحجام متغيرة ببروتوكولات (DNS/ICMP).', color: '#00e676' },
            { icon: <Eye size={16} />, label: 'تراكم 24 ساعة الماضية', desc: 'الكشف عن التسريبات البطيئة للبيانات والتي تتم على فترات.', color: '#00c8ff' },
          ].map(({ icon, label, desc, color }) => (
            <div
              key={label}
              style={{
                padding: '14px 16px',
                background: 'rgba(255, 255, 255, 0.02)',
                borderRadius: '10px',
                border: '1px solid rgba(255, 255, 255, 0.06)',
                borderRight: `3px solid ${color}`,
              }}
            >
              <div style={{ color, display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6, fontWeight: 700, fontSize: '0.82rem' }}>
                {icon} {label}
              </div>
              <div style={{ fontSize: '0.74rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                {desc}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
