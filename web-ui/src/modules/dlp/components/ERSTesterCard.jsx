import React from 'react';
import { Zap, Send, Activity, Sparkles, CheckCircle2, AlertTriangle, ShieldAlert } from 'lucide-react';
import { RadialBarChart, RadialBar } from 'recharts';
import { useDLPStore } from '../store/dlpStore';
import { useDLP } from '../hooks/useDLP';

function ERSGauge({ score, label }) {
  const color =
    score >= 0.80 ? '#ff4d6a' : score >= 0.60 ? '#ffab40' : score >= 0.35 ? '#fbbf24' : '#00e676';
  const pct = Math.round(score * 100);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6 }}>
      <div style={{ position: 'relative', width: 100, height: 100, display: 'flex', justifyContent: 'center' }}>
        <RadialBarChart
          width={100}
          height={100}
          cx="50%"
          cy="50%"
          innerRadius="70%"
          outerRadius="100%"
          startAngle={210}
          endAngle={-30}
          data={[{ value: pct, fill: color }]}
        >
          <RadialBar minAngle={5} dataKey="value" cornerRadius={6} isAnimationActive={true} />
        </RadialBarChart>
        <div
          style={{
            position: 'absolute',
            inset: 0,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          <span style={{ fontWeight: 800, fontSize: '1.2rem', color, fontFamily: 'JetBrains Mono, monospace' }} dir="ltr">
            {pct}%
          </span>
        </div>
      </div>
      <span style={{ fontSize: '0.74rem', color: 'var(--text-secondary)', fontWeight: 700 }}>{label}</span>
    </div>
  );
}

function SignalBar({ label, value, color }) {
  const val = value ?? 0;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.76rem' }}>
        <span style={{ color: 'var(--text-secondary)' }}>{label}</span>
        <span style={{ color, fontWeight: 700, fontFamily: 'JetBrains Mono, monospace' }} dir="ltr">
          {(val * 100).toFixed(0)}%
        </span>
      </div>
      <div style={{ height: 6, background: 'rgba(255, 255, 255, 0.08)', borderRadius: 4, overflow: 'hidden' }}>
        <div
          style={{
            height: '100%',
            width: `${val * 100}%`,
            background: color,
            borderRadius: 4,
            transition: 'width 0.5s ease',
          }}
        />
      </div>
    </div>
  );
}

export default function ERSTesterCard() {
  const { ersForm, updateErsForm, ersResult, setErsResult } = useDLPStore();
  const { testErs } = useDLP();

  const handleTest = (e) => {
    e.preventDefault();
    if (!ersForm.payload_hex) return;
    testErs.mutate(ersForm, {
      onSuccess: (data) => setErsResult(data),
    });
  };

  const signals = ersResult?.signals;
  const SIGNAL_COLORS = {
    entropy: '#ff4d6a',
    velocity: '#ffab40',
    chunking: '#fbbf24',
    protocol: '#00e676',
    protocol_deviation: '#00e676',
    accumulation: '#00c8ff',
    msem: '#818cf8',
  };

  const translateDecision = (d) => {
    switch (d) {
      case 'EXFILTRATION':
        return 'إرسال تسريبي مؤكد (حظر فوري)';
      case 'HIGH_RISK':
        return 'مخاطرة شديدة جداً';
      case 'SUSPICIOUS':
        return 'سلوك شاذ ومشبوه';
      case 'NORMAL':
        return 'حركة بيانات طبيعية وآمنة';
      default:
        return d;
    }
  };

  const translateSignals = (k) => {
    switch (k) {
      case 'entropy':
        return 'العشوائية (Shannon Entropy)';
      case 'velocity':
        return 'طفرة السرعة والتدفق';
      case 'chunking':
        return 'التقطيع الدقيق الثابت';
      case 'protocol':
      case 'protocol_deviation':
        return 'انحراف بروتوكول النقل';
      case 'accumulation':
        return 'التراكم الزمني (24h)';
      case 'msem':
        return 'إشارات MSEM-Lite العصبية';
      default:
        return k.replace('_', ' ');
    }
  };

  return (
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
          <Zap size={18} />
        </div>
        <div>
          <h3 style={{ fontWeight: 800, fontSize: '1rem', color: 'var(--text-primary)', margin: 0 }}>
            مختبر ومحاكي درجات الخطر السلوكي (ERS Signal Sandbox)
          </h3>
          <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
            اختبار حمولات Hex ومعاينة تحليل محرك BEFP لدرجة الخطر في الوقت الفعلي
          </span>
        </div>
      </div>

      <form onSubmit={handleTest} style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        <div>
          <label style={{ display: 'block', fontSize: '0.74rem', color: 'var(--text-secondary)', marginBottom: 4 }}>
            حمولة البيانات السداسية عشرية (Payload Hex String)
          </label>
          <textarea
            className="input"
            rows={3}
            placeholder="48656c6c6f20576f726c64... (أدخل سلسلة Hex للتجربة)"
            value={ersForm.payload_hex || ''}
            onChange={(e) => updateErsForm({ payload_hex: e.target.value })}
            style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.78rem', direction: 'ltr', textAlign: 'left', width: '100%' }}
            required
          />
        </div>

        <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
          <button
            type="submit"
            className="btn btn-primary"
            disabled={testErs.isPending}
            style={{ padding: '8px 18px', fontSize: '0.8rem', fontWeight: 700 }}
          >
            <Activity size={14} /> {testErs.isPending ? 'جاري الفحص السلوكي...' : 'تشغيل الاختبار ومحاكاة ERS'}
          </button>
        </div>
      </form>

      {/* ── Test Results ── */}
      {ersResult && (
        <div
          style={{
            marginTop: 20,
            padding: 16,
            background: 'rgba(255, 255, 255, 0.02)',
            borderRadius: 12,
            border: '1px solid rgba(0, 200, 255, 0.2)',
            display: 'flex',
            flexDirection: 'column',
            gap: 16,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 14 }}>
            <ERSGauge score={ersResult.ers_score ?? 0} label="درجة الخطر التراكمي (ERS)" />

            <div style={{ flex: 1, minWidth: '220px' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>القرار الأمني للمحرك</div>
              <div
                style={{
                  fontSize: '1rem',
                  fontWeight: 800,
                  color:
                    ersResult.ers_score >= 0.8 ? '#ff4d6a' : ersResult.ers_score >= 0.5 ? '#ffab40' : '#00e676',
                  marginTop: 2,
                }}
              >
                {translateDecision(ersResult.decision)}
              </div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', marginTop: 4 }}>
                زمن الاستدلال العصبي: <code style={{ color: '#00c8ff' }}>{ersResult.latency_ms || '0.12'} ms</code>
              </div>
            </div>
          </div>

          {signals && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 10, paddingTop: 10, borderTop: '1px solid rgba(255, 255, 255, 0.06)' }}>
              {Object.entries(signals).map(([sigKey, sigVal]) => (
                <SignalBar
                  key={sigKey}
                  label={translateSignals(sigKey)}
                  value={sigVal}
                  color={SIGNAL_COLORS[sigKey] || '#00c8ff'}
                />
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
