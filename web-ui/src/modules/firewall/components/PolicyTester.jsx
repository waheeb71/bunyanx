import { useState } from 'react';
import { motion } from 'framer-motion';
import { Play, RefreshCw, CheckCircle2, XCircle } from 'lucide-react';
import { firewallApi } from '../api/firewallApi';
import { SectionCard } from '../../../components/Shared';
import useFirewallStore from '../../../stores/firewallStore';

export function PolicyTester() {
  const { showToast } = useFirewallStore();
  const [srcIp, setSrcIp] = useState('192.168.1.50');
  const [dstIp, setDstIp] = useState('8.8.8.8');
  const [dstPort, setDstPort] = useState('53');
  const [protocol, setProtocol] = useState('udp');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleTest = async (e) => {
    e.preventDefault();
    if (!srcIp || !dstIp || !dstPort) return;
    setLoading(true);
    try {
      const res = await firewallApi.evaluatePolicy(srcIp, dstIp, parseInt(dstPort), protocol);
      setResult(res.data);
      showToast('تم محاكاة الحزمة بنجاح', 'success');
    } catch (err) {
      showToast('فشل فحص الحزمة: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <SectionCard title="محاكي وفاحص سياسات الجدار الناري (Policy Flow Tester)" icon={Play}>
      <p style={{ color: 'var(--text-secondary)', marginBottom: 'var(--sp-4)' }}>
        أدخل معلمات تدفق حزمة البيانات لمحاكاة مطابقتها الفورية مع السياسات الحالية (GeoIP &rarr; ACL &rarr; L7 App Control).
      </p>
      
      <form onSubmit={handleTest} style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 'var(--sp-4)', alignItems: 'end', marginBottom: 'var(--sp-5)' }}>
        <div className="fw-form-group" style={{ marginBottom: 0 }}>
          <label>عنوان IP المصدر (Source IP)</label>
          <input className="fw-input" value={srcIp} onChange={e => setSrcIp(e.target.value)} required placeholder="192.168.1.50" dir="ltr" />
        </div>
        <div className="fw-form-group" style={{ marginBottom: 0 }}>
          <label>عنوان IP الوجهة (Destination IP)</label>
          <input className="fw-input" value={dstIp} onChange={e => setDstIp(e.target.value)} required placeholder="8.8.8.8" dir="ltr" />
        </div>
        <div className="fw-form-group" style={{ marginBottom: 0 }}>
          <label>منفذ الوجهة (Destination Port)</label>
          <input className="fw-input" type="number" value={dstPort} onChange={e => setDstPort(e.target.value)} required placeholder="53" min="1" max="65535" dir="ltr" />
        </div>
        <div className="fw-form-group" style={{ marginBottom: 0 }}>
          <label>البروتوكول</label>
          <select className="fw-input" value={protocol} onChange={e => setProtocol(e.target.value)}>
            <option value="tcp">TCP</option>
            <option value="udp">UDP</option>
            <option value="icmp">ICMP</option>
            <option value="any">ANY</option>
          </select>
        </div>
        <button type="submit" className="fw-btn-primary" style={{ height: 42, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6 }} disabled={loading}>
          {loading ? <RefreshCw size={14} className="spin" /> : <Play size={14} />}
          محاكاة حزمة
        </button>
      </form>

      {result && (
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="card" style={{ padding: 'var(--sp-5)', border: `1px solid ${result.action === 'ALLOW' ? 'var(--success)' : 'var(--danger)'}`, background: 'var(--bg-overlay)' }}>
          <h4 style={{ margin: '0 0 var(--sp-3) 0', fontWeight: 700, color: result.action === 'ALLOW' ? 'var(--success)' : 'var(--danger)', display: 'flex', alignItems: 'center', gap: 6 }}>
            {result.action === 'ALLOW' ? <CheckCircle2 size={18} /> : <XCircle size={18} />}
            قرار التوجيه: {result.action === 'ALLOW' ? 'سماح (ALLOW)' : result.action}
          </h4>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 'var(--sp-4)' }}>
            <div>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>السبب التحليلي</span>
              <p style={{ margin: '4px 0 0 0', fontWeight: 600 }}>{result.reason}</p>
            </div>
            <div>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>درجة الثقة بالقرار</span>
              <p style={{ margin: '4px 0 0 0', fontWeight: 700, color: 'var(--accent)', fontFamily: 'var(--font-mono)' }}>{Math.round(result.confidence * 100)}%</p>
            </div>
            <div>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>القواعد المطابقة (Rules matched)</span>
              <div style={{ marginTop: 4 }}>
                {result.matched_rules && result.matched_rules.length > 0 ? (
                  result.matched_rules.map(rname => (
                    <span key={rname} className="badge badge-accent mono" style={{ fontSize: 11 }}>{rname}</span>
                  ))
                ) : (
                  <span className="badge" style={{ background: 'var(--bg-overlay)', fontSize: 11 }}>لا توجد قواعد (Default Policy)</span>
                )}
              </div>
            </div>
          </div>
        </motion.div>
      )}
    </SectionCard>
  );
}

export default PolicyTester;
