import { useState } from 'react';
import { ShieldCheck, ShieldAlert, Plus, Trash2, RefreshCw, CheckCircle2, AlertTriangle, RotateCcw, Search } from 'lucide-react';
import { SectionCard } from '../../../components/Shared';

export function AccessControlPanel({ settings, mutators, clearIpSession }) {
  const whitelist = settings?.access_lists?.whitelist || { ips: [], cidrs: [] };
  const blacklist = settings?.access_lists?.blacklist || { ips: [], cidrs: [] };

  const [newWhiteIp, setNewWhiteIp] = useState('');
  const [newBlackIp, setNewBlackIp] = useState('');
  const [resetIp, setResetIp] = useState('');
  
  const [actionMsg, setActionMsg] = useState(null);
  const [resetting, setResetting] = useState(false);

  // Add Whitelist IP/CIDR
  const handleAddWhite = () => {
    if (!newWhiteIp.trim()) return;
    const ipVal = newWhiteIp.trim();
    const isCidr = ipVal.includes('/');
    const updatedIps = isCidr ? whitelist.ips : [...whitelist.ips, ipVal];
    const updatedCidrs = isCidr ? [...whitelist.cidrs, ipVal] : whitelist.cidrs;

    mutators.updateWhitelist(updatedIps, updatedCidrs);
    setNewWhiteIp('');
    setActionMsg({ type: 'success', text: `تم إضافة ${ipVal} للقائمة البيضاء` });
  };

  // Remove Whitelist Entry
  const handleRemoveWhite = (val, isCidr) => {
    const updatedIps = isCidr ? whitelist.ips : whitelist.ips.filter(i => i !== val);
    const updatedCidrs = isCidr ? whitelist.cidrs.filter(c => c !== val) : whitelist.cidrs;
    mutators.updateWhitelist(updatedIps, updatedCidrs);
  };

  // Add Blacklist IP/CIDR
  const handleAddBlack = () => {
    if (!newBlackIp.trim()) return;
    const ipVal = newBlackIp.trim();
    const isCidr = ipVal.includes('/');
    const updatedIps = isCidr ? blacklist.ips : [...blacklist.ips, ipVal];
    const updatedCidrs = isCidr ? [...blacklist.cidrs, ipVal] : blacklist.cidrs;

    mutators.updateBlacklist(updatedIps, updatedCidrs);
    setNewBlackIp('');
    setActionMsg({ type: 'success', text: `تم إضافة ${ipVal} للقائمة السوداء` });
  };

  // Remove Blacklist Entry
  const handleRemoveBlack = (val, isCidr) => {
    const updatedIps = isCidr ? blacklist.ips : blacklist.ips.filter(i => i !== val);
    const updatedCidrs = isCidr ? blacklist.cidrs.filter(c => c !== val) : blacklist.cidrs;
    mutators.updateBlacklist(updatedIps, updatedCidrs);
  };

  // Reset IP Session History
  const handleResetSession = async () => {
    if (!resetIp.trim()) return;
    setResetting(true);
    try {
      const res = await clearIpSession(resetIp.trim());
      setActionMsg({ type: 'success', text: res.data?.message || `تم إعادة ضبط سجل الجلسات للـ IP ${resetIp}` });
      setResetIp('');
    } catch (e) {
      setActionMsg({ type: 'error', text: e.response?.data?.detail || 'فشل إعادة ضبط جلسة الـ IP.' });
    } finally {
      setResetting(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--sp-4)' }}>
      
      {/* Banner */}
      {actionMsg && (
        <div style={{
          padding: '12px 16px',
          borderRadius: '8px',
          background: actionMsg.type === 'success' ? 'rgba(40, 199, 111, 0.1)' : 'rgba(234, 84, 85, 0.1)',
          border: `1px solid ${actionMsg.type === 'success' ? 'var(--success)' : 'var(--danger)'}`,
          color: actionMsg.type === 'success' ? 'var(--success)' : 'var(--danger)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          fontSize: '0.9rem'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            {actionMsg.type === 'success' ? <CheckCircle2 size={18} /> : <AlertTriangle size={18} />}
            <span>{actionMsg.text}</span>
          </div>
          <button onClick={() => setActionMsg(null)} style={{ background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', fontWeight: 'bold' }}>✕</button>
        </div>
      )}

      {/* Main Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: 'var(--sp-4)' }}>
        
        {/* Whitelist Panel */}
        <SectionCard title="القائمة البيضاء (IP Whitelist)" icon={ShieldCheck}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
              عناوين IP والشبكات الفرعية (CIDR) التي يتم استثناؤها من فحص WAF وتمريرها فوراً.
            </p>

            <div style={{ display: 'flex', gap: 8 }}>
              <input
                type="text"
                placeholder="أدخل IP أو CIDR (مثال: 192.168.1.100 أو 10.0.0.0/24)"
                value={newWhiteIp}
                onChange={e => setNewWhiteIp(e.target.value)}
                style={{ flex: 1, padding: '8px 12px', background: 'var(--bg-overlay)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text-main)' }}
                dir="ltr"
              />
              <button className="btn btn-primary" onClick={handleAddWhite} style={{ gap: 4 }}>
                <Plus size={16} /> إضافة
              </button>
            </div>

            <div style={{ background: 'var(--bg-overlay)', borderRadius: 8, padding: 12, border: '1px solid var(--border)', minHeight: 120, maxHeight: 240, overflowY: 'auto' }}>
              {[...whitelist.ips.map(ip => ({ val: ip, isCidr: false })), ...whitelist.cidrs.map(c => ({ val: c, isCidr: true }))].length === 0 ? (
                <div style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.85rem', padding: 30 }}>
                  القائمة البيضاء فارغة حالياً.
                </div>
              ) : (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                  {whitelist.ips.map(ip => (
                    <span key={ip} className="mono" style={{ display: 'inline-flex', alignItems: 'center', gap: 6, background: 'rgba(40, 199, 111, 0.15)', border: '1px solid rgba(40, 199, 111, 0.3)', color: 'var(--success)', padding: '4px 10px', borderRadius: 16, fontSize: '0.85rem' }}>
                      {ip}
                      <button onClick={() => handleRemoveWhite(ip, false)} style={{ background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', display: 'flex', alignItems: 'center' }}>
                        <Trash2 size={12} />
                      </button>
                    </span>
                  ))}
                  {whitelist.cidrs.map(cidr => (
                    <span key={cidr} className="mono" style={{ display: 'inline-flex', alignItems: 'center', gap: 6, background: 'rgba(0, 200, 255, 0.15)', border: '1px solid rgba(0, 200, 255, 0.3)', color: 'var(--accent)', padding: '4px 10px', borderRadius: 16, fontSize: '0.85rem' }}>
                      {cidr} (CIDR)
                      <button onClick={() => handleRemoveWhite(cidr, true)} style={{ background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', display: 'flex', alignItems: 'center' }}>
                        <Trash2 size={12} />
                      </button>
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>
        </SectionCard>

        {/* Blacklist Panel */}
        <SectionCard title="القائمة السوداء (IP Blacklist)" icon={ShieldAlert}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
              عناوين IP والشبكات التي يتم حجبها فوراً دون المرور بنماذج التقييم.
            </p>

            <div style={{ display: 'flex', gap: 8 }}>
              <input
                type="text"
                placeholder="أدخل IP أو CIDR للحجب المباشر"
                value={newBlackIp}
                onChange={e => setNewBlackIp(e.target.value)}
                style={{ flex: 1, padding: '8px 12px', background: 'var(--bg-overlay)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text-main)' }}
                dir="ltr"
              />
              <button className="btn btn-danger" onClick={handleAddBlack} style={{ gap: 4 }}>
                <Plus size={16} /> حجب
              </button>
            </div>

            <div style={{ background: 'var(--bg-overlay)', borderRadius: 8, padding: 12, border: '1px solid var(--border)', minHeight: 120, maxHeight: 240, overflowY: 'auto' }}>
              {[...blacklist.ips.map(ip => ({ val: ip, isCidr: false })), ...blacklist.cidrs.map(c => ({ val: c, isCidr: true }))].length === 0 ? (
                <div style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.85rem', padding: 30 }}>
                  القائمة السوداء فارغة حالياً.
                </div>
              ) : (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                  {blacklist.ips.map(ip => (
                    <span key={ip} className="mono" style={{ display: 'inline-flex', alignItems: 'center', gap: 6, background: 'rgba(234, 84, 85, 0.15)', border: '1px solid rgba(234, 84, 85, 0.3)', color: 'var(--danger)', padding: '4px 10px', borderRadius: 16, fontSize: '0.85rem' }}>
                      {ip}
                      <button onClick={() => handleRemoveBlack(ip, false)} style={{ background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', display: 'flex', alignItems: 'center' }}>
                        <Trash2 size={12} />
                      </button>
                    </span>
                  ))}
                  {blacklist.cidrs.map(cidr => (
                    <span key={cidr} className="mono" style={{ display: 'inline-flex', alignItems: 'center', gap: 6, background: 'rgba(255, 159, 67, 0.15)', border: '1px solid rgba(255, 159, 67, 0.3)', color: 'var(--warning)', padding: '4px 10px', borderRadius: 16, fontSize: '0.85rem' }}>
                      {cidr} (CIDR)
                      <button onClick={() => handleRemoveBlack(cidr, true)} style={{ background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', display: 'flex', alignItems: 'center' }}>
                        <Trash2 size={12} />
                      </button>
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>
        </SectionCard>

      </div>

      {/* IP Session Reset Tool */}
      <SectionCard title="إعادة ضبط سجل جلسة IP (IP Session Reset)" icon={RotateCcw}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
            تُفريغ تاريخ جلسة GNN والتتبع الزمني لعنوان IP معين (مفيد بعد إجراء اختبارات الاختراق المصرح بها لاستعادة تصفح الـ IP بشكل طبيعي).
          </p>

          <div style={{ display: 'flex', gap: 10, maxWidth: 500 }}>
            <input
              type="text"
              placeholder="أدخل عنوان IP (مثال: 192.168.1.50)"
              value={resetIp}
              onChange={e => setResetIp(e.target.value)}
              style={{ flex: 1, padding: '8px 12px', background: 'var(--bg-overlay)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text-main)' }}
              dir="ltr"
            />
            <button className="btn btn-warning" onClick={handleResetSession} disabled={resetting || !resetIp.trim()}>
              {resetting ? <RefreshCw size={14} className="waf-spin" /> : <RotateCcw size={14} />}
              تصفير الجلسة
            </button>
          </div>
        </div>
      </SectionCard>

    </div>
  );
}
