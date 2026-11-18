import React, { useState } from 'react';
import { X, Key, Users, Globe, Server, RefreshCw, Plus, ShieldCheck } from 'lucide-react';
import ConfigField from './ConfigField';

export function AddPeerModal({ isOpen, onClose, onSubmit, onAdd, onGenerateKeys, onGenKeys, loading }) {
  if (!isOpen) return null;

  const [peer, setPeer] = useState({
    name: '', public_key: '', allowed_ips: '10.99.0.2/32',
    endpoint: '', persistent_keepalive: 25,
  });
  const [generatedPrivateKey, setGeneratedPrivateKey] = useState('');
  const [genLoading, setGenLoading] = useState(false);

  const submitFn = onSubmit || onAdd;
  const genKeysFn = onGenerateKeys || onGenKeys;

  const set = (k) => (e) => setPeer(p => ({ ...p, [k]: e.target.value }));

  const handleAdd = (e) => {
    e.preventDefault();
    if (submitFn) {
      submitFn(
        { ...peer, allowed_ips: peer.allowed_ips.split(',').map(s => s.trim()) },
        generatedPrivateKey
      );
    }
  };

  const handleGenKeys = async () => {
    if (!genKeysFn) return;
    setGenLoading(true);
    try {
      const result = await genKeysFn();
      if (result?.public_key) {
        setPeer(p => ({ ...p, public_key: result.public_key }));
        if (result.private_key) {
          setGeneratedPrivateKey(result.private_key);
        }
      }
    } finally {
      setGenLoading(false);
    }
  };

  return (
    <div className="vpn-modal-overlay" onClick={onClose}>
      <div className="vpn-modal" onClick={e => e.stopPropagation()}>

        <div className="vpn-modal-header">
          <div className="vpn-modal-title">
            <div className="vpn-modal-icon">
              <Users size={18} style={{ color: '#00c8ff' }} />
            </div>
            إضافة عميل VPN جديد (WireGuard Peer)
          </div>
          <button type="button" className="vpn-modal-close" onClick={onClose}>
            <X size={16} />
          </button>
        </div>

        <form onSubmit={handleAdd}>
          <div className="vpn-modal-body">

            <ConfigField label="اسم العميل / المُعرّف" icon={Users}>
              <input
                className="vpn-input"
                type="text"
                placeholder="مثال: جهاز المحمول للمشرف"
                value={peer.name}
                onChange={set('name')}
                autoFocus
                required
              />
            </ConfigField>

            <ConfigField label="المفتاح العام (Public Key)" icon={Key}>
              <div style={{ display: 'flex', gap: 8 }}>
                <input
                  className="vpn-input"
                  type="text"
                  dir="ltr"
                  placeholder="أدخل المفتاح العام هنا..."
                  value={peer.public_key}
                  onChange={set('public_key')}
                  required
                  style={{ flex: 1 }}
                />
                <button
                  type="button"
                  className="vpn-gen-btn"
                  onClick={handleGenKeys}
                  disabled={genLoading}
                  title="توليد زوج مفاتيح جديد تلقائياً"
                >
                  {genLoading ? <RefreshCw size={13} className="vpn-spin" /> : <Key size={13} />}
                  توليد
                </button>
              </div>
            </ConfigField>

            {generatedPrivateKey && (
              <div className="vpn-key-generated-banner">
                <ShieldCheck size={16} style={{ color: '#28c76f', flexShrink: 0 }} />
                <div>
                  <div style={{ fontWeight: 700, color: '#28c76f', fontSize: '0.8rem' }}>
                    تم توليد زوج مفاتيح بنجاح!
                  </div>
                  <div style={{ fontSize: '0.73rem', opacity: 0.85, fontFamily: 'monospace' }} dir="ltr">
                    PrivateKey: {generatedPrivateKey.substring(0, 16)}…
                  </div>
                </div>
              </div>
            )}

            <ConfigField
              label="العناوين المسموحة (Allowed IPs)"
              icon={Globe}
              hint="العناوين المخصصة لهذا العميل عبر الـ VPN (مثال: 10.99.0.2/32)"
            >
              <input
                className="vpn-input"
                type="text"
                dir="ltr"
                placeholder="10.99.0.2/32"
                value={peer.allowed_ips}
                onChange={set('allowed_ips')}
                required
              />
            </ConfigField>

            <ConfigField
              label="نقطة النهاية Endpoint (اختياري)"
              icon={Server}
              hint="عنوان الـ IP والمنفذ الخارجي للعميل إن وجد (IP:Port)"
            >
              <input
                className="vpn-input"
                type="text"
                dir="ltr"
                placeholder="peer.example.com:51820"
                value={peer.endpoint}
                onChange={set('endpoint')}
              />
            </ConfigField>
          </div>

          <div className="vpn-modal-footer">
            <button type="button" className="vpn-btn vpn-btn--ghost" onClick={onClose}>
              إلغاء
            </button>
            <button type="submit" className="vpn-btn vpn-btn--primary" disabled={loading}>
              {loading ? <><RefreshCw size={14} className="vpn-spin" /> يُضاف...</> : <><Plus size={14} /> إضافة العميل</>}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default AddPeerModal;
