import React, { useState } from 'react';
import { Download, Copy, Check, X, FileText, ShieldAlert, QrCode, Smartphone, Terminal } from 'lucide-react';
import { QRCodeSVG } from '../../../utils/qrCode';

export function ClientConfigModal({ isOpen, peer, serverConfig = {}, privateKey, onClose }) {
  const [copied, setCopied] = useState(false);
  const [activeView, setActiveView] = useState('qr'); // 'qr' | 'code'

  if (!isOpen || !peer) return null;

  const serverAddress = (window.location && window.location.hostname && window.location.hostname !== 'localhost')
    ? window.location.hostname
    : (serverConfig.server_ip ? serverConfig.server_ip.split('/')[0] : '10.99.0.1');
  const serverPort = serverConfig.listen_port || 51820;
  const allowedIp = peer.allowed_ips ? peer.allowed_ips[0] : '10.99.0.2/32';

  const configContent = `[Interface]
PrivateKey = ${privateKey || '<CLIENT_PRIVATE_KEY>'}
Address = ${allowedIp}
${serverConfig.dns ? `DNS = ${serverConfig.dns}\n` : ''}${serverConfig.mtu ? `MTU = ${serverConfig.mtu}\n` : ''}
[Peer]
PublicKey = ${serverConfig.public_key || '<SERVER_PUBLIC_KEY>'}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = ${serverAddress}:${serverPort}
PersistentKeepalive = ${peer.persistent_keepalive || 25}
`;

  const handleCopy = async () => {
    await navigator.clipboard.writeText(configContent).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };

  const handleDownload = () => {
    const filename = `${(peer.name || 'wg-client').toLowerCase().replace(/\s+/g, '_')}_wg0.conf`;
    const blob = new Blob([configContent], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="vpn-modal-overlay" onClick={onClose}>
      <div
        className="vpn-modal vpn-config-modal"
        onClick={(e) => e.stopPropagation()}
        style={{ maxWidth: 520, borderRadius: 16 }}
        dir="rtl"
      >
        {/* Header */}
        <div className="vpn-modal-header">
          <div className="vpn-modal-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
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
              <Smartphone size={18} />
            </div>
            <div>
              <div style={{ fontWeight: 800, fontSize: '0.98rem', color: 'var(--text-primary)' }}>
                تكوين عميل WireGuard (QR & Config)
              </div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
                العميل: <strong>{peer.name || 'عميل WireGuard'}</strong> · <code dir="ltr">{allowedIp}</code>
              </div>
            </div>
          </div>
          <button className="vpn-modal-close" onClick={onClose}>
            <X size={16} />
          </button>
        </div>

        {/* View Switcher Tabs */}
        <div style={{ display: 'flex', gap: 8, padding: '12px 20px 0', borderBottom: '1px solid rgba(255, 255, 255, 0.06)' }}>
          <button
            type="button"
            onClick={() => setActiveView('qr')}
            style={{
              padding: '6px 14px',
              borderRadius: '8px 8px 0 0',
              border: 'none',
              cursor: 'pointer',
              fontSize: '0.78rem',
              fontWeight: 800,
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              background: activeView === 'qr' ? 'rgba(0, 200, 255, 0.15)' : 'transparent',
              color: activeView === 'qr' ? '#00c8ff' : 'var(--text-secondary)',
              borderBottom: activeView === 'qr' ? '2px solid #00c8ff' : '2px solid transparent',
            }}
          >
            <QrCode size={14} /> رمز الاستجابة السريعة (QR Code)
          </button>

          <button
            type="button"
            onClick={() => setActiveView('code')}
            style={{
              padding: '6px 14px',
              borderRadius: '8px 8px 0 0',
              border: 'none',
              cursor: 'pointer',
              fontSize: '0.78rem',
              fontWeight: 800,
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              background: activeView === 'code' ? 'rgba(0, 200, 255, 0.15)' : 'transparent',
              color: activeView === 'code' ? '#00c8ff' : 'var(--text-secondary)',
              borderBottom: activeView === 'code' ? '2px solid #00c8ff' : '2px solid transparent',
            }}
          >
            <Terminal size={14} /> نص التكوين (.conf)
          </button>
        </div>

        <div className="vpn-modal-body" style={{ padding: '20px' }}>
          {!privateKey && (
            <div className="vpn-config-warn" style={{ marginBottom: 16 }}>
              <ShieldAlert size={14} style={{ color: '#ffab40', flexShrink: 0 }} />
              <span style={{ fontSize: '0.74rem' }}>
                ملاحظة: هذا الرمز يحتوي على المفتاح العام. إذا كنت تريد تشغيل النفق فورياً على هاتفك، تأكد من توفر المفتاح الخاص.
              </span>
            </div>
          )}

          {/* QR View */}
          {activeView === 'qr' ? (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center', gap: 14 }}>
              <div
                style={{
                  background: '#ffffff',
                  padding: '16px',
                  borderRadius: '12px',
                  boxShadow: '0 8px 32px rgba(0, 200, 255, 0.25)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <QRCodeSVG
                  value={configContent}
                  size={200}
                  level="M"
                  includeMargin={false}
                />
              </div>

              <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', maxWidth: 360, lineHeight: 1.5 }}>
                امسح الرمز مباشرة باستخدام تطبيق <strong>WireGuard</strong> على الهاتف (iOS / Android) لإضافة النفق فورياً بنقرة واحدة.
              </div>
            </div>
          ) : (
            /* Code View */
            <div className="vpn-code-block-wrap">
              <pre className="vpn-code-block" dir="ltr" style={{ fontSize: '0.78rem', maxHeight: 220, overflowY: 'auto' }}>
                {configContent}
              </pre>
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div className="vpn-modal-footer" style={{ justifyContent: 'space-between', padding: '14px 20px' }}>
          <button type="button" className="vpn-btn vpn-btn--ghost" onClick={handleCopy}>
            {copied ? <Check size={14} style={{ color: '#00e676' }} /> : <Copy size={14} />}
            {copied ? 'تم النسخ' : 'نسخ التكوين'}
          </button>
          <div style={{ display: 'flex', gap: 8 }}>
            <button type="button" className="vpn-btn vpn-btn--ghost" onClick={onClose}>
              إغلاق
            </button>
            <button type="button" className="vpn-btn vpn-btn--primary" onClick={handleDownload}>
              <Download size={14} />
              تحميل ملف (.conf)
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default ClientConfigModal;
