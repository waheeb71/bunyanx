import React, { useState } from 'react';
import { Copy, CheckCircle2, Trash2, FileText, QrCode, Smartphone } from 'lucide-react';

export function PeerRow({ peer, isConnected = false, rxBytes = 0, txBytes = 0, onRequestRemove, onExportConfig }) {
  const [copied, setCopied] = useState(false);

  const copyKey = async () => {
    await navigator.clipboard.writeText(peer.public_key).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const initials = (peer.name || 'P').slice(0, 2).toUpperCase();

  const formatBytes = (b) => {
    if (!b) return '0 KB';
    if (b < 1024) return b + ' B';
    if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
    return (b / 1048576).toFixed(1) + ' MB';
  };

  return (
    <tr className="vpn-peer-row">
      <td>
        <div className="vpn-peer-name-cell">
          <div
            className="vpn-peer-avatar"
            style={{
              background: isConnected ? 'rgba(0, 230, 118, 0.15)' : 'rgba(0, 200, 255, 0.1)',
              border: `1px solid ${isConnected ? 'rgba(0, 230, 118, 0.35)' : 'rgba(0, 200, 255, 0.25)'}`,
              color: isConnected ? '#00e676' : '#00c8ff',
            }}
          >
            {initials}
          </div>
          <div>
            <div className="vpn-peer-name" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              {peer.name || 'عميل غير مُسمى'}
              {isConnected ? (
                <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#00e676', boxShadow: '0 0 6px #00e676' }} title="متصل حالياً" />
              ) : (
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'rgba(255,255,255,0.2)' }} title="غير متصل" />
              )}
            </div>
            <div className="vpn-peer-keepalive" style={{ fontSize: '0.7rem' }}>
              Keepalive: {peer.persistent_keepalive || 25}s
            </div>
          </div>
        </div>
      </td>
      <td>
        <div className="vpn-pubkey-cell" dir="ltr">
          <span className="vpn-pubkey">{peer.public_key.substring(0, 18)}…</span>
          <button className="vpn-copy-btn" onClick={copyKey} title="نسخ المفتاح العام">
            {copied ? <CheckCircle2 size={12} style={{ color: '#00e676' }} /> : <Copy size={12} />}
          </button>
        </div>
      </td>
      <td>
        <div className="vpn-ips-wrap">
          {(peer.allowed_ips || []).map((ip) => (
            <span key={ip} className="vpn-ip-tag" dir="ltr">
              {ip}
            </span>
          ))}
        </div>
      </td>
      <td>
        <span className="vpn-endpoint" dir="ltr" style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.74rem' }}>
          {peer.endpoint || <span style={{ opacity: 0.3 }}>تلقائي (Dynamic)</span>}
        </span>
      </td>
      <td>
        <div style={{ display: 'flex', gap: 6, justifyContent: 'center', alignItems: 'center' }}>
          {onExportConfig && (
            <button
              className="vpn-icon-action-btn"
              onClick={() => onExportConfig(peer)}
              title="عرض رمز الاستجابة السريعة (QR Code) وملف التكوين"
              style={{ color: '#00c8ff', borderColor: 'rgba(0, 200, 255, 0.25)', background: 'rgba(0, 200, 255, 0.08)' }}
            >
              <QrCode size={14} />
            </button>
          )}
          <button
            className="vpn-remove-btn"
            onClick={() => onRequestRemove(peer)}
            title="إزالة العميل"
          >
            <Trash2 size={13} />
          </button>
        </div>
      </td>
    </tr>
  );
}

export default PeerRow;
