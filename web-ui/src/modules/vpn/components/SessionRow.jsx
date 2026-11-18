import React from 'react';
import { Activity, Clock, XCircle } from 'lucide-react';

export function SessionRow({ session, onRequestTerminate }) {
  const durationMin = Math.floor((session.duration_seconds || 0) / 60);
  const hrs = Math.floor(durationMin / 60);
  const mins = durationMin % 60;
  const durText = hrs > 0 ? `${hrs}س ${mins}د` : `${mins} دقيقة`;

  const rxBytes = session.bytes_rx || 0;
  const txBytes = session.bytes_tx || 0;
  const totalBytes = rxBytes + txBytes || 1; // avoid / 0

  // Minimum 2% width so the bar is always slightly visible if there is ANY traffic
  const rxPct = rxBytes > 0 ? Math.max(2, (rxBytes / totalBytes) * 100) : 0;
  const txPct = txBytes > 0 ? Math.max(2, (txBytes / totalBytes) * 100) : 0;

  const formatBytes = (b) => {
    if (b < 1024) return b + ' B';
    if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
    return (b / 1048576).toFixed(1) + ' MB';
  };

  return (
    <tr className="vpn-peer-row">
      <td>
        <div className="vpn-peer-name-cell">
          <div className="vpn-peer-avatar" style={{ background: 'linear-gradient(135deg,#1f2937,#111827)', border: '1px solid rgba(40,199,111,0.3)', color: '#28c76f' }}>
            <Activity size={16} />
          </div>
          <div>
            <div className="vpn-peer-name">
              <span className="vpn-pulse-dot" />
              {session.username}
            </div>
            <div className="vpn-peer-keepalive" dir="ltr">{session.peer_public_key?.substring(0, 16)}…</div>
          </div>
        </div>
      </td>
      <td>
        <div className="vpn-ips-wrap">
          {(session.allowed_ips || []).map(ip => (
            <span key={ip} className="vpn-ip-tag" dir="ltr">{ip}</span>
          ))}
        </div>
      </td>
      <td>
        <span className="vpn-endpoint" dir="ltr" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <Clock size={12} style={{ opacity: 0.5 }} />
          {durText}
        </span>
      </td>
      <td>
        <div className="vpn-data-bars">
          <div className="vpn-data-bar-row">
            <span style={{ width: 14, color: '#28c76f' }}>↓</span>
            <div className="vpn-data-bar-track">
              <div className="vpn-data-bar-fill rx" style={{ width: `${rxPct}%` }} />
            </div>
            <span style={{ width: 45, textAlign: 'left' }}>{formatBytes(rxBytes)}</span>
          </div>
          <div className="vpn-data-bar-row">
            <span style={{ width: 14, color: '#00d4ff' }}>↑</span>
            <div className="vpn-data-bar-track">
              <div className="vpn-data-bar-fill tx" style={{ width: `${txPct}%` }} />
            </div>
            <span style={{ width: 45, textAlign: 'left' }}>{formatBytes(txBytes)}</span>
          </div>
        </div>
      </td>
      <td>
        <button
          className="vpn-remove-btn"
          onClick={() => onRequestTerminate(session)}
          title="إنهاء الجلسة"
        >
          <XCircle size={13} />
        </button>
      </td>
    </tr>
  );
}

export default SessionRow;
