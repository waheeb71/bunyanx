import React, { useState, useEffect, useMemo } from 'react';
import {
  Shield, Play, Square, Settings, Users, Plus, Server, Hash, RefreshCw, AlertCircle,
  Lock, Globe, Activity, ChevronDown, MonitorSmartphone, Search, Download, FileText,
  QrCode, ArrowDownRight, ArrowUpRight, Wifi, Zap, Cpu, Layers
} from 'lucide-react';
import { useVPN } from './hooks/useVPN';
import VpnStatChip from './components/VpnStatChip';
import ConfigField from './components/ConfigField';
import SessionRow from './components/SessionRow';
import PeerRow from './components/PeerRow';
import AddPeerModal from './components/AddPeerModal';
import ConfirmModal from './components/ConfirmModal';
import ClientConfigModal from './components/ClientConfigModal';
import ToastBanner from './components/ToastBanner';
import './VPN.css';

export default function VPN() {
  const {
    status,
    interfaceName,
    isActive,
    config: initialConfig,
    peers,
    peersLoading,
    sessions,
    sessionSummary,
    vpnLogs,
    vpnAlerts,
    diagnostics,
    isLoading,
    toggleMutation,
    saveConfig,
    addPeer,
    removePeer,
    terminateSession,
    generateKeys,
    refetch,
  } = useVPN();

  const [config, setConfig] = useState(initialConfig);
  const [showAddPeer, setShowAddPeer] = useState(false);
  const [activeTab, setActiveTab] = useState('peers');

  // Search states
  const [peerSearch, setPeerSearch] = useState('');
  const [sessionSearch, setSessionSearch] = useState('');

  // Toast notification state
  const [toast, setToast] = useState(null);

  // Modal dialog states
  const [confirmState, setConfirmState] = useState({
    isOpen: false,
    title: '',
    message: '',
    confirmText: 'تأكيد',
    variant: 'danger',
    onConfirm: null,
  });

  const [clientConfigState, setClientConfigState] = useState({
    isOpen: false,
    peer: null,
    privateKey: '',
  });

  useEffect(() => {
    setConfig(initialConfig);
  }, [initialConfig]);

  const showToast = (message, type = 'info') => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 4000);
  };

  const handleToggle = () => {
    const actionText = isActive ? 'إيقاف' : 'تشغيل';
    setConfirmState({
      isOpen: true,
      title: `${actionText} خادم WireGuard`,
      message: isActive
        ? 'هل أنت متأكد من رغبتك في إيقاف خادم الـ VPN؟ سيتم قطع الاتصال بكافة الأنفاق والجلسات النشطة.'
        : 'هل تريد تشغيل خادم الـ VPN وتفعيل الاتصالات المشفرة؟',
      confirmText: actionText,
      variant: isActive ? 'danger' : 'primary',
      onConfirm: () => {
        setConfirmState((prev) => ({ ...prev, isOpen: false }));
        toggleMutation.mutate(undefined, {
          onSuccess: () => showToast(`تم ${actionText} خادم WireGuard بنجاح!`, 'success'),
          onError: (err) => showToast(err.response?.data?.detail || err.message, 'error'),
        });
      },
    });
  };

  const handleSaveConfig = (e) => {
    e.preventDefault();
    saveConfig.mutate(config, {
      onSuccess: () => showToast('تم حفظ وتطبيق إعدادات خادم VPN بنجاح!', 'success'),
      onError: (err) => showToast(err.response?.data?.detail || err.message, 'error'),
    });
  };

  const handleAddPeer = (peerData, genPrivKey = '') => {
    addPeer.mutate(peerData, {
      onSuccess: () => {
        setShowAddPeer(false);
        showToast(`تمت إضافة العميل "${peerData.name}" بنجاح!`, 'success');
        if (genPrivKey) {
          setClientConfigState({
            isOpen: true,
            peer: peerData,
            privateKey: genPrivKey,
          });
        }
      },
      onError: (err) => showToast(err.response?.data?.detail || err.message, 'error'),
    });
  };

  const handleGenerateKeys = async () => {
    try {
      const res = await generateKeys.mutateAsync();
      showToast('تم توليد زوج مفاتيح WireGuard جديد بنجاح!', 'success');
      return res;
    } catch {
      showToast('فشل توليد المفاتيح', 'error');
      return null;
    }
  };

  const handleRequestRemovePeer = (peer) => {
    setConfirmState({
      isOpen: true,
      title: 'إزالة عميل VPN',
      message: `هل أنت متأكد من رغبتك في حذف العميل "${peer.name}"؟ سيتم إلغاء صلاحية المفتاح قطعياً.`,
      confirmText: 'حذف العميل',
      variant: 'danger',
      onConfirm: () => {
        setConfirmState((prev) => ({ ...prev, isOpen: false }));
        removePeer.mutate(peer.public_key, {
          onSuccess: () => showToast(`تمت إزالة العميل "${peer.name}" بنجاح`, 'success'),
          onError: (err) => showToast(err.response?.data?.detail || err.message, 'error'),
        });
      },
    });
  };

  const handleRequestTerminateSession = (session) => {
    setConfirmState({
      isOpen: true,
      title: 'إنهاء جلسة VPN حية',
      message: `هل أنت متأكد من إنهاء جلسة المستخدم "${session.username}" فوراً؟`,
      confirmText: 'إنهاء الجلسة',
      variant: 'danger',
      onConfirm: () => {
        setConfirmState((prev) => ({ ...prev, isOpen: false }));
        terminateSession.mutate(session.session_id, {
          onSuccess: () => showToast(`تم إنهاء جلسة "${session.username}" بنجاح`, 'success'),
          onError: (err) => showToast(err.response?.data?.detail || err.message, 'error'),
        });
      },
    });
  };

  // Filtered lists
  const filteredPeers = useMemo(() => {
    if (!peerSearch.trim()) return peers;
    const q = peerSearch.toLowerCase();
    return peers.filter(
      (p) =>
        (p.name && p.name.toLowerCase().includes(q)) ||
        (p.public_key && p.public_key.toLowerCase().includes(q)) ||
        (p.allowed_ips && p.allowed_ips.some((ip) => ip.includes(q)))
    );
  }, [peers, peerSearch]);

  const filteredSessions = useMemo(() => {
    if (!sessionSearch.trim()) return sessions;
    const q = sessionSearch.toLowerCase();
    return sessions.filter(
      (s) =>
        (s.username && s.username.toLowerCase().includes(q)) ||
        (s.peer_public_key && s.peer_public_key.toLowerCase().includes(q)) ||
        (s.allowed_ips && s.allowed_ips.some((ip) => ip.includes(q)))
    );
  }, [sessions, sessionSearch]);

  // Aggregate Tx/Rx Data
  const totalRx = useMemo(() => {
    return sessions.reduce((acc, s) => acc + (s.bytes_rx || 0), 0);
  }, [sessions]);

  const totalTx = useMemo(() => {
    return sessions.reduce((acc, s) => acc + (s.bytes_tx || 0), 0);
  }, [sessions]);

  const formatBytes = (b) => {
    if (!b) return '0.0 MB';
    if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
    if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB';
    return (b / 1073741824).toFixed(2) + ' GB';
  };

  // CSV Export helpers
  const exportPeersCSV = () => {
    if (peers.length === 0) return;
    const headers = ['Name', 'Public Key', 'Allowed IPs', 'Endpoint', 'Keepalive'];
    const rows = peers.map((p) => [
      `"${p.name || ''}"`,
      `"${p.public_key || ''}"`,
      `"${(p.allowed_ips || []).join('; ')}"`,
      `"${p.endpoint || ''}"`,
      p.persistent_keepalive || 25,
    ]);
    const csvContent = '\uFEFF' + [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `wireguard_peers_${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const actionLoading =
    toggleMutation.isPending ||
    saveConfig.isPending ||
    addPeer.isPending ||
    removePeer.isPending ||
    terminateSession.isPending;

  if (isLoading) {
    return (
      <div className="vpn-loading" dir="rtl">
        <RefreshCw size={22} className="vpn-spin" />
        <span>جاري تحميل بيانات WireGuard...</span>
      </div>
    );
  }

  return (
    <div className="vpn-root" dir="rtl">
      <ToastBanner toast={toast} onClose={() => setToast(null)} />

      {/* ── Confirm Modal ── */}
      <ConfirmModal
        isOpen={confirmState.isOpen}
        title={confirmState.title}
        message={confirmState.message}
        confirmText={confirmState.confirmText}
        variant={confirmState.variant}
        onConfirm={confirmState.onConfirm}
        onCancel={() => setConfirmState((prev) => ({ ...prev, isOpen: false }))}
      />

      {/* ── Add Peer Modal ── */}
      <AddPeerModal
        isOpen={showAddPeer}
        onClose={() => setShowAddPeer(false)}
        onSubmit={handleAddPeer}
        onGenerateKeys={handleGenerateKeys}
        loading={addPeer.isPending}
      />

      {/* ── Client Config & QR Modal ── */}
      <ClientConfigModal
        isOpen={clientConfigState.isOpen}
        peer={clientConfigState.peer}
        serverConfig={config}
        privateKey={clientConfigState.privateKey}
        onClose={() => setClientConfigState({ isOpen: false, peer: null, privateKey: '' })}
      />

      {/* ── 1. Hero Header ── */}
      <div className="vpn-hero">
        <div className="vpn-hero-glow" />
        <div className="vpn-hero-content">
          <div className="vpn-hero-left">
            <div className="vpn-hero-icon">
              <Lock size={26} style={{ color: '#00c8ff' }} />
            </div>
            <div>
              <h1 className="vpn-hero-title">بوابة الشبكة الافتراضية الآمنة (WireGuard VPN Gateway)</h1>
              <p className="vpn-hero-sub">
                واجهة: <span dir="ltr">{interfaceName}</span> · {config.server_ip} · منفذ: {config.listen_port}
              </p>
            </div>
          </div>

          {/* Quick Metrics Bar */}
          <div className="vpn-hero-stats">
            <VpnStatChip label="حالة الخادم" value={isActive ? 'نشط 🟢' : 'متوقف 🔴'} color={isActive ? '#00e676' : '#ff4d6a'} />
            <VpnStatChip label="العملاء المسجلين" value={peers.length} color="#00c8ff" />
            <VpnStatChip label="الجلسات الحية" value={sessionSummary.active_sessions ?? 0} color="#00e676" />
            <VpnStatChip label="تشفير النفق" value="ChaCha20" color="#ffab40" />
          </div>
        </div>
      </div>

      {/* ── 2. Server Status & Traffic Summary Strip ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 14 }}>
        {/* Status Card */}
        <div className="vpn-status-card" style={{ margin: 0 }}>
          <div className="vpn-status-left">
            <div className={`vpn-status-orb ${isActive ? 'vpn-status-orb--on' : 'vpn-status-orb--off'}`}>
              <Shield size={22} />
            </div>
            <div>
              <div className="vpn-status-title" style={{ fontSize: '0.92rem' }}>
                خادم WireGuard — {interfaceName}
              </div>
              <div className="vpn-status-desc" style={{ fontSize: '0.72rem' }}>
                {isActive ? 'النفق الآمن يوجه الحزم المشفرة' : 'محرك الخادم متوقف حالياً'}
              </div>
            </div>
          </div>

          <div className="vpn-status-actions">
            <button
              className={`vpn-btn ${isActive ? 'vpn-btn--stop' : 'vpn-btn--start'}`}
              onClick={handleToggle}
              disabled={actionLoading}
              style={{ padding: '6px 14px', fontSize: '0.78rem' }}
            >
              {toggleMutation.isPending ? (
                <><RefreshCw size={13} className="vpn-spin" /> يُعالج…</>
              ) : isActive ? (
                <><Square size={13} fill="currentColor" /> إيقاف</>
              ) : (
                <><Play size={13} fill="currentColor" /> تشغيل</>
              )}
            </button>
          </div>
        </div>

        {/* Rx / Tx Metric Card */}
        <div
          className="card"
          style={{
            background: 'rgba(10, 14, 26, 0.75)',
            border: '1px solid rgba(0, 200, 255, 0.15)',
            borderRadius: '12px',
            padding: '14px 18px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{ width: 36, height: 36, borderRadius: 10, background: 'rgba(0, 230, 118, 0.12)', color: '#00e676', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <ArrowDownRight size={18} />
            </div>
            <div>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-secondary)' }}>بيانات مستلمة (Download Rx)</div>
              <div style={{ fontSize: '1.15rem', fontWeight: 800, fontFamily: 'JetBrains Mono, monospace', color: '#00e676' }}>
                {formatBytes(totalRx)}
              </div>
            </div>
          </div>

          <div style={{ width: 1, height: 30, background: 'rgba(255, 255, 255, 0.08)' }} />

          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{ width: 36, height: 36, borderRadius: 10, background: 'rgba(0, 200, 255, 0.12)', color: '#00c8ff', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <ArrowUpRight size={18} />
            </div>
            <div>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-secondary)' }}>بيانات مرسلة (Upload Tx)</div>
              <div style={{ fontSize: '1.15rem', fontWeight: 800, fontFamily: 'JetBrains Mono, monospace', color: '#00c8ff' }}>
                {formatBytes(totalTx)}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ── 3. Tabs Navigation ── */}
      <div className="vpn-tabs">
        <button
          className={`vpn-tab-btn ${activeTab === 'peers' ? 'active' : ''}`}
          onClick={() => setActiveTab('peers')}
        >
          <Users size={14} /> إدارة النظراء ورمز الاستجابة السريعة (Peers & QR)
        </button>
        <button
          className={`vpn-tab-btn ${activeTab === 'sessions' ? 'active' : ''}`}
          onClick={() => setActiveTab('sessions')}
        >
          <Activity size={14} /> الجلسات النشطة ومعدلات التدفق ({sessionSummary.active_sessions ?? 0})
        </button>
        <button
          className={`vpn-tab-btn ${activeTab === 'config' ? 'active' : ''}`}
          onClick={() => setActiveTab('config')}
        >
          <Settings size={14} /> إعدادات البوابة والشبكة
        </button>
        <button
          className={`vpn-tab-btn ${activeTab === 'logs' ? 'active' : ''}`}
          onClick={() => setActiveTab('logs')}
        >
          <Layers size={14} /> سجلات العمليات والتنبيهات
        </button>
      </div>

      {/* ══ TAB 1: Peers & QR ══ */}
      {activeTab === 'peers' && (
        <div className="vpn-peers-card">
          <div className="vpn-card-header">
            <div className="vpn-card-title">
              <Users size={16} style={{ color: '#00c8ff' }} />
              العملاء المسجلون (WireGuard Peers)
              <span className="vpn-count-pill">{peers.length}</span>
            </div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <button className="vpn-btn vpn-btn--ghost vpn-btn--sm" onClick={exportPeersCSV} title="تصدير جدول العملاء CSV">
                <Download size={13} /> تصدير CSV
              </button>
              <button className="vpn-btn vpn-btn--primary vpn-btn--sm" onClick={() => setShowAddPeer(true)}>
                <Plus size={13} /> إضافة عميل جديد
              </button>
            </div>
          </div>

          {/* Search Bar */}
          <div className="vpn-table-toolbar">
            <div className="vpn-search-wrap">
              <Search size={14} className="vpn-search-icon" />
              <input
                type="text"
                className="vpn-search-input"
                placeholder="البحث باسم العميل، المفتاح العام، أو العنوان..."
                value={peerSearch}
                onChange={(e) => setPeerSearch(e.target.value)}
              />
            </div>
          </div>

          {peersLoading ? (
            <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-secondary)' }}>
              <RefreshCw size={16} className="vpn-spin" /> جاري التحميل...
            </div>
          ) : filteredPeers.length === 0 ? (
            <div className="vpn-empty">
              <Users size={32} style={{ opacity: 0.1, margin: '0 auto 8px', display: 'block' }} />
              <span>{peerSearch ? 'لا توجد نتائج مطابقة للبحث.' : 'لا يوجد عملاء مضافون بعد.'}</span>
              {!peerSearch && (
                <button className="vpn-btn vpn-btn--primary" onClick={() => setShowAddPeer(true)} style={{ marginTop: 8 }}>
                  <Plus size={14} /> إضافة أول عميل
                </button>
              )}
            </div>
          ) : (
            <div className="vpn-table-wrap">
              <table className="vpn-table">
                <thead>
                  <tr>
                    <th>اسم العميل / الحالة</th>
                    <th>المفتاح العام (Public Key)</th>
                    <th>العناوين المسموحة (Allowed IPs)</th>
                    <th>نقطة النهاية (Endpoint)</th>
                    <th style={{ width: 90, textAlign: 'center' }}>QR / إجراءات</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredPeers.map((peer) => {
                    const isConnected = sessions.some((s) => s.peer_public_key === peer.public_key);
                    return (
                      <PeerRow
                        key={peer.public_key}
                        peer={peer}
                        isConnected={isConnected}
                        onRequestRemove={handleRequestRemovePeer}
                        onExportConfig={(p) => setClientConfigState({ isOpen: true, peer: p, privateKey: '' })}
                      />
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* ══ TAB 2: Live Sessions ══ */}
      {activeTab === 'sessions' && (
        <div className="vpn-peers-card">
          <div className="vpn-card-header">
            <div className="vpn-card-title">
              <Activity size={16} style={{ color: '#00e676' }} />
              الجلسات الحية النشطة
              <span className="vpn-count-pill" style={{ background: 'rgba(0, 230, 118, 0.15)', color: '#00e676', borderColor: 'rgba(0, 230, 118, 0.3)' }}>
                {sessions.length}
              </span>
            </div>
          </div>

          {sessions.length === 0 ? (
            <div className="vpn-empty">
              <Wifi size={32} style={{ opacity: 0.1, margin: '0 auto 8px', display: 'block' }} />
              <span>لا توجد جلسات VPN نشطة متصلة بالخادم حالياً.</span>
            </div>
          ) : (
            <div className="vpn-table-wrap">
              <table className="vpn-table">
                <thead>
                  <tr>
                    <th>المستخدم</th>
                    <th>العناوين المخصصة</th>
                    <th>مدة الاتصال</th>
                    <th>معدل نقل البيانات (Rx / Tx)</th>
                    <th style={{ width: 60, textAlign: 'center' }}>إنهاء</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredSessions.map((session) => (
                    <SessionRow
                      key={session.session_id || session.peer_public_key}
                      session={session}
                      onRequestTerminate={handleRequestTerminateSession}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* ══ TAB 3: Gateway Configuration ══ */}
      {activeTab === 'config' && (
        <div className="vpn-config-card" style={{ maxWidth: 700 }}>
          <div className="vpn-card-header">
            <div className="vpn-card-title">
              <Settings size={16} style={{ color: '#00c8ff' }} />
              إعدادات خادم WireGuard والشبكة
            </div>
          </div>

          <form className="vpn-config-form" onSubmit={handleSaveConfig} style={{ padding: 20 }}>
            <ConfigField label="الشبكة الفرعية للخادم (CIDR)" icon={Server}>
              <input
                className="vpn-input"
                type="text"
                dir="ltr"
                placeholder="10.99.0.1/24"
                value={config.server_ip}
                onChange={(e) => setConfig({ ...config, server_ip: e.target.value })}
                required
              />
            </ConfigField>

            <ConfigField label="منفذ الاستماع (Listen Port)" icon={Hash}>
              <input
                className="vpn-input"
                type="number"
                dir="ltr"
                value={config.listen_port}
                onChange={(e) => setConfig({ ...config, listen_port: parseInt(e.target.value) || 51820 })}
                required
              />
            </ConfigField>

            <ConfigField label="خادم DNS للعملاء" icon={Globe}>
              <input
                className="vpn-input"
                type="text"
                dir="ltr"
                placeholder="1.1.1.1, 8.8.8.8"
                value={config.dns || ''}
                onChange={(e) => setConfig({ ...config, dns: e.target.value })}
              />
            </ConfigField>

            <ConfigField label="وحدة الإرسال الكبرى (MTU)" icon={Activity}>
              <input
                className="vpn-input"
                type="number"
                dir="ltr"
                value={config.mtu || 1420}
                onChange={(e) => setConfig({ ...config, mtu: parseInt(e.target.value) || 1420 })}
              />
            </ConfigField>

            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 14 }}>
              <button type="submit" className="vpn-btn vpn-btn--primary" disabled={saveConfig.isPending}>
                <Settings size={14} /> {saveConfig.isPending ? 'جاري الحفظ...' : 'حفظ وتطبيق الإعدادات'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* ══ TAB 4: Logs & Diagnostics ══ */}
      {activeTab === 'logs' && (
        <div className="vpn-peers-card">
          <div className="vpn-card-header">
            <div className="vpn-card-title">
              <Layers size={16} style={{ color: '#00c8ff' }} />
              سجل العمليات وأحداث الـ VPN
            </div>
          </div>
          <div style={{ padding: 20 }}>
            {vpnLogs?.length === 0 ? (
              <div className="vpn-empty">لا توجد سجلات أحداث مسجلة بعد.</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {(vpnLogs || []).map((l, i) => (
                  <div
                    key={i}
                    style={{
                      padding: '8px 12px',
                      background: 'rgba(255, 255, 255, 0.02)',
                      borderRadius: 6,
                      border: '1px solid rgba(255, 255, 255, 0.04)',
                      fontFamily: 'JetBrains Mono, monospace',
                      fontSize: '0.76rem',
                      color: 'var(--text-secondary)',
                    }}
                  >
                    {l.message || JSON.stringify(l)}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
