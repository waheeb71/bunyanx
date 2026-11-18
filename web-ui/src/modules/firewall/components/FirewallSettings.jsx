import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Settings, Globe, ShieldAlert, RefreshCw, Trash2, Network,
  Edit2, Check, X, Shield, Plus, Lock, Cpu, Server, Activity,
  Sliders, AlertTriangle, CheckCircle2, Zap, Radio, Terminal,
  Layers, HardDrive, ShieldCheck, Tag, Flag
} from 'lucide-react';
import { firewallApi } from '../api/firewallApi';
import useFirewallStore from '../../../stores/firewallStore';

/* ── Common GeoIP Presets ── */
const GEO_PRESETS = {
  high_risk: {
    label: 'حظر الدول عالية الخطورة والتهديدات',
    countries: ['RU', 'CN', 'KP', 'IR', 'BY'],
    type: 'block',
  },
  gcc: {
    label: 'استثناء دول الخليج العربي (GCC)',
    countries: ['SA', 'AE', 'KW', 'QA', 'BH', 'OM'],
    type: 'white',
  },
  global_trusted: {
    label: 'استثناء النطاقات السحابية العالمية الموثوقة',
    countries: ['US', 'GB', 'DE', 'FR', 'NL', 'JP'],
    type: 'white',
  },
};

export default function FirewallSettings() {
  const qc = useQueryClient();
  const { showToast } = useFirewallStore();

  const { data: config, isLoading } = useQuery({
    queryKey: ['firewall-config'],
    queryFn: () => firewallApi.getConfig().then((r) => r.data),
    retry: false,
  });

  const { data: stats } = useQuery({
    queryKey: ['firewall-stats'],
    queryFn: () => firewallApi.getStats().then((r) => r.data),
    refetchInterval: 5000,
  });

  const updateMut = useMutation({
    mutationFn: (newCfg) => firewallApi.updateConfig(newCfg),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['firewall-config'] });
      qc.invalidateQueries({ queryKey: ['firewall-stats'] });
      showToast('تم حفظ إعدادات الجدار الناري وإعادة تحميل المحرك بالذاكرة بنجاح.', 'success');
    },
    onError: (err) => {
      showToast('فشل الحفظ: ' + (err.response?.data?.detail || err.message), 'error');
    },
  });

  // Local Form States
  const [enabled, setEnabled] = useState(true);
  const [mode, setMode] = useState('enforce');
  const [defaultPolicy, setDefaultPolicy] = useState('DROP');
  const [stateTimeout, setStateTimeout] = useState(300);
  const [maxActiveConnections, setMaxActiveConnections] = useState(100000);

  // GeoIP
  const [dbPath, setDbPath] = useState('system/data/GeoIP2-City.mmdb');
  const [asnDbPath, setAsnDbPath] = useState('system/data/GeoLite2-ASN.mmdb');
  const [blockedCountries, setBlockedCountries] = useState([]);
  const [whitelistedCountries, setWhitelistedCountries] = useState([]);
  const [newBlockedCode, setNewBlockedCode] = useState('');
  const [newWhiteCode, setNewWhiteCode] = useState('');

  // Zones
  const [zones, setZones] = useState({ WAN: ['eth0'], LAN: ['eth1'], DMZ: [], MGMT: [] });
  const [newZoneName, setNewZoneName] = useState('DMZ');
  const [newZoneIface, setNewZoneIface] = useState('');

  // Management & Dev Ports
  const [managementPorts, setManagementPorts] = useState([22, 443, 8080, 8443]);
  const [newMgmtPort, setNewMgmtPort] = useState('');
  const [devPortsEnabled, setDevPortsEnabled] = useState(false);
  const [devPorts, setDevPorts] = useState([3000, 5173, 8000, 8088]);
  const [newDevPort, setNewDevPort] = useState('');

  // Custom Ports
  const [customPorts, setCustomPorts] = useState([]);
  const [newCpName, setNewCpName] = useState('');
  const [newCpPort, setNewCpPort] = useState('');
  const [newCpProto, setNewCpProto] = useState('tcp');
  const [newCpDir, setNewCpDir] = useState('input');
  const [editCpIndex, setEditCpIndex] = useState(null);

  // Sync state with fetched config
  useEffect(() => {
    if (config) {
      setEnabled(config.enabled !== false);
      setMode(config.mode || 'enforce');
      setDefaultPolicy(config.default_policy || 'DROP');
      setStateTimeout(config.state_timeout_seconds ?? 300);
      setMaxActiveConnections(config.max_active_connections ?? 100000);

      if (config.geoip) {
        setDbPath(config.geoip.db_path || 'system/data/GeoIP2-City.mmdb');
        setAsnDbPath(config.geoip.asn_db_path || 'system/data/GeoLite2-ASN.mmdb');
        setBlockedCountries(config.geoip.blocked_countries || []);
        setWhitelistedCountries(config.geoip.whitelisted_countries || []);
      }

      setZones(config.zones && Object.keys(config.zones).length > 0 ? config.zones : { WAN: ['eth0'], LAN: ['eth1'], DMZ: [] });
      setManagementPorts(config.management_ports || [22, 443, 8080, 8443]);
      setDevPortsEnabled(config.dev_ports_enabled === true);
      setDevPorts(config.dev_ports || [3000, 5173, 8000, 8088]);
      setCustomPorts(config.custom_ports || []);
    }
  }, [config]);

  const handleSave = (e) => {
    e.preventDefault();
    const payload = {
      enabled,
      mode,
      default_policy: defaultPolicy,
      state_timeout_seconds: parseInt(stateTimeout, 10),
      max_active_connections: parseInt(maxActiveConnections, 10),
      geoip: {
        db_path: dbPath,
        asn_db_path: asnDbPath,
        blocked_countries: blockedCountries,
        whitelisted_countries: whitelistedCountries,
      },
      zones,
      management_ports: managementPorts.map((p) => parseInt(p, 10)).filter((p) => !isNaN(p)),
      dev_ports_enabled: devPortsEnabled,
      dev_ports: devPorts.map((p) => parseInt(p, 10)).filter((p) => !isNaN(p)),
      custom_ports: customPorts.map((cp) => ({
        name: cp.name,
        port: parseInt(cp.port, 10),
        protocol: cp.protocol.toLowerCase(),
        direction: cp.direction.toLowerCase(),
        enabled: cp.enabled !== false,
      })),
    };
    updateMut.mutate(payload);
  };

  // GeoIP Handlers
  const addBlockedCountry = () => {
    const code = newBlockedCode.trim().toUpperCase();
    if (code && code.length === 2 && !blockedCountries.includes(code)) {
      setBlockedCountries([...blockedCountries, code]);
      setNewBlockedCode('');
    } else {
      showToast('أدخل رمز دولة ثنائي صحيح (مثال: RU أو CN).', 'error');
    }
  };

  const addWhitelistedCountry = () => {
    const code = newWhiteCode.trim().toUpperCase();
    if (code && code.length === 2 && !whitelistedCountries.includes(code)) {
      setWhitelistedCountries([...whitelistedCountries, code]);
      setNewWhiteCode('');
    } else {
      showToast('أدخل رمز دولة ثنائي صحيح (مثال: SA أو AE).', 'error');
    }
  };

  const applyGeoPreset = (key) => {
    const p = GEO_PRESETS[key];
    if (!p) return;
    if (p.type === 'block') {
      const merged = Array.from(new Set([...blockedCountries, ...p.countries]));
      setBlockedCountries(merged);
    } else {
      const merged = Array.from(new Set([...whitelistedCountries, ...p.countries]));
      setWhitelistedCountries(merged);
    }
    showToast(`تم تطبيق قالب "${p.label}" بنجاح`, 'success');
  };

  // Zone Handlers
  const addInterfaceToZone = () => {
    if (!newZoneIface.trim()) return;
    const iface = newZoneIface.trim();
    const zoneList = zones[newZoneName] || [];
    if (!zoneList.includes(iface)) {
      setZones({
        ...zones,
        [newZoneName]: [...zoneList, iface],
      });
      setNewZoneIface('');
    }
  };

  const removeInterfaceFromZone = (zName, iface) => {
    setZones({
      ...zones,
      [zName]: (zones[zName] || []).filter((i) => i !== iface),
    });
  };

  // Port Handlers
  const addMgmtPort = () => {
    const p = parseInt(newMgmtPort.trim(), 10);
    if (p && p >= 1 && p <= 65535 && !managementPorts.includes(p)) {
      setManagementPorts([...managementPorts, p]);
      setNewMgmtPort('');
    }
  };

  const addDevPort = () => {
    const p = parseInt(newDevPort.trim(), 10);
    if (p && p >= 1 && p <= 65535 && !devPorts.includes(p)) {
      setDevPorts([...devPorts, p]);
      setNewDevPort('');
    }
  };

  // Custom Port Handlers
  const saveCustomPort = () => {
    const p = parseInt(newCpPort, 10);
    if (!newCpName.trim() || isNaN(p) || p < 1 || p > 65535) {
      showToast('يرجى كتابة اسم ورقم منفذ صحيح (1-65535)', 'error');
      return;
    }
    const item = {
      name: newCpName.trim(),
      port: p,
      protocol: newCpProto,
      direction: newCpDir,
      enabled: true,
    };
    if (editCpIndex !== null) {
      const updated = [...customPorts];
      updated[editCpIndex] = item;
      setCustomPorts(updated);
      setEditCpIndex(null);
    } else {
      setCustomPorts([...customPorts, item]);
    }
    setNewCpName('');
    setNewCpPort('');
  };

  if (isLoading) {
    return (
      <div className="card" style={{ padding: 48, textAlign: 'center', color: 'var(--text-secondary)' }} dir="rtl">
        <RefreshCw size={24} className="spin" style={{ color: '#00c8ff', margin: '0 auto 8px', display: 'block' }} />
        جاري تحميل إعدادات وتكوين جدار الحماية...
      </div>
    );
  }

  return (
    <form onSubmit={handleSave} style={{ display: 'flex', flexDirection: 'column', gap: 20 }} dir="rtl">
      {/* ── Top Header & Live Telemetry Ribbon ── */}
      <div
        className="card"
        style={{
          background: 'rgba(10, 14, 26, 0.75)',
          backdropFilter: 'blur(16px)',
          border: '1px solid rgba(0, 200, 255, 0.2)',
          borderRadius: 'var(--radius-lg)',
          padding: '20px 24px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: 16,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div
            style={{
              width: 44,
              height: 44,
              borderRadius: 12,
              background: 'rgba(0, 200, 255, 0.12)',
              border: '1px solid rgba(0, 200, 255, 0.3)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#00c8ff',
            }}
          >
            <Settings size={22} />
          </div>
          <div>
            <h2 style={{ fontSize: '1.15rem', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
              إعدادات جدار الحماية والمناطق (Firewall Engine & Zones Config)
            </h2>
            <p style={{ margin: '2px 0 0', fontSize: '0.74rem', color: 'var(--text-secondary)', fontFamily: 'JetBrains Mono, monospace' }}>
              Stateful Inspection · Geo-Fencing · Zone-Based Firewall · Port Allowlists
            </p>
          </div>
        </div>

        {/* Live Status Indicators */}
        <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
          <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '6px 14px', borderRadius: 8, border: '1px solid rgba(255, 255, 255, 0.06)' }}>
            <div style={{ fontSize: '0.66rem', color: 'var(--text-secondary)' }}>الاتصالات النشطة (Active TCP Conns)</div>
            <div style={{ fontSize: '1.1rem', fontWeight: 800, fontFamily: 'JetBrains Mono, monospace', color: '#00c8ff' }}>
              {stats?.active_connections ?? 0}
            </div>
          </div>

          <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '6px 14px', borderRadius: 8, border: '1px solid rgba(255, 255, 255, 0.06)' }}>
            <div style={{ fontSize: '0.66rem', color: 'var(--text-secondary)' }}>قاطع الدائرة (Circuit Breaker)</div>
            <div style={{ fontSize: '0.85rem', fontWeight: 800, color: '#00e676' }}>
              {stats?.circuit_breaker || 'HEALTHY 🟢'}
            </div>
          </div>

          <button
            type="submit"
            className="btn btn-primary"
            disabled={updateMut.isPending}
            style={{ padding: '9px 22px', fontSize: '0.85rem', fontWeight: 800 }}
          >
            {updateMut.isPending ? <RefreshCw size={14} className="spin" /> : <Check size={14} />}
            {updateMut.isPending ? 'جاري الحفظ والتحميل...' : 'حفظ وتطبيق الإعدادات'}
          </button>
        </div>
      </div>

      {/* ── 1. Core Engine Operating Mode & State Parameters ── */}
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
          <Shield size={18} style={{ color: '#00c8ff' }} />
          <h3 style={{ margin: 0, fontSize: '0.98rem', fontWeight: 800, color: 'var(--text-primary)' }}>
            1. وضع التشغيل ومعايير التصفية الحركية (Stateful Engine Parameters)
          </h3>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 16 }}>
          {/* Master Enable */}
          <div style={{ padding: 14, background: 'rgba(255, 255, 255, 0.02)', borderRadius: 10, border: '1px solid rgba(255, 255, 255, 0.06)' }}>
            <div style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 6 }}>
              حالة محرك جدار الحماية (Master Firewall)
            </div>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: '0.82rem', color: enabled ? '#00e676' : '#ff4d6a', fontWeight: 800 }}>
              <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
              {enabled ? 'المحرك نشط ويقوم بفحص وتصفية الحزم' : 'المحرك معطل بالكامل (Bypass All)'}
            </label>
          </div>

          {/* Mode */}
          <div style={{ padding: 14, background: 'rgba(255, 255, 255, 0.02)', borderRadius: 10, border: '1px solid rgba(255, 255, 255, 0.06)' }}>
            <div style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 6 }}>
              وضع المعالجة (Operating Mode)
            </div>
            <select className="bl-input" value={mode} onChange={(e) => setMode(e.target.value)} style={{ fontSize: '0.82rem' }}>
              <option value="enforce">Enforce (فرض الحظر الفوري وسرعة العتاد)</option>
              <option value="monitor">Monitor (المراقبة والتسجيل فقط بدون إسقاط الحزم)</option>
              <option value="learning">Learning (وضع التعلم الذاتي وبناء السلوك)</option>
            </select>
          </div>

          {/* Default Policy */}
          <div style={{ padding: 14, background: 'rgba(255, 255, 255, 0.02)', borderRadius: 10, border: '1px solid rgba(255, 255, 255, 0.06)' }}>
            <div style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 6 }}>
              السياسة الافتراضية (Default Fallback Policy)
            </div>
            <select className="bl-input" value={defaultPolicy} onChange={(e) => setDefaultPolicy(e.target.value)} style={{ fontSize: '0.82rem' }}>
              <option value="DROP">DROP (إسقاط صامت - Zero Trust)</option>
              <option value="REJECT">REJECT (إرسال TCP Reset / ICMP Unreachable)</option>
              <option value="ACCEPT">ACCEPT (سماح افتراضي للحزم غير المطابقة)</option>
            </select>
          </div>

          {/* State Timeout */}
          <div style={{ padding: 14, background: 'rgba(255, 255, 255, 0.02)', borderRadius: 10, border: '1px solid rgba(255, 255, 255, 0.06)' }}>
            <div style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>
              مهلة انتهاء جدول الحالات (TCP State Timeout)
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <input
                className="bl-input"
                type="number"
                min="30"
                max="3600"
                value={stateTimeout}
                onChange={(e) => setStateTimeout(e.target.value)}
                style={{ fontSize: '0.85rem', width: 120 }}
              />
              <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>ثانية (الافتراضي: 300 ثانية)</span>
            </div>
          </div>
        </div>
      </div>

      {/* ── 2. GeoIP & Country-Based Filtering ── */}
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
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16, flexWrap: 'wrap', gap: 10 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Globe size={18} style={{ color: '#ffab40' }} />
            <div>
              <h3 style={{ margin: 0, fontSize: '0.98rem', fontWeight: 800, color: 'var(--text-primary)' }}>
                2. التصفية الجغرافية للدول (GeoIP & Country-Based Fencing)
              </h3>
              <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
                حظر أو استثناء حركة المرور حسب بلد المنشأ باستخدام قواعد بيانات MaxMind GeoIP2
              </span>
            </div>
          </div>

          {/* Quick Presets */}
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {Object.entries(GEO_PRESETS).map(([k, p]) => (
              <button
                key={k}
                type="button"
                className="btn btn-ghost"
                onClick={() => applyGeoPreset(k)}
                style={{ padding: '4px 10px', fontSize: '0.72rem', borderColor: 'rgba(255, 255, 255, 0.1)' }}
              >
                <Flag size={12} style={{ color: '#00c8ff' }} /> + {p.label}
              </button>
            ))}
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 16 }}>
          {/* Blocked Countries */}
          <div style={{ padding: 14, background: 'rgba(255, 77, 106, 0.04)', borderRadius: 10, border: '1px solid rgba(255, 77, 106, 0.2)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
              <span style={{ fontSize: '0.78rem', fontWeight: 800, color: '#ff4d6a' }}>
                الدول المحظورة جغرافياً ({blockedCountries.length})
              </span>
            </div>
            <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
              <input
                className="bl-input"
                placeholder="رمز الدولة (مثال: RU, CN)..."
                value={newBlockedCode}
                onChange={(e) => setNewBlockedCode(e.target.value)}
                maxLength={2}
                style={{ textTransform: 'uppercase', width: 140 }}
              />
              <button type="button" className="btn btn-danger" onClick={addBlockedCountry} style={{ padding: '4px 12px', fontSize: '0.75rem' }}>
                <Plus size={12} /> إضافة للحظر
              </button>
            </div>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', minHeight: 40 }}>
              {blockedCountries.length === 0 ? (
                <span style={{ fontSize: '0.74rem', color: 'var(--text-secondary)' }}>لا توجد دول محظورة حالياً.</span>
              ) : (
                blockedCountries.map((code) => (
                  <span
                    key={code}
                    style={{
                      fontFamily: 'JetBrains Mono, monospace',
                      fontSize: '0.75rem',
                      fontWeight: 800,
                      background: 'rgba(255, 77, 106, 0.15)',
                      color: '#ff4d6a',
                      border: '1px solid rgba(255, 77, 106, 0.3)',
                      padding: '2px 8px',
                      borderRadius: 6,
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 4,
                    }}
                  >
                    {code}
                    <button type="button" onClick={() => setBlockedCountries(blockedCountries.filter((c) => c !== code))} style={{ background: 'none', border: 'none', color: '#ff4d6a', cursor: 'pointer', padding: 0 }}>
                      <X size={12} />
                    </button>
                  </span>
                ))
              )}
            </div>
          </div>

          {/* Whitelisted Countries */}
          <div style={{ padding: 14, background: 'rgba(0, 230, 118, 0.04)', borderRadius: 10, border: '1px solid rgba(0, 230, 118, 0.2)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
              <span style={{ fontSize: '0.78rem', fontWeight: 800, color: '#00e676' }}>
                الدول المستثناة والموثوقة ({whitelistedCountries.length})
              </span>
            </div>
            <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
              <input
                className="bl-input"
                placeholder="رمز الدولة (مثال: SA, AE)..."
                value={newWhiteCode}
                onChange={(e) => setNewWhiteCode(e.target.value)}
                maxLength={2}
                style={{ textTransform: 'uppercase', width: 140 }}
              />
              <button type="button" className="btn btn-primary" onClick={addWhitelistedCountry} style={{ padding: '4px 12px', fontSize: '0.75rem', background: '#00e676', color: '#000' }}>
                <Plus size={12} /> إضافة للاستثناء
              </button>
            </div>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', minHeight: 40 }}>
              {whitelistedCountries.length === 0 ? (
                <span style={{ fontSize: '0.74rem', color: 'var(--text-secondary)' }}>لا توجد دول مضافة للاستثناء المسبق.</span>
              ) : (
                whitelistedCountries.map((code) => (
                  <span
                    key={code}
                    style={{
                      fontFamily: 'JetBrains Mono, monospace',
                      fontSize: '0.75rem',
                      fontWeight: 800,
                      background: 'rgba(0, 230, 118, 0.15)',
                      color: '#00e676',
                      border: '1px solid rgba(0, 230, 118, 0.3)',
                      padding: '2px 8px',
                      borderRadius: 6,
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 4,
                    }}
                  >
                    {code}
                    <button type="button" onClick={() => setWhitelistedCountries(whitelistedCountries.filter((c) => c !== code))} style={{ background: 'none', border: 'none', color: '#00e676', cursor: 'pointer', padding: 0 }}>
                      <X size={12} />
                    </button>
                  </span>
                ))
              )}
            </div>
          </div>
        </div>
      </div>

      {/* ── 3. Port Allowlists & Dev Bypass Settings ── */}
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
          <Zap size={18} style={{ color: '#00c8ff' }} />
          <div>
            <h3 style={{ margin: 0, fontSize: '0.98rem', fontWeight: 800, color: 'var(--text-primary)' }}>
              3. قوائم المنافذ الإدارية وتجاوز التطوير (Port Allowlists)
            </h3>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
              المنافذ المسموح بها دائماً لإدارة المنظومة ومنافذ الوكيل والتطوير
            </span>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 16 }}>
          {/* Management Ports */}
          <div style={{ padding: 14, background: 'rgba(255, 255, 255, 0.02)', borderRadius: 10, border: '1px solid rgba(255, 255, 255, 0.06)' }}>
            <div style={{ fontSize: '0.78rem', fontWeight: 800, color: 'var(--text-primary)', marginBottom: 8 }}>
              منافذ الإدارة الآمنة الدائمة (Management Ports)
            </div>
            <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
              <input
                className="bl-input"
                type="number"
                placeholder="رقم المنفذ (مثال: 8443)..."
                value={newMgmtPort}
                onChange={(e) => setNewMgmtPort(e.target.value)}
                style={{ width: 140 }}
              />
              <button type="button" className="btn btn-ghost" onClick={addMgmtPort} style={{ padding: '4px 12px', fontSize: '0.75rem' }}>
                <Plus size={12} /> إضافة منفذ
              </button>
            </div>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {managementPorts.map((port) => (
                <span
                  key={port}
                  style={{
                    fontFamily: 'JetBrains Mono, monospace',
                    fontSize: '0.78rem',
                    fontWeight: 800,
                    background: 'rgba(0, 200, 255, 0.12)',
                    color: '#00c8ff',
                    border: '1px solid rgba(0, 200, 255, 0.3)',
                    padding: '2px 8px',
                    borderRadius: 6,
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 4,
                  }}
                >
                  Port {port}
                  <button type="button" onClick={() => setManagementPorts(managementPorts.filter((p) => p !== port))} style={{ background: 'none', border: 'none', color: '#00c8ff', cursor: 'pointer', padding: 0 }}>
                    <X size={12} />
                  </button>
                </span>
              ))}
            </div>
          </div>

          {/* Dev / Proxy Ports Bypass */}
          <div style={{ padding: 14, background: 'rgba(255, 255, 255, 0.02)', borderRadius: 10, border: '1px solid rgba(255, 255, 255, 0.06)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ fontSize: '0.78rem', fontWeight: 800, color: 'var(--text-primary)' }}>
                منافذ التطوير وتجاوز الوكيل (Dev / Proxy Ports)
              </span>
              <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.75rem', color: devPortsEnabled ? '#00e676' : 'var(--text-secondary)', cursor: 'pointer' }}>
                <input type="checkbox" checked={devPortsEnabled} onChange={(e) => setDevPortsEnabled(e.target.checked)} />
                {devPortsEnabled ? 'مفعل (Dev Mode)' : 'معطل في الإنتاج'}
              </label>
            </div>

            {devPortsEnabled && (
              <>
                <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
                  <input
                    className="bl-input"
                    type="number"
                    placeholder="رقم المنفذ (مثال: 5173)..."
                    value={newDevPort}
                    onChange={(e) => setNewDevPort(e.target.value)}
                    style={{ width: 140 }}
                  />
                  <button type="button" className="btn btn-ghost" onClick={addDevPort} style={{ padding: '4px 12px', fontSize: '0.75rem' }}>
                    <Plus size={12} /> إضافة منفذ
                  </button>
                </div>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {devPorts.map((port) => (
                    <span
                      key={port}
                      style={{
                        fontFamily: 'JetBrains Mono, monospace',
                        fontSize: '0.78rem',
                        fontWeight: 800,
                        background: 'rgba(255, 171, 64, 0.12)',
                        color: '#ffab40',
                        border: '1px solid rgba(255, 171, 64, 0.3)',
                        padding: '2px 8px',
                        borderRadius: 6,
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: 4,
                      }}
                    >
                      Port {port}
                      <button type="button" onClick={() => setDevPorts(devPorts.filter((p) => p !== port))} style={{ background: 'none', border: 'none', color: '#ffab40', cursor: 'pointer', padding: 0 }}>
                        <X size={12} />
                      </button>
                    </span>
                  ))}
                </div>
              </>
            )}
          </div>
        </div>
      </div>

      {/* ── 4. Zone-Based Interface Mapping ── */}
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
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16, flexWrap: 'wrap', gap: 10 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Network size={18} style={{ color: '#818cf8' }} />
            <div>
              <h3 style={{ margin: 0, fontSize: '0.98rem', fontWeight: 800, color: 'var(--text-primary)' }}>
                4. ربط مناطق الأمان بالواجهات الشبكية (Zone-to-Interface Mapping)
              </h3>
              <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
                توزيع كروت الشبكة والأنفاق على المناطق الأمنية (WAN / LAN / DMZ / MGMT)
              </span>
            </div>
          </div>

          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <select className="bl-input" value={newZoneName} onChange={(e) => setNewZoneName(e.target.value)} style={{ width: 110, fontSize: '0.78rem' }}>
              <option value="WAN">WAN</option>
              <option value="LAN">LAN</option>
              <option value="DMZ">DMZ</option>
              <option value="MGMT">MGMT</option>
            </select>
            <input
              className="bl-input"
              placeholder="اسم الكرت (مثال: eth2, wg0)..."
              value={newZoneIface}
              onChange={(e) => setNewZoneIface(e.target.value)}
              style={{ width: 150, fontSize: '0.78rem' }}
            />
            <button type="button" className="btn btn-ghost" onClick={addInterfaceToZone} style={{ padding: '6px 12px', fontSize: '0.78rem' }}>
              <Plus size={12} /> ربط بالمنطقة
            </button>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 12 }}>
          {['WAN', 'LAN', 'DMZ', 'MGMT'].map((zName) => {
            const ifaces = zones[zName] || [];
            return (
              <div
                key={zName}
                style={{
                  background: 'rgba(255, 255, 255, 0.02)',
                  border: '1px solid rgba(255, 255, 255, 0.06)',
                  borderRadius: 10,
                  padding: 14,
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                  <span style={{ fontWeight: 800, fontSize: '0.85rem', color: '#00c8ff' }}>{zName} Zone</span>
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>{ifaces.length} واجهات</span>
                </div>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', minHeight: 32 }}>
                  {ifaces.length === 0 ? (
                    <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>لا توجد كروت مخصصة.</span>
                  ) : (
                    ifaces.map((iface) => (
                      <span
                        key={iface}
                        style={{
                          fontFamily: 'JetBrains Mono, monospace',
                          fontSize: '0.75rem',
                          background: 'rgba(129, 140, 248, 0.12)',
                          color: '#818cf8',
                          border: '1px solid rgba(129, 140, 248, 0.25)',
                          padding: '2px 8px',
                          borderRadius: 4,
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: 4,
                        }}
                      >
                        {iface}
                        <button type="button" onClick={() => removeInterfaceFromZone(zName, iface)} style={{ background: 'none', border: 'none', color: '#818cf8', cursor: 'pointer', padding: 0 }}>
                          <X size={11} />
                        </button>
                      </span>
                    ))
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* ── 5. Dynamic Custom Ports Matrix ── */}
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
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16, flexWrap: 'wrap', gap: 10 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Layers size={18} style={{ color: '#00e676' }} />
            <div>
              <h3 style={{ margin: 0, fontSize: '0.98rem', fontWeight: 800, color: 'var(--text-primary)' }}>
                5. مصفوفة المنافذ المخصصة الديناميكية (Custom Service Ports)
              </h3>
              <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
                تعريف منافذ مخصصة غير محدودة للخدمات الداخلية ووحدات الـ NGFW
              </span>
            </div>
          </div>
        </div>

        {/* Input Row for New Custom Port */}
        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1fr 1fr auto', gap: 10, marginBottom: 14, alignItems: 'center' }}>
          <input
            className="bl-input"
            placeholder="اسم المنفذ (مثال: DNS Security, Syslog)..."
            value={newCpName}
            onChange={(e) => setNewCpName(e.target.value)}
            style={{ fontSize: '0.8rem' }}
          />
          <input
            className="bl-input"
            type="number"
            placeholder="المنفذ (1-65535)..."
            value={newCpPort}
            onChange={(e) => setNewCpPort(e.target.value)}
            style={{ fontSize: '0.8rem' }}
          />
          <select className="bl-input" value={newCpProto} onChange={(e) => setNewCpProto(e.target.value)} style={{ fontSize: '0.8rem' }}>
            <option value="tcp">TCP</option>
            <option value="udp">UDP</option>
            <option value="both">Both (TCP/UDP)</option>
          </select>
          <select className="bl-input" value={newCpDir} onChange={(e) => setNewCpDir(e.target.value)} style={{ fontSize: '0.8rem' }}>
            <option value="input">Input (وارد للمنظومة)</option>
            <option value="forward">Forward (توجيه للشبكة)</option>
            <option value="both">Both (كلاهما)</option>
          </select>
          <button type="button" className="btn btn-primary" onClick={saveCustomPort} style={{ padding: '8px 16px', fontSize: '0.8rem' }}>
            <Plus size={13} /> {editCpIndex !== null ? 'تحديث' : 'إضافة'}
          </button>
        </div>

        {/* Custom Ports Table */}
        <div style={{ overflowX: 'auto' }}>
          {customPorts.length === 0 ? (
            <div style={{ padding: '24px 0', textAlign: 'center', color: 'var(--text-secondary)', fontSize: '0.78rem' }}>
              لا توجد منافذ مخصصة مضافة حالياً.
            </div>
          ) : (
            <table className="table" style={{ width: '100%' }}>
              <thead>
                <tr>
                  <th>اسم الخدمة</th>
                  <th>المنفذ</th>
                  <th>البروتوكول</th>
                  <th>الاتجاه</th>
                  <th>الحالة</th>
                  <th style={{ width: 80, textAlign: 'left' }}>إجراءات</th>
                </tr>
              </thead>
              <tbody>
                {customPorts.map((cp, idx) => (
                  <tr key={idx}>
                    <td style={{ fontWeight: 700, color: 'var(--text-primary)' }}>{cp.name}</td>
                    <td>
                      <code style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.8rem', color: '#00c8ff', background: 'rgba(0, 200, 255, 0.08)', padding: '2px 8px', borderRadius: 4 }}>
                        {cp.port}
                      </code>
                    </td>
                    <td>
                      <span style={{ fontSize: '0.74rem', fontFamily: 'JetBrains Mono, monospace', textTransform: 'uppercase' }}>
                        {cp.protocol}
                      </span>
                    </td>
                    <td>
                      <span style={{ fontSize: '0.74rem', color: 'var(--text-secondary)' }}>{cp.direction}</span>
                    </td>
                    <td>
                      <label style={{ cursor: 'pointer', fontSize: '0.74rem', color: cp.enabled !== false ? '#00e676' : '#ff4d6a', fontWeight: 700 }}>
                        <input
                          type="checkbox"
                          checked={cp.enabled !== false}
                          onChange={(e) => {
                            const updated = [...customPorts];
                            updated[idx].enabled = e.target.checked;
                            setCustomPorts(updated);
                          }}
                        />{' '}
                        {cp.enabled !== false ? 'مفعل' : 'معطل'}
                      </label>
                    </td>
                    <td style={{ textAlign: 'left' }}>
                      <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
                        <button
                          type="button"
                          className="btn btn-ghost"
                          onClick={() => {
                            setNewCpName(cp.name);
                            setNewCpPort(cp.port);
                            setNewCpProto(cp.protocol);
                            setNewCpDir(cp.direction);
                            setEditCpIndex(idx);
                          }}
                          style={{ padding: '4px 8px' }}
                          title="تعديل"
                        >
                          <Edit2 size={13} />
                        </button>
                        <button
                          type="button"
                          className="btn btn-ghost"
                          onClick={() => setCustomPorts(customPorts.filter((_, i) => i !== idx))}
                          style={{ color: '#ff4d6a', padding: '4px 8px' }}
                          title="حذف"
                        >
                          <Trash2 size={13} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </form>
  );
}
