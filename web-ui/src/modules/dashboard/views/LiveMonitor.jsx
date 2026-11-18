import { useEffect, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import {
  Globe2, Activity, AlertTriangle, Radio, Maximize2, Minimize2, ShieldAlert, Layers
} from 'lucide-react';
import {
  wafApi, idsApi, dlpApi, webFilterApi, malwareApi, dnsApi,
  emailApi, sslApi, firewallApi, ubaApi, proxyApi, vpnApi,
} from '../../../services/api';
import { useLiveFeedStore } from '../../../stores/liveFeedStore';
import useDashboardStore from '../stores/useDashboardStore';
import { useUnifiedMapData } from '../../../hooks/useUnifiedMapData';

import AttackGlobe from '../components/AttackGlobe';
import AttackMap from '../../dashboardpro/widgets/AttackMap';
import TrafficChart from '../components/TrafficChart';
import AlertFeed from '../components/AlertFeed';
import ModuleHealthGrid, { getModuleHealthList } from '../components/ModuleHealth';
import StatCardsGrid, { getStatCards } from '../components/StatCards';
import EventDetailDrawer from '../components/EventDetailDrawer';

/* animation */
const cv = { hidden: { opacity: 0 }, show: { opacity: 1, transition: { staggerChildren: 0.08 } } };
const iv = { hidden: { opacity: 0, y: 16 }, show: { opacity: 1, y: 0, transition: { type: 'spring', stiffness: 280, damping: 26 } } };

/* ── Siren Synthesizer ── */
const playSiren = () => {
  const AudioCtx = window.AudioContext || window.webkitAudioContext;
  if (!AudioCtx) return;
  const ctx = new AudioCtx();
  const osc = ctx.createOscillator();
  const gain = ctx.createGain();
  osc.connect(gain);
  gain.connect(ctx.destination);

  osc.type = 'square';
  const now = ctx.currentTime;
  osc.frequency.setValueAtTime(500, now);
  osc.frequency.linearRampToValueAtTime(1000, now + 0.3);
  osc.frequency.linearRampToValueAtTime(500, now + 0.6);
  osc.frequency.linearRampToValueAtTime(1000, now + 0.9);
  osc.frequency.linearRampToValueAtTime(500, now + 1.2);

  gain.gain.setValueAtTime(0, now);
  gain.gain.linearRampToValueAtTime(0.05, now + 0.05); // low volume to protect ears
  gain.gain.setValueAtTime(0.05, now + 1.15);
  gain.gain.linearRampToValueAtTime(0, now + 1.2);

  osc.start(now);
  osc.stop(now + 1.2);
};

export default function LiveMonitor({ sysStatus }) {
  const liveAlerts = useLiveFeedStore(s => s.alertsFeed);
  const trafficData = useLiveFeedStore(s => s.trafficHistory);
  const liveStats = useLiveFeedStore(s => s.liveStats);
  const wsState = useLiveFeedStore(s => s.wsState);
  const [soundEnabled, setSoundEnabled] = useState(false);
  const soundEnabledRef = useRef(soundEnabled);
  const [isGlobeFullscreen, setIsGlobeFullscreen] = useState(false);
  const [mapMode, setMapMode] = useState('2d'); // '2d' is default as requested

  const globePanelRef = useRef(null);

  const selectedAlert = useDashboardStore((s) => s.selectedEvent);
  const setSelectedAlert = useDashboardStore((s) => s.setSelectedEvent);

  useEffect(() => {
    soundEnabledRef.current = soundEnabled;
  }, [soundEnabled]);

  // Handle Fullscreen change events
  useEffect(() => {
    const handleFSChange = () => {
      setIsGlobeFullscreen(!!document.fullscreenElement);
    };
    document.addEventListener('fullscreenchange', handleFSChange);
    return () => document.removeEventListener('fullscreenchange', handleFSChange);
  }, []);

  const toggleGlobeFullscreen = () => {
    if (!globePanelRef.current) return;
    if (!document.fullscreenElement) {
      globePanelRef.current.requestFullscreen().catch(() => {});
    } else {
      document.exitFullscreen().catch(() => {});
    }
  };

  // Play siren audio alert for critical/high alerts
  useEffect(() => {
    if (liveAlerts.length > 0) {
      const latest = liveAlerts[0];
      if (soundEnabledRef.current && (latest.severity === 'critical' || latest.severity === 'high')) {
        playSiren();
      }
    }
  }, [liveAlerts]);

  /* ── Module health ── */
  const fetchMods = async () => {
    const safeCall = (fn) => (typeof fn === 'function' ? fn().then((r) => r.data).catch(() => null) : Promise.resolve(null));

    const [waf, ids, dlp, wf, mal, dns, email, ssl, fw, uba, proxy, vpn, qos, systemMods] = await Promise.all([
      safeCall(wafApi?.status),
      safeCall(idsApi?.status),
      safeCall(dlpApi?.status),
      safeCall(webFilterApi?.status),
      safeCall(malwareApi?.status),
      safeCall(dnsApi?.status),
      safeCall(emailApi?.status),
      safeCall(sslApi?.status),
      safeCall(firewallApi?.getStats || firewallApi?.getConfig),
      safeCall(ubaApi?.status),
      safeCall(proxyApi?.status),
      safeCall(vpnApi?.status),
      safeCall(qosApi?.status),
      safeCall(systemApi?.modules),
    ]);

    const sysMap = systemMods || {};

    const resolveModuleState = (modData, sysConf) => {
      if (sysConf && typeof sysConf.enabled === 'boolean' && sysConf.enabled === false) {
        return { enabled: false, status: 'disabled' };
      }
      if (sysConf && (sysConf.mode === 'off' || sysConf.mode === 'disabled')) {
        return { enabled: false, status: 'disabled' };
      }
      if (modData && (modData.enabled === false || modData.status === 'disabled' || modData.mode === 'off')) {
        return { enabled: false, status: 'disabled' };
      }
      return modData || sysConf || { enabled: true };
    };

    return {
      waf: resolveModuleState(waf, sysMap.waf),
      ids: resolveModuleState(ids, sysMap.ids_ips || sysMap.ids),
      ids_ips: resolveModuleState(ids, sysMap.ids_ips || sysMap.ids),
      dlp: resolveModuleState(dlp, sysMap.dlp),
      wf: resolveModuleState(wf, sysMap.web_filter || sysMap.wf),
      web_filter: resolveModuleState(wf, sysMap.web_filter || sysMap.wf),
      mal: resolveModuleState(mal, sysMap.malware_av || sysMap.mal),
      malware_av: resolveModuleState(mal, sysMap.malware_av || sysMap.mal),
      dns: resolveModuleState(dns, sysMap.dns_security || sysMap.dns),
      dns_security: resolveModuleState(dns, sysMap.dns_security || sysMap.dns),
      email: resolveModuleState(email, sysMap.email_security || sysMap.email),
      email_security: resolveModuleState(email, sysMap.email_security || sysMap.email),
      ssl: resolveModuleState(ssl, sysMap.ssl_inspection || sysMap.ssl),
      ssl_inspection: resolveModuleState(ssl, sysMap.ssl_inspection || sysMap.ssl),
      fw: resolveModuleState(fw, sysMap.firewall || sysMap.fw),
      firewall: resolveModuleState(fw, sysMap.firewall || sysMap.fw),
      uba: resolveModuleState(uba, sysMap.uba),
      proxy: resolveModuleState(proxy, sysMap.proxy),
      vpn: resolveModuleState(vpn, sysMap.vpn),
      qos: resolveModuleState(qos, sysMap.qos),
    };
  };

  const { data: mods } = useQuery({
    queryKey: ['dash_mods_health'],
    queryFn: fetchMods,
    refetchInterval: 5000,
  });

  const { arcs: combinedArcs, targets, stats: globeStats, mapKpis } = useUnifiedMapData();

  const statCards = getStatCards(liveStats, sysStatus);
  const modulesHealth = getModuleHealthList(mods);
  const criticalCount = liveAlerts.filter(a => a.severity === 'critical').length;

  return (
    <motion.div initial="hidden" animate="show" variants={cv} style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>

      {/* ── Stat cards ── */}
      <motion.div variants={iv}>
        <StatCardsGrid statCards={statCards} />
      </motion.div>

      {/* ── WS status banner ── */}
      {(wsState === 'closed' || wsState === 'reconnecting') && (
        <motion.div
          variants={iv}
          style={{
            display: 'flex', alignItems: 'center', gap: 10,
            padding: '10px 14px', marginBottom: 14,
            background: 'rgba(255,193,7,0.06)', border: '1px solid rgba(255,193,7,0.2)', borderRadius: 10,
            fontSize: '0.8rem', color: '#ffc107', fontFamily: 'Cairo, sans-serif',
          }}
        >
          <Radio size={14} />
          {wsState === 'reconnecting'
            ? 'اتصال البث الحي مقطوع — جارٍ إعادة الاتصال تلقائياً...'
            : 'اتصال البث الحي مقطوع — يتم إعادة المحاولة...'}
        </motion.div>
      )}

      {/* ── Main grid ── */}
      <div className="db-main-grid">

        {/* Left column */}
        <div className="dash-col-left" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

          {/* Map Widgets (Both 2D & 3D stay mounted to preserve WebGL context & HQ pins) */}
          <div style={{ display: mapMode === '2d' ? 'block' : 'none' }}>
            <motion.div variants={iv} style={{ marginBottom: 0 }}>
              <AttackMap
                liveAlerts={liveAlerts}
                mapStats={mapKpis && Object.keys(mapKpis).length > 0 ? mapKpis : globeStats}
                mapMode={mapMode}
                onToggleMapMode={setMapMode}
              />
            </motion.div>
          </div>

          <div style={{ display: mapMode === '3d' ? 'block' : 'none' }}>
            <motion.div
              ref={globePanelRef}
              className="db-panel"
              variants={iv}
              style={{
                height: isGlobeFullscreen ? '100vh' : 460,
                marginBottom: 0,
                display: 'flex',
                flexDirection: 'column',
                background: isGlobeFullscreen ? '#0a0e1a' : undefined,
                padding: isGlobeFullscreen ? '20px' : undefined,
              }}
            >
              <div className="db-panel-header">
                <div className="db-panel-title">
                  <Globe2 size={16} /> خريطة الهجمات ثلاثية الأبعاد الحية (3D Threat Map)
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <button
                    type="button"
                    onClick={toggleGlobeFullscreen}
                    title={isGlobeFullscreen ? 'إلغاء وضع ملء الشاشة' : 'توسيع الخريطة ملء الشاشة'}
                    style={{
                      border: '1px solid rgba(255,255,255,0.18)',
                      background: 'rgba(255,255,255,0.06)',
                      color: '#00d4ff',
                      borderRadius: 6,
                      padding: '4px 10px',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: 6,
                      fontSize: '0.72rem',
                      fontFamily: 'Cairo, sans-serif',
                      transition: 'all 0.2s ease',
                    }}
                  >
                    {isGlobeFullscreen ? <Minimize2 size={13} /> : <Maximize2 size={13} />}
                    <span>{isGlobeFullscreen ? 'تصغير' : 'ملء الشاشة'}</span>
                  </button>
                </div>
              </div>
              <div style={{ flex: 1, minHeight: 0, position: 'relative', width: '100%', height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <AttackGlobe arcs={combinedArcs} targets={targets} onSelectArc={setSelectedAlert} />
              </div>
            </motion.div>
          </div>


          {/* Traffic chart */}
          <motion.div className="db-panel" variants={iv} style={{ height: 260, marginBottom: 0, display: 'flex', flexDirection: 'column' }}>
            <div className="db-panel-header">
              <div className="db-panel-title">
                <Activity size={16} /> معدل النقل الشبكي — L7
              </div>
              {wsState === 'open' && (
                <span style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: '0.7rem', color: '#28c76f' }}>
                  <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#28c76f', animation: 'db-pulse 2s infinite', display: 'inline-block' }} />
                  بث حي
                </span>
              )}
            </div>
            <div className="db-chart-wrap" style={{ flex: 1, minHeight: 0 }}>
              <TrafficChart data={trafficData} />
            </div>
          </motion.div>

          {/* Module health */}
          <motion.div variants={iv} style={{ height: 150 }}>
            <ModuleHealthGrid modulesHealth={modulesHealth} />
          </motion.div>
        </div>

        {/* Right column — Alert feed */}
        <div className="dash-col-right">
          <motion.div
            className="db-panel"
            variants={iv}
            style={{ height: '100%', marginBottom: 0, display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0 }}
          >
            <div className="db-panel-header">
              <div className="db-panel-title">
                <AlertTriangle size={16} style={{ color: criticalCount > 0 ? '#ff5f5f' : undefined }} />
                تغذية التنبيهات الحية
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <button
                  onClick={() => setSoundEnabled(!soundEnabled)}
                  title={soundEnabled ? 'إيقاف ونان التنبيهات' : 'تفعيل ونان التنبيهات'}
                  style={{ border: 'none', background: 'transparent', color: soundEnabled ? '#ff5f5f' : 'rgba(255,255,255,0.3)', cursor: 'pointer', padding: 4 }}
                >
                  <ShieldAlert size={16} />
                </button>
                <span style={{ fontSize: '0.72rem', color: 'rgba(255,255,255,0.4)', fontFamily: 'Cairo, sans-serif' }}>
                  {liveAlerts.length} تنبيهات
                </span>
              </div>
            </div>
            <div style={{ flex: 1, minHeight: 0, overflowY: 'auto', scrollbarWidth: 'thin' }}>
              <AlertFeed alerts={liveAlerts} alertsToShow={liveAlerts} onSelectAlert={setSelectedAlert} />
            </div>
          </motion.div>
        </div>

      </div>

      {/* ── Event Detail Drawer ── */}
      <EventDetailDrawer event={selectedAlert} alert={selectedAlert} onClose={() => setSelectedAlert(null)} />

    </motion.div>
  );
}
