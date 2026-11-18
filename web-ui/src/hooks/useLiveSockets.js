import { useEffect, useRef } from 'react';
import { BASE_URL } from '../services/apiClient';
import { useLiveFeedStore } from '../stores/liveFeedStore';
import { useAlertStore } from '../stores/alertStore';
import { dashboardApi, idsApi } from '../services/api';
import { dashboardApi as dashApi } from '../modules/dashboard/api/dashboardApi';
import { formatAlert } from '../utils/alertFormatter';

function isTokenExpired(token) {
  if (!token) return true;
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    if (!payload.exp) return false;
    return payload.exp * 1000 <= Date.now();
  } catch {
    return true;
  }
}

export function useLiveSockets() {
  const addWafEvent = useLiveFeedStore(s => s.addWafEvent);
  const addTrafficLog = useLiveFeedStore(s => s.addTrafficLog);
  const addAlertLog = useLiveFeedStore(s => s.addAlertLog);
  const setLiveStats = useLiveFeedStore(s => s.setLiveStats);
  const setWsState = useLiveFeedStore(s => s.setWsState);
  const trafficHistory = useLiveFeedStore(s => s.trafficHistory);
  const addAlert = useAlertStore(s => s.addAlert);

  const mainWsRef = useRef(null);
  const wafWsRef = useRef(null);

  const mainRetryCount = useRef(0);
  const wafRetryCount = useRef(0);

  const mainRetryTimer = useRef(null);
  const wafRetryTimer = useRef(null);

  const trafficSeeded = useRef(false);
  const alertsSeeded = useRef(false);

  // Seed traffic history once on startup from the dedicated endpoint
  useEffect(() => {
    if (!trafficSeeded.current && trafficHistory.length === 0) {
      trafficSeeded.current = true;
      dashApi.trafficHistory().then(res => {
        // Endpoint returns the array directly (or wrapped under data)
        const items = Array.isArray(res?.data) ? res.data
          : Array.isArray(res?.data?.data) ? res.data.data
          : [];
        if (items.length > 0) {
          items.forEach(item => {
            const timeStr = typeof item.time === 'number'
              ? new Date(item.time * 1000).toLocaleTimeString('ar-SA', { hour12: false, minute: '2-digit', second: '2-digit' })
              : (item.time || new Date().toLocaleTimeString('ar-SA', { hour12: false, minute: '2-digit', second: '2-digit' }));
            addTrafficLog({
              time: timeStr,
              reqs: typeof item.reqs === 'number' ? item.reqs : (item.requests || 0),
              blocks: typeof item.blocks === 'number' ? item.blocks : (item.dropped || 0),
            });
          });
        }
      }).catch(err => console.error('Failed to seed traffic history:', err));
    }
  }, [addTrafficLog, trafficHistory.length]);

  // Seed alerts history once on startup
  useEffect(() => {
    if (!alertsSeeded.current) {
      alertsSeeded.current = true;
      idsApi.alerts(0, 20).then(res => {
        const items = res?.data?.items || (Array.isArray(res?.data) ? res.data : []);
        if (items.length > 0) {
          items.forEach(alert => {
            const mappedAlert = {
              id: alert.id || crypto.randomUUID(),
              severity: alert.severity || 'info',
              src: alert.src_ip,
              title: alert.category || 'تهديد مكتشف',
              timestamp: alert.full_timestamp || new Date().toISOString(),
              flag: alert.flag || '🌐',
              country: alert.country || 'Local',
              src_lat: alert.src_lat || alert.latitude || null,
              src_lng: alert.src_lng || alert.longitude || null,
              event_type: alert.event_type || 'ids_ips',
            };
            addAlertLog(formatAlert(mappedAlert));
          });
        }
      }).catch(err => console.error("Failed to seed alerts history:", err));
    }
  }, [addAlertLog]);

  useEffect(() => {
    let destroyed = false;

    const wsBase = (BASE_URL || 'http://localhost:8000').replace(/^http/, 'ws');

    // ── 1. Main Telemetry WebSocket ───────────────────
    const connectMain = () => {
      if (destroyed) return;
      const currentToken = localStorage.getItem('bunyanx_token');
      if (!currentToken || isTokenExpired(currentToken)) {
        mainRetryTimer.current = setTimeout(connectMain, 10000);
        return;
      }

      const ws = new WebSocket(`${wsBase}/api/v1/ws/live?token=${currentToken}`);
      mainWsRef.current = ws;

      ws.onopen = () => {
        if (destroyed) { ws.close(); return; }
        mainRetryCount.current = 0;
        setWsState('open');
        ws.send(JSON.stringify({ type: 'subscribe', room: 'stats' }));
        ws.send(JSON.stringify({ type: 'subscribe', room: 'alerts' }));
      };

      ws.onmessage = (msg) => {
        try {
          const { type, data: ev } = JSON.parse(msg.data);
          
          if (type === 'stats') {
            setLiveStats(ev);
            const t = new Date().toLocaleTimeString('ar-SA', { hour12: false, minute: '2-digit', second: '2-digit' });
            const logEntry = {
              time: t,
              reqs: ev.packets_per_second || 0,
              blocks: Math.floor((ev.bytes_per_second || 0) / 1024),
            };
            addTrafficLog(logEntry);
          } else if (type === 'alert') {
            const srcLat = ev.src_lat || ev.latitude || null;
            const srcLng = ev.src_lng || ev.longitude || null;
            const alertEntry = {
              id: ev.id || crypto.randomUUID(),
              severity: ev.severity || 'info',
              title: ev.alert_type || ev.description || 'تهديد مكتشف',
              src: ev.source_ip || '?.?.?.?',
              time: new Date(ev.timestamp || Date.now()).toLocaleTimeString('ar-SA'),
              timestamp: ev.timestamp || new Date().toISOString(),
              country: ev.country || 'Unknown',
              flag: ev.flag || '🌐',
              src_lat: srcLat,
              src_lng: srcLng,
              
              // Keys for AlertsView (IDS/IPS)
              sig_id: ev.event_metadata?.sig_id || 0,
              sample_id: ev.event_metadata?.phantom?.sample_id || '',
              category: ev.alert_type || ev.description || 'تهديد مكتشف',
              src_ip: ev.source_ip || '?.?.?.?',
              dst_ip: ev.destination_ip || '192.168.10.1',
              proto: ev.protocol || 'TCP',
              full_timestamp: ev.timestamp || new Date().toISOString(),
              event_type: ev.event_type || (ev.alert_type?.toLowerCase().includes('ids') || ev.alert_type?.toLowerCase().includes('ips') ? 'ids_ips' : 'other'),
            };
            const formatted = formatAlert(alertEntry);
            addAlertLog(formatted);
            addAlert(formatted);
          }
        } catch (err) {
          console.error("Failed to parse main WS message:", err);
        }
      };

      ws.onclose = (ev) => {
        if (destroyed) return;
        setWsState('reconnecting');
        const delay = ev?.code === 1008 ? 10000 : Math.min(2000 * Math.pow(2, mainRetryCount.current), 30000);
        mainRetryCount.current += 1;
        mainRetryTimer.current = setTimeout(connectMain, delay);
      };

      ws.onerror = () => {
        ws.close();
      };
    };

    // ── 2. WAF Live WebSocket ────────────────────────
    const connectWaf = () => {
      if (destroyed) return;
      const currentToken = localStorage.getItem('bunyanx_token');
      if (!currentToken || isTokenExpired(currentToken)) {
        wafRetryTimer.current = setTimeout(connectWaf, 10000);
        return;
      }

      const ws = new WebSocket(`${wsBase}/api/v1/waf/live`);
      wafWsRef.current = ws;

      ws.onopen = () => {
        if (destroyed) { ws.close(); return; }
        wafRetryCount.current = 0;
        ws.send(JSON.stringify({
          type: "auth",
          token: currentToken
        }));
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          const ev = {
            id: data.timestamp || Date.now(),
            time: new Date((data.timestamp || (Date.now() / 1000)) * 1000).toLocaleTimeString('ar-SA'),
            ip: data.src_ip || 'unknown',
            path: data.path || '/',
            action: data.action || 'ALLOW',
            risk: (data.risk_score || 0.0).toFixed(2),
            cause: data.triggers && data.triggers.length ? data.triggers.join(', ') : (data.xai_explanation || 'فحص أمني'),
          };
          addWafEvent(ev);
        } catch (err) {
          console.error("Failed to parse WAF WS message:", err);
        }
      };

      ws.onclose = (ev) => {
        if (destroyed) return;
        const delay = ev?.code === 1008 ? 10000 : Math.min(2000 * Math.pow(2, wafRetryCount.current), 30000);
        wafRetryCount.current += 1;
        wafRetryTimer.current = setTimeout(connectWaf, delay);
      };

      ws.onerror = () => {
        ws.close();
      };
    };

    connectMain();
    connectWaf();

    return () => {
      destroyed = true;
      if (mainWsRef.current) mainWsRef.current.close();
      if (wafWsRef.current) wafWsRef.current.close();
      clearTimeout(mainRetryTimer.current);
      clearTimeout(wafRetryTimer.current);
    };
  }, [addWafEvent, addTrafficLog, addAlertLog, setLiveStats, addAlert]);
}

export default useLiveSockets;
