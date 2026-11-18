/**
 * useUnifiedMapData.js
 * ─────────────────────────────────────────────────────────────
 * Unified Threat & Map Data Hook — Single Source of Truth
 * Connects all map views (3D Globe, 2D Maps, SOC Command Panels)
 * to real backend database telemetry and WebSocket live feeds.
 *
 * Sourced from: F:\enterprise_ngfw\api\routers\v1\dashboard.py
 */

import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { dashboardApi } from '../modules/dashboard/api/dashboardApi';
import { useLiveFeedStore } from '../stores/liveFeedStore';

export const HQ_DEFAULT_COORDS = [13.5795, 44.0206]; // Taiz, Yemen

export function useUnifiedMapData(options = {}) {
  const {
    timeframe = '24h',
    severityFilter = 'all',
    categoryFilter = 'all',
    refetchInterval = 5000,
  } = options;

  const alertsFeed = useLiveFeedStore((s) => s.alertsFeed);

  // 1. Fetch HQ & Branch locations
  const { data: locationData } = useQuery({
    queryKey: ['dashboard_location'],
    queryFn: () => dashboardApi.location().then((res) => res?.data || {}),
    staleTime: 600000,
  });

  // 2. Fetch Live Globe Threats
  const { data: globeThreatData, isLoading: isThreatsLoading } = useQuery({
    queryKey: ['globe_live_threats', timeframe, severityFilter, categoryFilter],
    queryFn: () =>
      dashboardApi
        .globeThreats({ timeframe, severity: severityFilter, category: categoryFilter })
        .then((r) => r?.data || {}),
    refetchInterval,
  });

  // 3. Fetch Aggregated Globe Stats
  const { data: globeStatsData, isLoading: isStatsLoading } = useQuery({
    queryKey: ['globe_stats', timeframe, severityFilter, categoryFilter],
    queryFn: () =>
      dashboardApi
        .globeStats({ timeframe, severity: severityFilter, category: categoryFilter })
        .then((r) => r?.data || {}),
    refetchInterval: refetchInterval * 2,
  });

  // 4. Fetch Map Overlay KPIs
  const { data: mapKpiData } = useQuery({
    queryKey: ['dashboard_map_stats'],
    queryFn: () => dashboardApi.mapStats().then((r) => r?.data || {}),
    refetchInterval: 10000,
  });

  // ── Normalize HQ & Branch Targets ──
  const targets = useMemo(() => {
    const list = [];
    if (locationData?.headquarters) {
      const hq = locationData.headquarters;
      list.push({
        id: 'taiz-hq',
        name: hq.name || 'المقر الرئيسي – تعز 🇾🇪',
        country: hq.country || 'اليمن',
        flag: hq.flag || '🇾🇪',
        lat: hq.lat ?? HQ_DEFAULT_COORDS[0],
        lng: hq.lng ?? HQ_DEFAULT_COORDS[1],
        lon: hq.lng ?? HQ_DEFAULT_COORDS[1],
        color: '#00e676',
      });
    } else {
      list.push({
        id: 'taiz-hq',
        name: 'المقر الرئيسي – تعز 🇾🇪',
        country: 'اليمن',
        flag: '🇾🇪',
        lat: HQ_DEFAULT_COORDS[0],
        lng: HQ_DEFAULT_COORDS[1],
        lon: HQ_DEFAULT_COORDS[1],
        color: '#00e676',
      });
    }

    if (Array.isArray(locationData?.branches)) {
      locationData.branches.forEach((b, i) => {
        list.push({
          id: `branch-${i}`,
          name: b.name || `فرع ${i + 1}`,
          country: b.country || '',
          flag: b.flag || '🌐',
          lat: b.lat ?? 0,
          lng: b.lng ?? 0,
          lon: b.lng ?? 0,
          color: '#00d4ff',
        });
      });
    }
    return list;
  }, [locationData]);

  const primaryHq = targets[0] || { lat: HQ_DEFAULT_COORDS[0], lng: HQ_DEFAULT_COORDS[1] };

  // ── Normalize & Combine Threat Arcs ──
  const arcs = useMemo(() => {
    const combined = [];
    const seenIds = new Set();

    // A. REST Live Threats Feed from backend database
    const restFeed = globeThreatData?.feed || [];
    restFeed.forEach((item) => {
      if (!item) return;
      const itemId = item.id || `rest-${item.ip}-${item.time}`;
      if (seenIds.has(itemId)) return;

      const srcLat = typeof item.src_lat === 'number' ? item.src_lat : parseFloat(item.src_lat);
      const srcLng = typeof item.src_lng === 'number' ? item.src_lng : parseFloat(item.src_lng);

      // Skip invalid or missing coordinates to eliminate ghost/fake attack arcs
      if (isNaN(srcLat) || isNaN(srcLng) || (srcLat === 0 && srcLng === 0)) return;

      seenIds.add(itemId);
      const colorHex = item.color || item.col || (item.sev === 'critical' ? '#ff4d6d' : item.sev === 'high' ? '#ff9100' : '#00d4ff');

      combined.push({
        id: itemId,
        srcLat,
        srcLng,
        startLat: srcLat,
        startLng: srcLng,
        dstLat: item.dst_lat || primaryHq.lat,
        dstLng: item.dst_lng || primaryHq.lng,
        endLat: item.dst_lat || primaryHq.lat,
        endLng: item.dst_lng || primaryHq.lng,
        color: colorHex,
        col: colorHex,
        country: item.country || 'Unknown',
        flag: item.flag || '🌐',
        ip: item.ip || item.source_ip || '0.0.0.0',
        targetIp: item.target_ip || item.destination_ip || '10.0.0.10',
        severity: item.sev || item.severity || 'medium',
        type: item.type || item.event_type || 'Intrusion',
        time: item.time || new Date().toISOString(),
        raw: item,
      });
    });

    // B. Live WebSocket Feed Stream
    (alertsFeed || []).forEach((item) => {
      if (!item) return;
      const itemId = item.id || `ws-${item.timestamp}-${item.src}`;
      if (seenIds.has(itemId)) return;

      const srcLat = typeof item.src_lat === 'number' ? item.src_lat : typeof item.latitude === 'number' ? item.latitude : parseFloat(item.src_lat || item.latitude);
      const srcLng = typeof item.src_lng === 'number' ? item.src_lng : typeof item.longitude === 'number' ? item.longitude : parseFloat(item.src_lng || item.longitude);

      // Skip invalid or missing coordinates to eliminate ghost/fake attack arcs
      if (isNaN(srcLat) || isNaN(srcLng) || (srcLat === 0 && srcLng === 0)) return;

      seenIds.add(itemId);
      const colorHex = item.severity === 'critical' ? '#ff4d6d' : item.severity === 'high' ? '#ff9100' : '#00d4ff';

      combined.push({
        id: itemId,
        srcLat,
        srcLng,
        startLat: srcLat,
        startLng: srcLng,
        dstLat: primaryHq.lat,
        dstLng: primaryHq.lng,
        endLat: primaryHq.lat,
        endLng: primaryHq.lng,
        color: colorHex,
        col: colorHex,
        country: item.country || 'Local',
        flag: item.flag || '🌐',
        ip: item.src || item.src_ip || '0.0.0.0',
        targetIp: item.dst_ip || '10.0.0.10',
        severity: item.severity || 'medium',
        type: item.title || item.event_type || 'Intrusion',
        time: item.timestamp || item.time || new Date().toISOString(),
        raw: item,
      });
    });

    return combined;
  }, [globeThreatData, alertsFeed, primaryHq]);

  const stats = useMemo(() => {
    return (
      globeThreatData?.stats || {
        total: arcs.length,
        blocked: arcs.filter((a) => a.severity === 'critical' || a.severity === 'high').length,
        countries: new Set(arcs.map((a) => a.country)).size || 1,
        rate: roundToTwo(arcs.length / 60),
      }
    );
  }, [globeThreatData, arcs]);

  // ── Dynamic Fallbacks for Cards (Severity, Top Countries, Attack Types, Regions, Timeline) ──
  const severity = useMemo(() => {
    if (globeStatsData?.severity && (globeStatsData.severity.critical > 0 || globeStatsData.severity.high > 0 || globeStatsData.severity.medium > 0)) {
      return globeStatsData.severity;
    }
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    arcs.forEach(a => {
      const s = (a.severity || 'medium').toLowerCase();
      if (counts[s] !== undefined) counts[s]++;
      else counts.medium++;
    });
    return counts;
  }, [globeStatsData, arcs]);

  const topCountries = useMemo(() => {
    if (globeStatsData?.top_countries && globeStatsData.top_countries.length > 0) {
      return globeStatsData.top_countries;
    }
    const map = new Map();
    arcs.forEach(a => {
      if (a.country && a.country !== 'Unknown' && a.country !== 'غير معروف') {
        const existing = map.get(a.country) || { name: a.country, flag: a.flag || '🌐', count: 0 };
        existing.count++;
        map.set(a.country, existing);
      }
    });
    const colors = ['#00d4ff', '#ff4d6d', '#ff9800', '#00e676', '#a78bfa'];
    return Array.from(map.values())
      .sort((a, b) => b.count - a.count)
      .slice(0, 5)
      .map((c, i) => ({ ...c, color: colors[i % colors.length] }));
  }, [globeStatsData, arcs]);

  const attackTypes = useMemo(() => {
    if (globeStatsData?.attack_types && Object.values(globeStatsData.attack_types).some(v => v > 0)) {
      return globeStatsData.attack_types;
    }
    const types = { malware: 0, web: 0, exploit: 0, network: 0, other: 0 };
    arcs.forEach(a => {
      const t = (a.type || '').toLowerCase();
      if (t.includes('malware') || t.includes('virus')) types.malware++;
      else if (t.includes('web') || t.includes('waf') || t.includes('sql') || t.includes('xss')) types.web++;
      else if (t.includes('exploit') || t.includes('cve') || t.includes('overflow')) types.exploit++;
      else if (t.includes('network') || t.includes('dos') || t.includes('scan') || t.includes('ids')) types.network++;
      else types.other++;
    });
    return types;
  }, [globeStatsData, arcs]);

  const regions = useMemo(() => {
    if (globeStatsData?.regions && Object.values(globeStatsData.regions).some(v => v > 0)) {
      return globeStatsData.regions;
    }
    const reg = { 'الشرق الأوسط': 0, 'أوروبا': 0, 'أفريقيا': 0, 'أمريكا الشمالية': 0, 'أمريكا الجنوبية': 0, 'آسيا': 0 };
    arcs.forEach(a => {
      const country = a.country || '';
      if (country.includes('اليمن') || country.includes('السعودية') || country.includes('الإمارات') || country.includes('مصر') || country.includes('عمان') || country.includes('قطر') || country.includes('الكويت')) {
        reg['الشرق الأوسط']++;
      } else if (country.includes('Germany') || country.includes('France') || country.includes('UK') || country.includes('United Kingdom') || country.includes('ألمانيا')) {
        reg['أوروبا']++;
      } else if (country.includes('China') || country.includes('Japan') || country.includes('India') || country.includes('الصين')) {
        reg['آسيا']++;
      } else if (country.includes('United States') || country.includes('US') || country.includes('Canada') || country.includes('أمريكا')) {
        reg['أمريكا الشمالية']++;
      } else {
        reg['الشرق الأوسط']++;
      }
    });
    return reg;
  }, [globeStatsData, arcs]);

  const timeline = useMemo(() => {
    if (globeStatsData?.timeline && globeStatsData.timeline.length > 0) {
      return globeStatsData.timeline;
    }
    const bins = [];
    const now = new Date();
    for (let i = 11; i >= 0; i--) {
      const d = new Date(now.getTime() - i * 2 * 3600 * 1000);
      const timeStr = d.toLocaleTimeString('ar-SA', { hour: '2-digit', minute: '2-digit', hour12: false });
      const matching = arcs.filter(a => {
        const at = new Date(a.time).getTime();
        return Math.abs(at - d.getTime()) <= 3600 * 1000;
      });
      const count = matching.length;
      const blocked = matching.filter(a => a.severity === 'critical' || a.severity === 'high').length;
      bins.push({ time: timeStr, attacks: count, blocked });
    }
    return bins;
  }, [globeStatsData, arcs]);

  return {
    arcs,
    targets,
    hqCoords: [primaryHq.lat, primaryHq.lng],
    stats,
    mapKpis: mapKpiData || {},
    topCountries,
    regions,
    severity,
    attackTypes,
    timeline,
    isLoading: isThreatsLoading || isStatsLoading,
  };
}

function roundToTwo(num) {
  return Math.round((num + Number.EPSILON) * 100) / 100;
}

export default useUnifiedMapData;
