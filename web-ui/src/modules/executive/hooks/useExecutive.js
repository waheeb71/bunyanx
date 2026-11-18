import { useQuery, useQueryClient } from '@tanstack/react-query';
import { executiveApi } from '../api/executiveApi';
import { useExecutiveStore } from '../../../stores/executiveStore';

export function useExecutive() {
  const store = useExecutiveStore();
  const queryClient = useQueryClient();

  // 1. Fetch system status
  const cachedSysData = store.sysData;
  const { data: sysData = cachedSysData, isLoading: isSysLoading } = useQuery({
    queryKey: ['exec_sys'],
    queryFn: () => executiveApi.status().then(r => {
      store.setSysData(r.data);
      return r.data;
    }),
    refetchInterval: 10000,
    placeholderData: cachedSysData,
  });

  // 2. Fetch active modules config
  const cachedModulesState = store.modulesState;
  const { data: modulesState = cachedModulesState || {}, isLoading: isModulesLoading } = useQuery({
    queryKey: ['exec_modules'],
    queryFn: () => executiveApi.modules().then(r => {
      store.setModulesState(r.data);
      return r.data || {};
    }),
    placeholderData: cachedModulesState,
  });

  // 3. Fetch security incidents from database
  const cachedIncidents = store.incidents || [];
  const { data: rawIncidents = cachedIncidents, isLoading: isIncidentsLoading, error: incidentsError, refetch: refetchIncidents } = useQuery({
    queryKey: ['exec_incidents'],
    queryFn: () => executiveApi.incidents().then(r => {
      const items = r?.data?.items || (Array.isArray(r?.data) ? r.data : []);
      store.setIncidents(items);
      return items;
    }),
    refetchInterval: 15000,
    placeholderData: cachedIncidents,
  });

  // 4. Fetch IDS alerts
  const cachedIdsAlerts = store.idsAlerts || [];
  const { data: rawIdsAlerts = cachedIdsAlerts, isLoading: isIdsLoading } = useQuery({
    queryKey: ['exec_ids_alerts'],
    queryFn: () => executiveApi.idsAlerts(0, 50).then(r => {
      const items = r?.data?.items || (Array.isArray(r?.data) ? r.data : []);
      store.setIdsAlerts(items);
      return items;
    }),
    refetchInterval: 15000,
    placeholderData: cachedIdsAlerts,
  });

  // Normalize data arrays
  const incidents = Array.isArray(rawIncidents) ? rawIncidents : [];
  const idsAlerts = Array.isArray(rawIdsAlerts) ? rawIdsAlerts : [];

  // 5. Fetch Malware Stats
  const cachedMalwareStats = store.malwareStats;
  const { data: malwareStats = cachedMalwareStats, isLoading: isMalwareLoading } = useQuery({
    queryKey: ['exec_malware_stats'],
    queryFn: () => executiveApi.malwareStats(24).then(r => {
      store.setMalwareStats(r.data);
      return r.data;
    }),
    refetchInterval: 30000,
    placeholderData: cachedMalwareStats,
  });

  // 6. Fetch Threat Trend
  const cachedThreatTrend = store.threatTrend;
  const { data: threatTrendData = cachedThreatTrend } = useQuery({
    queryKey: ['exec_threat_trend'],
    queryFn: () => executiveApi.threatTrend().then(r => {
      store.setThreatTrend(r.data);
      return r.data;
    }),
    refetchInterval: 60000,
    placeholderData: cachedThreatTrend,
  });

  // 7. Fetch Module Event Stats
  const cachedStats = store.statsData;
  const { data: statsData = cachedStats || {} } = useQuery({
    queryKey: ['exec_module_stats'],
    queryFn: () => executiveApi.moduleStats().then(r => {
      store.setStatsData(r.data);
      return r.data || {};
    }),
    refetchInterval: 30000,
    placeholderData: cachedStats,
  });

  // 8. Fetch traffic history for real connection trend
  const cachedTrafficHistory = store.trafficHistory;
  const { data: trafficHistory = cachedTrafficHistory } = useQuery({
    queryKey: ['exec_traffic_history'],
    queryFn: () => executiveApi.trafficHistory().then(r => {
      store.setTrafficHistory(r.data || []);
      return r.data || [];
    }),
    refetchInterval: 10000,
    placeholderData: cachedTrafficHistory,
  });

  const isLoading = isSysLoading || isModulesLoading || isIncidentsLoading || isIdsLoading || isMalwareLoading;

  const refetchAll = () => {
    queryClient.invalidateQueries({ queryKey: ['exec_sys'] });
    queryClient.invalidateQueries({ queryKey: ['exec_modules'] });
    queryClient.invalidateQueries({ queryKey: ['exec_incidents'] });
    queryClient.invalidateQueries({ queryKey: ['exec_ids_alerts'] });
    queryClient.invalidateQueries({ queryKey: ['exec_malware_stats'] });
    queryClient.invalidateQueries({ queryKey: ['exec_threat_trend'] });
    queryClient.invalidateQueries({ queryKey: ['exec_module_stats'] });
    queryClient.invalidateQueries({ queryKey: ['exec_traffic_history'] });
  };

  // Compute operational uptime display
  const uptimeSeconds = sysData?.uptime_seconds || sysData?.uptime || 0;
  const uptimeDays = Math.floor(uptimeSeconds / 86400);
  const uptimeHours = Math.floor((uptimeSeconds % 86400) / 3600);
  const uptimeStr = uptimeDays > 0 ? `${uptimeDays} يوم ${uptimeHours} ساعة` : `${uptimeHours} ساعة`;

  // Dynamic security risk calculations based on module states and active threats
  const activeIncidents = incidents.filter(i => i?.status !== 'closed');
  const criticalActive = activeIncidents.filter(i => i?.severity === 'critical').length;
  const highActive = activeIncidents.filter(i => i?.severity === 'high').length;
  const mediumActive = activeIncidents.filter(i => i?.severity === 'medium').length;

  // Deduct 6 points for each disabled core module
  const coreModules = ['firewall', 'waf', 'ids_ips', 'malware_av', 'dlp', 'dns_security'];
  let moduleDeductions = 0;
  if (modulesState) {
    coreModules.forEach(mod => {
      if (modulesState[mod] === false || modulesState[mod] === null || modulesState[mod] === undefined) {
        moduleDeductions += 6;
      }
    });
  }

  // Deduct points for active incidents
  const incidentDeductions = (criticalActive * 12) + (highActive * 7) + (mediumActive * 3);

  // Deduct points for raw volume of recent critical/high alerts
  const rawAlertDeductions = Math.min(10, Math.ceil(idsAlerts.filter(a => a?.severity === 'critical' || a?.severity === 'high').length / 5));

  const scoreDeductions = moduleDeductions + incidentDeductions + rawAlertDeductions;
  const securityScore = Math.max(10, 100 - scoreDeductions);

  // Helper to compute module maturity based on enabled state and real event counts
  const getModuleMaturity = (moduleKey, baseline) => {
    if (!modulesState || !modulesState[moduleKey]) return 20; // disabled
    const count = statsData?.[moduleKey]?.event_count || 0;
    return Math.min(98, baseline + Math.min(10, Math.ceil(count / 20)));
  };

  // Re-build module radar data based on actual backend configurations and event logs
  const radarData = [
    { subject: 'جدار الحماية', A: getModuleMaturity('firewall', 88) },
    { subject: 'WAF', A: getModuleMaturity('waf', 85) },
    { subject: 'IDS/IPS', A: getModuleMaturity('ids_ips', 85) },
    { subject: 'مكافحة البرمجيات', A: getModuleMaturity('malware_av', 86) },
    { subject: 'VPN', A: getModuleMaturity('vpn', 90) },
    { subject: 'DLP', A: getModuleMaturity('dlp', 82) },
    { subject: 'أمان DNS', A: getModuleMaturity('dns_security', 80) },
    { subject: 'SSL', A: getModuleMaturity('ssl_inspection', 80) },
  ];

  // Modules score breakdown for the Risk Gauge
  const scoreBreakdown = [
    { label: 'الجدار الناري', v: getModuleMaturity('firewall', 88) },
    { label: 'WAF (GNN)', v: getModuleMaturity('waf', 85) },
    { label: 'IDS/IPS (Phantom)', v: getModuleMaturity('ids_ips', 85) },
    { label: 'DLP (منع التسريب)', v: getModuleMaturity('dlp', 82) },
  ];

  const threatTrend = threatTrendData || [];

  // Calculate dynamic KPIs
  const blockRate = idsAlerts.length > 0 
    ? Math.round(((idsAlerts.length - activeIncidents.length) / idsAlerts.length) * 100) 
    : 99.4;

  // Compute dynamic trends
  const now = new Date();
  const past24h = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  const past48h = new Date(now.getTime() - 48 * 60 * 60 * 1000);
  
  // Incidents Trend
  const getIncDate = (i) => new Date(i.timestamp || i.ts || Date.now());
  const incidentsLast24h = incidents.filter(i => getIncDate(i) > past24h).length;
  const incidentsPrev24h = incidents.filter(i => getIncDate(i) > past48h && getIncDate(i) <= past24h).length;
  const incidentTrend = incidentsPrev24h > 0 
    ? Math.round(((incidentsLast24h - incidentsPrev24h) / incidentsPrev24h) * 100)
    : incidentsLast24h > 0 ? +100 : 0;

  // Threat Block Rate Trend
  const half = Math.floor(idsAlerts.length / 2);
  const blockRateRecent = half > 0
    ? ((idsAlerts.slice(0, half).length - activeIncidents.filter(i => getIncDate(i) > new Date(Date.now() - 12 * 60 * 60 * 1000)).length) / half) * 100
    : 99.4;
  const blockRateOlder = half > 0
    ? ((idsAlerts.slice(half).length - activeIncidents.filter(i => getIncDate(i) <= new Date(Date.now() - 12 * 60 * 60 * 1000)).length) / half) * 100
    : 99.2;
  const rawBlockTrend = blockRateRecent - blockRateOlder;
  const blockRateTrend = Math.round(Math.min(5, Math.max(-5, rawBlockTrend)) * 10) / 10 || 0.1;

  // Real connection packets trend calculated from trafficHistory
  const latestReqs = (trafficHistory || []).slice(-5).reduce((acc, h) => acc + (h.reqs || 0), 0);
  const olderReqs = (trafficHistory || []).slice(-10, -5).reduce((acc, h) => acc + (h.reqs || 0), 0);
  const connectionTrend = olderReqs > 0
    ? Math.round(((latestReqs - olderReqs) / olderReqs) * 100)
    : latestReqs > 0 ? +100 : 0;

  // Real Malware scans incident trend
  const malwareLast24h = incidents.filter(i => i.module === 'malware_av' && getIncDate(i) > past24h).length;
  const malwarePrev24h = incidents.filter(i => i.module === 'malware_av' && getIncDate(i) > past48h && getIncDate(i) <= past24h).length;
  const malwareTrend = malwarePrev24h > 0
    ? Math.round(((malwareLast24h - malwarePrev24h) / malwarePrev24h) * 100)
    : malwareLast24h > 0 ? +100 : 0;

  return {
    isLoading,
    incidentsError,
    refetchIncidents,
    refetchAll,
    uptimeSeconds,
    uptimeStr,
    activeIncidents,
    securityScore,
    scoreBreakdown,
    radarData,
    threatTrend,
    blockRate,
    incidentTrend,
    connectionTrend,
    blockRateTrend,
    malwareTrend,
    sysData,
    malwareStats,
    incidents,
  };
}

export default useExecutive;
