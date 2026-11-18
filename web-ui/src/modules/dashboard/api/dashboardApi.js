/**
 * Dashboard Module API endpoints
 * Complete integration for SIEM Live Monitor, Events Analysis, Raw Logs, Visitor Tracker & Threat Intel
 */
import api from '../../../services/apiClient';

export const dashboardApi = {
  // Live SIEM Globe & Threat Maps
  globeThreats: (params) => api.get('/api/v1/globe/threats/live', { params }),
  globeStats: (params) => api.get('/api/v1/globe/stats', { params }),
  threatTrend: (params) => api.get('/api/v1/executive/trend', { params }),
  trafficHistory: (params) => api.get('/api/v1/stats/traffic/history', { params }),
  location: (params) => api.get('/api/v1/dashboard/location', { params }),

  // Executive KPIs & Widgets
  kpi: (params) => api.get('/api/v1/dashboard/kpi', { params }),
  mapStats: (params) => api.get('/api/v1/dashboard/map_stats', { params }),
  severityBreakdown: (params) => api.get('/api/v1/dashboard/severity_breakdown', { params }),
  alertsTrend24h: (params) => api.get('/api/v1/dashboard/alerts_trend_24h', { params }),
  topServices: (params) => api.get('/api/v1/dashboard/top_services', { params }),

  // Core System Status & Audit
  systemStatus: () => api.get('/api/v1/system/status'),
  systemMetrics: () => api.get('/api/v1/system/metrics'),
  auditLogs: (params) => api.get('/api/v1/system/audit/logs', { params }),
};

export const logManagerApi = {
  // SIEM Security Events & Visitors
  searchEvents: (params) => api.get('/api/log_manager/events/search', { params }),
  visitors: (limit = 100) => api.get('/api/log_manager/visitors', { params: { limit } }),

  // Raw Log Files & Content Search
  listFiles: () => api.get('/api/log_manager/logs/files'),
  searchLogs: (params) => api.get('/api/log_manager/logs/search', { params }),
  stats: () => api.get('/api/log_manager/logs/stats'),
  clearLogs: (data) => api.post('/api/log_manager/logs/clear', data),

  // Log Manager Configuration
  getConfig: () => api.get('/api/log_manager/config'),
  updateConfig: (data) => api.put('/api/log_manager/config', data),
  streamLogsUrl: () => '/api/log_manager/logs/stream',
};

export const threatIntelApi = {
  gnnStatus: () => api.get('/api/v1/waf/gnn/status'),
  idsAlerts: (params) => api.get('/api/v1/ids_ips/alerts', { params }),
  malwareStatus: () => api.get('/api/v1/malware_av/status'),
  dnsThreats: () => api.get('/api/v1/dns/threats'),
  stats: () => api.get('/api/v1/threat-intel/stats'),
  lookup: (ip) => api.get(`/api/v1/threat-intel/lookup/${encodeURIComponent(ip)}`),
  refresh: () => api.post('/api/v1/threat-intel/refresh'),
};

export default dashboardApi;
