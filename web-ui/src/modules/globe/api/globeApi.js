import api from '../../../services/apiClient';

export const globeApi = {
  // Primary Globe endpoints
  threats: (params) => api.get('/api/v1/globe/threats/live', { params }),
  stats: (params) => api.get('/api/v1/globe/stats', { params }),

  // Backup / Fallback endpoints from Dashboard API
  location: (params) => api.get('/api/v1/dashboard/location', { params }),
  mapStats: (params) => api.get('/api/v1/dashboard/map_stats', { params }),
  severityBreakdown: (params) => api.get('/api/v1/dashboard/severity_breakdown', { params }),
  alertsTrend24h: (params) => api.get('/api/v1/dashboard/alerts_trend_24h', { params }),
  topServices: (params) => api.get('/api/v1/dashboard/top_services', { params }),
};

export default globeApi;
