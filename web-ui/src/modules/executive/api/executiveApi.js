import api from '../../../services/apiClient';

export const executiveApi = {
  status: () => api.get('/api/v1/status'),
  modules: () => api.get('/api/v1/config/modules'),
  incidents: () => api.get('/api/v1/response/incidents'),
  idsAlerts: (offset = 0, limit = 50) => api.get('/api/v1/ids_ips/alerts', { params: { skip: offset, limit } }),
  malwareStats: (hours = 24) => api.get('/api/v1/malware_av/stats', { params: { hours } }),
  threatTrend: () => api.get('/api/v1/executive/trend'),
  moduleStats: () => api.get('/api/v1/config/modules/stats'),
  trafficHistory: () => api.get('/api/v1/stats/traffic/history'),
};

export default executiveApi;
