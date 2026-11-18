/**
 * DNS Security Module API endpoints
 */
import api from '../../../services/apiClient';

export const dnsApi = {
  status: () => api.get('/api/v1/dns_security/status'),
  getConfig: () => api.get('/api/v1/dns_security/config'),
  updateConfig: (d) => api.put('/api/v1/dns_security/config', d),
  stats: () => api.get('/api/v1/dns_security/stats'),
  rules: () => api.get('/api/v1/dns_security/rules'),
  createRule: (d) => api.post('/api/v1/dns_security/rules', d),
  updateRule: (id, d) => api.put(`/api/v1/dns_security/rules/${id}`, d),
  deleteRule: (id) => api.delete(`/api/v1/dns_security/rules/${id}`),
  listDartAlerts: (params) => api.get('/api/v1/dns_security/dart_alerts', { params }),
  reviewDartAlert: (id) => api.put(`/api/v1/dns_security/dart_alerts/${id}/review`),
  flagDartFalsePositive: (id) => api.put(`/api/v1/dns_security/dart_alerts/${id}/false_positive`),
  listSteeringRules: () => api.get('/api/v1/dns_security/steering'),
  createSteeringRule: (d) => api.post('/api/v1/dns_security/steering', d),
  deleteSteeringRule: (name) => api.delete(`/api/v1/dns_security/steering/${encodeURIComponent(name)}`),
  refreshThreatIntel: () => api.post('/api/v1/dns_security/intel/refresh'),
  getQueries: (params) => api.get('/api/v1/dns_security/queries', { params }),
  clearQueries: () => api.post('/api/v1/dns_security/queries/clear'),
};

export default dnsApi;

