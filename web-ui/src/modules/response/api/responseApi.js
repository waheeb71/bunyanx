/**
 * Response Center Module API endpoints
 */
import api from '../../../services/apiClient';

export const responseApi = {
  blocks: () => api.get('/api/v1/response/blocks'),
  unblock: (ip) => api.delete(`/api/v1/response/blocks/${encodeURIComponent(ip)}`),
  incidents: (limit = 100) => api.get('/api/v1/response/incidents', { params: { limit } }),
  incidentDetail: (id) => api.get(`/api/v1/response/incidents/${id}`),
  updateStatus: (id, status) => api.put(`/api/v1/response/incidents/${id}/status`, { status }),
  triggerAction: (id, action, label) => {
    let payload = {};
    if (typeof action === 'object' && action !== null) {
      payload = { ...action };
      if (!payload.label) payload.label = payload.action || 'Mitigate';
    } else {
      payload = { action, label: label || action };
    }
    return api.post(`/api/v1/response/incidents/${id}/action`, payload);
  },
  // Policy & TTL
  policyEngines: () => api.get('/api/v1/policy/engines').catch(() => ({ data: { engines: [] } })),
  ttlEntries: () => api.get('/api/v1/policy/ttl/entries').catch(() => ({ data: { entries: {} } })),
  addTtlEntry: (data) => api.post('/api/v1/policy/ttl/entry', data),
  removeTtlEntry: (action, target) => api.delete('/api/v1/policy/ttl/entry', { data: { action, target } }),
};

export default responseApi;
