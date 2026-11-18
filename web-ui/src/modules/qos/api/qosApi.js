import api from '../../../services/apiClient';

export const qosApi = {
  status: () => api.get('/api/v1/qos/status'),
  config: () => api.get('/api/v1/qos/config'),
  updateConfig: (d) => api.put('/api/v1/qos/config', d),
  stats: () => api.get('/api/v1/qos/stats'),
  resetBucket: (ip) => api.delete(`/api/v1/qos/buckets/${ip}`),
};
