import api from '../../../services/apiClient';

export const proxyApi = {
  status: () => api.get('/api/v1/proxy/status'),
  config: () => api.get('/api/v1/proxy/config'),
  updateConfig: (data) => api.put('/api/v1/proxy/config', data),
  stats: () => api.get('/api/v1/proxy/stats'),
  sessions: () => api.get('/api/v1/proxy/sessions'),
  vips: () => api.get('/api/v1/proxy/vips'),
  addVip: (data) => api.post('/api/v1/proxy/vips', data),
  deleteVip: (name) => api.delete(`/api/v1/proxy/vips/${name}`),
  getPacUrl: () => '/api/v1/proxy/proxy.pac',
  getWpadUrl: () => '/api/v1/proxy/wpad.dat',
};
