import api from '../../../services/apiClient';

const BASE = '/api/v1/email_security';

export const emailApi = {
  status:              ()          => api.get(`${BASE}/status`),
  config:              ()          => api.get(`${BASE}/config`),
  configSchema:        ()          => api.get(`${BASE}/config/schema`),
  updateConfig:        (d)         => api.put(`${BASE}/config`, d),
  resetConfig:         ()          => api.post(`${BASE}/config/reset`),
  stats:               ()          => api.get(`${BASE}/stats`),
  logs:                (params)    => api.get(`${BASE}/logs`, { params }),
  whitelist:           ()          => api.get(`${BASE}/whitelist`),
  addToWhitelist:      (d)         => api.post(`${BASE}/whitelist`, d),
  removeFromWhitelist: (type, val) => api.delete(`${BASE}/whitelist/${type}/${val}`),
  modelMetrics:        ()          => api.get(`${BASE}/model/metrics`),
};

