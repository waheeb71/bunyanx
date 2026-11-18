/**
 * UBA Module API endpoints
 */
import api from '../../../services/apiClient';

export const ubaApi = {
  status: () => api.get('/api/v1/uba/status'),
  config: () => api.get('/api/v1/uba/config'),
  updateConfig: (d) => api.put('/api/v1/uba/config', d),
  users: (params) => api.get('/api/v1/uba/users', { params }),
  userProfile: (name) => api.get(`/api/v1/uba/users/${name}`),
  userEvents: (name, p) => api.get(`/api/v1/uba/users/${name}/events`, { params: p }),
  events: (params) => api.get('/api/v1/uba/events', { params }),
  alerts: () => api.get('/api/v1/uba/alerts'),
  resetUser: (name) => api.delete(`/api/v1/uba/users/${name}/reset`),
  demoFileAccess: (d) => api.post('/api/v1/uba/demo/file_access', d),
  demoOpenHoneytoken: (payload) => api.post('/api/v1/uba/demo/open_honeytoken', payload),
};

export default ubaApi;
