import api from '../../../services/apiClient';

export const httpApi = {
  status: () => api.get('/api/v1/http_inspection/status'),
  config: () => api.get('/api/v1/http_inspection/config'),
  updateConfig: (d) => api.put('/api/v1/http_inspection/config', d),
  patterns: () => api.get('/api/v1/http_inspection/patterns'),
  addPattern: (d) => api.post('/api/v1/http_inspection/patterns', d),
  updatePattern: (id, d) => api.put(`/api/v1/http_inspection/patterns/${id}`, d),
  deletePattern: (id) => api.delete(`/api/v1/http_inspection/patterns/${id}`),
  logs: () => api.get('/api/v1/http_inspection/logs'),
};
