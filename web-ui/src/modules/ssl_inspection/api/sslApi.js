/**
 * SSL Inspection Module API endpoints
 */
import api from '../../../services/apiClient';

export const sslApi = {
  status: () => api.get('/api/v1/ssl-inspection/status'),
  config: () => api.get('/api/v1/ssl-inspection/config'),
  updateConfig: (d) => api.put('/api/v1/ssl-inspection/config', d),
  policies: () => api.get('/api/v1/ssl-inspection/policies'),
  createPolicy: (d) => api.post('/api/v1/ssl-inspection/policies', d),
  updatePolicy: (id, d) => api.put(`/api/v1/ssl-inspection/policies/${id}`, d),
  deletePolicy: (id) => api.delete(`/api/v1/ssl-inspection/policies/${id}`),
  certificates: () => api.get('/api/v1/ssl-inspection/certificates'),
  uploadCert: (d) => api.post('/api/v1/ssl-inspection/certificates/upload', d),
  statistics: () => api.get('/api/v1/ssl-inspection/statistics'),
  logs: (params = {}) => api.get('/api/v1/ssl-inspection/logs', { params }),
};

export default sslApi;
