import api from '../../../services/apiClient';

export const webFilterApi = {
  status: () => api.get('/api/v1/web_filter/status'),
  config: () => api.get('/api/v1/web_filter/config'),
  updateConfig: (d) => api.put('/api/v1/web_filter/config', d),
  categories: () => api.get('/api/v1/web_filter/categories'),
  addCategory: (d) => api.post('/api/v1/web_filter/categories', d),
  updateCategory: (id, d) => api.put(`/api/v1/web_filter/categories/${id}`, d),
  deleteCategory: (id) => api.delete(`/api/v1/web_filter/categories/${id}`),
  domains: () => api.get('/api/v1/web_filter/domains'),
  addDomain: (d) => api.post('/api/v1/web_filter/domains', d),
  updateDomain: (id, d) => api.put(`/api/v1/web_filter/domains/${id}`, d),
  deleteDomain: (id) => api.delete(`/api/v1/web_filter/domains/${id}`),
  train: () => api.post('/api/v1/web_filter/train'),
};
