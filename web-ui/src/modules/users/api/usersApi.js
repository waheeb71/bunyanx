/**
 * Users & RBAC Module API client
 */
import api from '../../../services/apiClient';

export const usersApi = {
  list: () => api.get('/api/v1/users/'),
  create: (data) => api.post('/api/v1/users/', data),
  delete: (name) => api.delete(`/api/v1/users/${name}`),
  rules: (name) => api.get(`/api/v1/users/${name}/rules`),
  addRule: (name, data) => api.post(`/api/v1/users/${name}/rules`, data),
  deleteRule: (name, id) => api.delete(`/api/v1/users/${name}/rules/${id}`),
};

export default usersApi;
