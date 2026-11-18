import api from '../../../services/apiClient';

export const netopsApi = {
  sockets: () => api.get('/api/v1/netops/sockets'),
  connections: () => api.get('/api/v1/netops/connections'),
  ports: () => api.get('/api/v1/netops/ports'),
  modules: () => api.get('/api/v1/netops/modules'),
  eventbus: () => api.get('/api/v1/netops/eventbus'),
  websockets: () => api.get('/api/v1/netops/websockets'),
};
