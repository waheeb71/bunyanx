/**
 * VPN Module API endpoints
 */
import api from '../../../services/apiClient';

export const vpnApi = {
  status: () => api.get('/api/v1/vpn/status'),
  config: () => api.get('/api/v1/vpn/config'),
  updateConfig: (d) => api.put('/api/v1/vpn/config', d),
  start: () => api.post('/api/v1/vpn/start'),
  stop: () => api.post('/api/v1/vpn/stop'),
  peers: () => api.get('/api/v1/vpn/peers'),
  addPeer: (d) => api.post('/api/v1/vpn/peers', d),
  removePeer: (k) => api.delete(`/api/v1/vpn/peers/${encodeURIComponent(k)}`),
  generateKeys: () => api.post('/api/v1/vpn/keys/generate'),
  sessions: () => api.get('/api/v1/vpn/sessions'),
  sessionSummary: () => api.get('/api/v1/vpn/sessions/summary'),
  terminateSession: (id) => api.delete(`/api/v1/vpn/sessions/${id}`),
  portalLogin: (data) => api.post('/api/v1/vpn/portal/login', data),
  logs: () => api.get('/api/v1/vpn/logs'),
  diagnostics: () => api.get('/api/v1/vpn/diagnostics')
};

export default vpnApi;

