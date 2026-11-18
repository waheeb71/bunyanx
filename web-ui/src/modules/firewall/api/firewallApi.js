/**
 * Firewall Module API endpoints
 */
import api from '../../../services/apiClient';

export const firewallApi = {
  // Policy Rules CRUD
  rules: () => api.get('/api/v1/rules'),
  createRule: (d) => api.post('/api/v1/rules', d),
  updateRule: (id, d) => api.put(`/api/v1/rules/${id}`, d),
  deleteRule: (id) => api.delete(`/api/v1/rules/${id}`),

  // Policy Evaluation
  evaluatePolicy: (src_ip, dst_ip, dst_port, protocol) =>
    api.post('/api/v1/policy/evaluate', null, {
      params: { src_ip, dst_ip, dst_port, protocol }
    }),

  // IP Blocklist (kernel-level eBPF)
  blockedIps: () => api.get('/api/v1/block/ips'),
  blockIp: (ip, reason, duration_seconds) =>
    api.post(`/api/v1/block/${encodeURIComponent(ip)}`, { 
      reason: reason || 'Manual block', 
      duration_seconds: duration_seconds || null 
    }),
  unblockIp: (ip) => api.delete(`/api/v1/block/${encodeURIComponent(ip)}`),
  unblockAll: () => api.delete('/api/v1/block/all'),

  // XDP / eBPF Acceleration
  xdpStatus: () => api.get('/api/v1/acceleration/xdp/status'),
  switchXdpMode: (mode, iface) =>
    api.post('/api/v1/acceleration/xdp/mode', { mode, interface: iface || null }),

  // Administrative Config & Real-time Stats Management
  getConfig: () => api.get('/api/v1/config'),
  updateConfig: (d) => api.put('/api/v1/config', d),
  getStats: () => api.get('/api/v1/stats'),
};

export const optimizerApi = {
  analyze: () => api.get('/api/v1/optimizer/suggest'),
  applyDeletes: (ids) =>
    Promise.all(ids.map((id) => api.delete(`/api/v1/rules/${id}`))),
};

export default firewallApi;
