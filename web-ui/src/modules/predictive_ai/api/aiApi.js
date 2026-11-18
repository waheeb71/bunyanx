/**
 * Predictive AI Module API endpoints
 */
import api from '../../../services/apiClient';

export const aiApi = {
  config: () => api.get('/api/v1/ai/config'),
  updateConfig: (d) => api.put('/api/v1/ai/config', d),
  models: () => api.get('/api/v1/ai/models'),
  uploadModel: (id, f) => {
    const fd = new FormData();
    fd.append('file', f);
    return api.post(`/api/v1/ai/models/upload/${id}`, fd, { headers: { 'Content-Type': 'multipart/form-data' } });
  },
  // Kill-chain graph
  killchainGraph: () => api.get('/api/v1/ai/killchain/graph'),
  killchainStats: () => api.get('/api/v1/ai/killchain/stats'),
  // Intent prediction
  activeIntents: () => api.get('/api/v1/ai/intent/active'),
  ipIntent: (ip) => api.get(`/api/v1/ai/intent/${ip}`),
  // RL Safety
  safetyBudget: () => api.get('/api/v1/ai/safety/budget'),
  safetyAudit: (n = 20) => api.get(`/api/v1/ai/safety/audit?n=${n}`),
  // AEGIS core
  AEGISHealth: () => api.get('/api/v1/ai/AEGIS/health'),
  AEGISDecisions: (limit = 20) => api.get(`/api/v1/ai/AEGIS/decisions?limit=${limit}`),
  AEGISBeliefIp: (ip) => api.get(`/api/v1/ai/AEGIS/belief/${ip}`),
  AEGISIntentIp: (ip) => api.get(`/api/v1/ai/AEGIS/intent/${ip}`),
  AEGISActiveDecoys: () => api.get('/api/v1/ai/AEGIS/deception/active'),
  // AEGIS UEBA
  uebaMetrics: () => api.get('/api/v1/ai/AEGIS/ueba/metrics'),
  uebaBaseline: (ip) => api.get(`/api/v1/ai/AEGIS/ueba/baseline/${ip}`),
  // AEGIS attacker management
  resetAttacker: (ip) => api.post(`/api/v1/ai/AEGIS/attacker/reset/${ip}`),
  recordFeedback: (d) => api.post('/api/v1/ai/AEGIS/feedback', d),
  recordDecoyInteraction: (d) => api.post('/api/v1/ai/AEGIS/deception/interact', d),
  // GNN
  gnnStatus: () => api.get('/api/v1/ai/AEGIS/gnn/status'),
  // TPE
  threatAssessment: (d) => api.post('/api/v1/ai/threat-assessment', d),
  threatAssessmentSectors: () => api.get('/api/v1/ai/threat-assessment/sectors'),
  tpeLastReport: () => api.get('/api/v1/ai/tpe/last-report'),
  // DB history logs
  logsDecisions: (limit = 50) => api.get(`/api/v1/ai/logs/decisions?limit=${limit}`),
  logsIntent: (limit = 50, ip = null) => api.get(`/api/v1/ai/logs/intent?limit=${limit}${ip ? `&src_ip=${ip}` : ''}`),
  logsRlSafety: (limit = 50) => api.get(`/api/v1/ai/logs/rl-safety?limit=${limit}`),
  logsDecoy: (limit = 50) => api.get(`/api/v1/ai/logs/decoy?limit=${limit}`),
};

export default aiApi;
