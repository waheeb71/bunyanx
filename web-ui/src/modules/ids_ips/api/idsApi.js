/**
 * IDS/IPS Module API endpoints
 */
import api from '../../../services/apiClient';

export const idsApi = {
  status: () => api.get('/api/v1/ids_ips/status'),
  alerts: (offset = 0, limit = 100, hours = 24) => api.get('/api/v1/ids_ips/alerts', { params: { offset, limit, hours } }),
  rules: () => api.get('/api/v1/ids_ips/signatures'),
  createRule: (d) => api.post('/api/v1/ids_ips/signatures', d),
  deleteRule: (id) => api.delete(`/api/v1/ids_ips/signatures/${id}`),
  getConfig: () => api.get('/api/v1/ids_ips/config'),
  updateConfig: (d) => api.put('/api/v1/ids_ips/config', d),
  phantomStatus: () => api.get('/api/v1/ids_ips/phantom/status'),
  phantomDrift: () => api.get('/api/v1/ids_ips/phantom/drift'),
  deceptionTraps: () => api.get('/api/v1/ids_ips/deception/traps'),
  feedback: (sampleId, trueLabel, isCorrect) => api.post('/api/v1/ids_ips/phantom/feedback', { sample_id: sampleId, true_label: trueLabel, is_correct: isCorrect }),
};

export default idsApi;
