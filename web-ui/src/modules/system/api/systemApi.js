/**
 * Enterprise bunyanx — System Module API Service Layer
 * Centralized client for system status, health, interfaces, updates, and configuration versioning.
 */
import api from '../../../services/apiClient';

export const systemApi = {
  // System Status & Health
  getStatus: () => api.get('/api/v1/status'),
  getHealth: () => api.get('/health'),
  getHealthDetailed: () => api.get('/api/v1/system/health/detailed'),
  getModules: () => api.get('/api/v1/config/modules'),
  getModuleStats: () => api.get('/api/v1/config/modules/stats'),
  toggleModule: (name, enabled) => api.put(`/api/v1/modules/${name}/toggle`, { enabled }),

  // OTA Updates
  checkUpdate: () => api.get('/api/v1/system/update/check'),
  applyUpdate: (data) => api.post('/api/v1/system/update/apply', data),
  getUpdateHistory: (lines = 50) => api.get(`/api/v1/system/update/history?lines=${lines}`),

  // High Availability
  getHaStatus: () => api.get('/api/v1/ha/status'),
  syncHa: () => api.post('/api/v1/ha/sync'),

  // Networking Interfaces
  getInterfaces: () => api.get('/api/v1/system/networking/interfaces'),
  assignInterfaces: (assignments) => api.put('/api/v1/system/networking/interfaces', assignments),
  confirmInterfaces: () => api.post('/api/v1/system/networking/interfaces/confirm'),
  getNetworkingStatus: () => api.get('/api/v1/system/networking/status'),

  // Security Diagnostics
  getSecurityValidation: () => api.get('/api/v1/security/validation'),
  getSecurityWarnings: () => api.get('/api/v1/security/warnings'),

  // Configuration Snapshots & Versions
  getConfigVersions: () => api.get('/api/v1/config/versions'),
  getConfigDiff: (v1, v2) => api.get('/api/v1/config/diff', { params: { v1, v2 } }),
  rollbackConfig: (version) => api.post(`/api/v1/config/rollback?version=${version}`),
  takeConfigSnapshot: () => api.post('/api/v1/config/snapshot'),
};

export default systemApi;
