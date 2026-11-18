/**
 * API Service Layer
 * Single source of truth for all backend communication.
 * Refactored to import the base client from apiClient.js.
 * Decentralized module APIs are imported and re-exported.
 */
import api, { BASE_URL } from './apiClient';

export { default, default as api, BASE_URL } from './apiClient';

// Decentralized Module APIs re-exported for backward compatibility
export { aiApi } from '../modules/predictive_ai/api/aiApi';
export { firewallApi, optimizerApi } from '../modules/firewall/api/firewallApi';
export { responseApi } from '../modules/response/api/responseApi';
export { ubaApi } from '../modules/uba/api/ubaApi';
export { idsApi } from '../modules/ids_ips/api/idsApi';
export { vpnApi } from '../modules/vpn/api/vpnApi';
export { sslApi } from '../modules/ssl_inspection/api/sslApi';
export { dnsApi } from '../modules/dns_security/api/dnsApi';
export { malwareApi } from '../modules/malware_av/api/malwareApi';
export { dashboardApi, logManagerApi, threatIntelApi } from '../modules/dashboard/api/dashboardApi';
export { webFilterApi } from '../modules/web_filter/api/webFilterApi';
export { qosApi } from '../modules/qos/api/qosApi';
export { wafApi } from '../modules/waf/api/wafApi';
export { httpApi } from '../modules/http_inspection/api/httpApi';
export { netopsApi } from '../modules/netops/api/netopsApi';
export { proxyApi } from '../modules/proxy/api/proxyApi';
export { emailApi } from '../modules/email_security/api/emailApi';
export { executiveApi } from '../modules/executive/api/executiveApi';
export { globeApi } from '../modules/globe/api/globeApi';
export { pkiApi, certificatesApi } from '../modules/pki/api/pkiApi';
export { cvasApi } from '../modules/cvas/api/cvasApi';

export { authApi } from '../modules/auth/api/authApi';

/* ── System ────────────────────────────────────────── */
export const systemApi = {
  status: () => api.get('/api/v1/status'),
  health: () => api.get('/health'),
  healthDetailed: () => api.get('/api/v1/health/detailed'),
  config: (file = 'base.yaml') => api.get(`/api/v1/config?file=${file}`),
  modules: () => api.get('/api/v1/config/modules'),
  moduleStats: () => api.get('/api/v1/config/modules/stats'),
  updateConfig: (data, file = 'base.yaml') => api.put(`/api/v1/config?file=${file}`, data),
  resetConfig: (file = 'base.yaml') => api.post(`/api/v1/config/reset?file=${file}`),
  toggleModule: (name, enabled) =>
    api.put(`/api/v1/modules/${name}/toggle`, { enabled }),
  checkUpdate: () => api.get('/api/v1/system/update/check'),
  applyUpdate: (data) => api.post('/api/v1/system/update/apply', data),
  auditLogs: () => api.get('/api/v1/system/audit/logs'),
};

/* ── Users & RBAC ──────────────────────────────────── */
export const usersApi = {
  list: () => api.get('/api/v1/users/'),
  create: (data) => api.post('/api/v1/users/', data),
  delete: (name) => api.delete(`/api/v1/users/${name}`),
  rules: (name) => api.get(`/api/v1/users/${name}/rules`),
  addRule: (name, data) => api.post(`/api/v1/users/${name}/rules`, data),
  deleteRule: (name, id) => api.delete(`/api/v1/users/${name}/rules/${id}`),
};







/* ── DLP (Data Loss) ───────────────────────────────── */
export { dlpApi } from '../modules/dlp/dlpApi';




/* ── System Core Relocated APIs ────────────────────── */
export const mlCoreApi = {
  config: () => api.get('/api/v1/ml-core/config'),
  updateConfig: (d) => api.put('/api/v1/ml-core/config', d),
};

export const haApi = {
  status: () => api.get('/api/v1/ha/status'),
  sync: () => api.post('/api/v1/ha/sync'),
};

export const interfacesApi = {
  list: () => api.get('/api/v1/system/networking/interfaces'),
  assign: (d) => api.put('/api/v1/system/networking/interfaces', d),
  confirm: () => api.post('/api/v1/system/networking/interfaces/confirm'),
  status: () => api.get('/api/v1/system/networking/status'),
};


/* ── Phase 8: Enterprise Control Plane ─────────────── */
export const enterpriseApi = {
  healthDetailed: () => api.get('/api/v1/system/health/detailed'),
  configVersions: () => api.get('/api/v1/config/versions'),
  configDiff: (v1, v2) => api.get('/api/v1/config/diff', { params: { v1, v2 } }),
  configRollback: (version) => api.post(`/api/v1/config/rollback?version=${version}`),
};

export const siemApi = {
  status: () => api.get('/api/v1/siem/status'),
  test: () => api.post('/api/v1/siem/test'),
};

export const securityApi = {
  validation: () => api.get('/api/v1/security/validation'),
  warnings: () => api.get('/api/v1/security/warnings'),
};
