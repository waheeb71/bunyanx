import api from '../../../services/apiClient';

export const wafApi = {
  status: () => api.get('/api/v1/waf/status'),
  events: (params) => api.get('/api/v1/waf/events', { params }),
  simulateAttack: (attackType) => api.post('/api/v1/waf/demo/simulate_attack', null, { params: { attack_type: attackType } }),
  gnnStatus: () => api.get('/api/v1/waf/gnn/status'),
  gnnLogs: () => api.get('/api/v1/waf/gnn/logs'),
  flushLogs: () => api.post('/api/v1/waf/gnn/logs/flush'),
  startTraining: (data) => api.post('/api/v1/waf/gnn/train', data),
  trainingStatus: () => api.get('/api/v1/waf/gnn/train/status'),
  activateModel: (data) => api.put('/api/v1/waf/gnn/activate', data),
  toggleGnn: (enabled) => api.put('/api/v1/waf/gnn/toggle', { enabled }),

  // WAAP Controls
  toggleWaapFeature: (feature, enabled) => api.put(`/api/v1/waf/waap/toggle/${feature}`, { enabled }),
  updateRateLimit: (data) => api.put('/api/v1/waf/waap/rate_limiter/config', data),

  // Shadow Autopilot
  startShadowMode: (hours) => api.post('/api/v1/waf/waap/shadow_mode/start', { hours }),
  stopShadowMode: () => api.post('/api/v1/waf/waap/shadow_mode/stop'),
  shadowModeStatus: () => api.get('/api/v1/waf/waap/shadow_mode/status'),
  exportShadowSchema: () => api.get('/api/v1/waf/waap/shadow_mode/export'),

  // Settings & Configuration
  settings: () => api.get('/api/v1/waf/settings'),
  reloadSettings: () => api.post('/api/v1/waf/settings/reload'),
  setWafMode: (mode) => api.put('/api/v1/waf/settings/mode', { mode }),
  setWafMaster: (enabled) => api.put('/api/v1/waf/settings/master', { enabled }),
  
  // Model Configurations
  toggleModel: (model, enabled) => api.put(`/api/v1/waf/models/${model}/toggle`, { enabled }),
  configModel: (model, data) => api.put(`/api/v1/waf/models/${model}/config`, data),
  configBot: (data) => api.put('/api/v1/waf/bot/config', data),
  
  // Rules and Defenses
  updateRiskThresholds: (data) => api.put('/api/v1/waf/risk_thresholds', data),
  configThreatIntel: (data) => api.put('/api/v1/waf/threat_intel/config', data),
  configHoneypot: (data) => api.put('/api/v1/waf/honeypot/config', data),
  configDeception: (data) => api.put('/api/v1/waf/deception/config', data),
  configPerformance: (data) => api.put('/api/v1/waf/performance/config', data),
  configAto: (data) => api.put('/api/v1/waf/ato/config', data),
  configGraphql: (data) => api.put('/api/v1/waf/graphql/config', data),
  configPreprocessing: (data) => api.put('/api/v1/waf/preprocessing/config', data),
  configDynamicAmplifiers: (data) => api.put('/api/v1/waf/dynamic_amplifiers/config', data),
  
  // IP Access Lists & Session Management
  updateWhitelist: (ips, cidrs) => api.put('/api/v1/waf/ip/whitelist', { ips, cidrs }),
  addWhitelist: (ips, cidrs) => api.post('/api/v1/waf/ip/whitelist/add', { ips, cidrs }),
  updateBlacklist: (ips, cidrs) => api.put('/api/v1/waf/ip/blacklist', { ips, cidrs }),
  addBlacklist: (ips, cidrs) => api.post('/api/v1/waf/ip/blacklist/add', { ips, cidrs }),
  clearIpSession: (ip) => api.post('/api/v1/waf/ip/session/clear', null, { params: { ip } }),

  // API Schema Upload
  uploadApiSchema: (endpoint, schema) => api.post('/api/v1/waf/waap/api_schema/upload', { endpoint, schema_definition: schema }),

  // Intelligence & Explainer
  configSelfLearning: (data) => api.put('/api/v1/waf/self_learning/config', data),
  configLogging: (data) => api.put('/api/v1/waf/logging/config', data),
  configXai: (data) => api.put('/api/v1/waf/xai_explainer/config', data),
};
