/**
 * DLP API Service — Extended with BEFP + AI endpoints
 * Replaces the basic dlpApi in services/api.js
 * Import from here for all DLP-related API calls.
 */
import api from '../../services/api';

export const dlpApi = {
  // ── Core ─────────────────────────────────────────────────
  status:       ()     => api.get('/api/v1/dlp/status'),
  config:       ()     => api.get('/api/v1/dlp/config'),
  updateConfig: (d)    => api.put('/api/v1/dlp/config', d),
  audit:        ()     => api.get('/api/v1/dlp/audit'),

  // ── Custom Rules ─────────────────────────────────────────
  rules:       ()      => api.get('/api/v1/dlp/rules'),
  createRule:  (d)     => api.post('/api/v1/dlp/rules', d),
  deleteRule:  (id)    => api.delete(`/api/v1/dlp/rules/${id}`),

  // ── BEFP Behavioral Intelligence ─────────────────────────
  ipProfile:    (ip)   => api.get(`/api/v1/dlp/behavioral/profile/${ip}`),
  highRiskIps:  ()     => api.get('/api/v1/dlp/behavioral/high-risk'),
  testErs:      (d)    => api.post('/api/v1/dlp/behavioral/test-ers', d),

  // ── Self-Learning Feedback ───────────────────────────────
  submitFeedback: (d)  => api.post('/api/v1/dlp/feedback', d),
  pendingFeedback: ()  => api.get('/api/v1/dlp/feedback/pending'),
  reviewFeedback: (id, action) => api.put(`/api/v1/dlp/feedback/${id}/review`, { action }),

  // ── Diagnostics & Weight Optimization ─────────────────────
  yamlSettings:    ()     => api.get('/api/v1/dlp/config/settings'),
  msemProfile:     (ip)   => api.get(`/api/v1/dlp/behavioral/msem-profile/${ip}`),
  optimizeWeights: ()     => api.post('/api/v1/dlp/behavioral/optimize-weights'),
};

