/**
 * bunyanx Voice Alert Service (CVAS) Frontend API Service Client
 * All endpoint paths match /api/v1/cvas/* (see api/routers/v1/cvas.py)
 *
 * FIX: removed duplicate export — was exported both as named and default.
 * Now exported as default only; consumers use `import cvasApi from './api/cvasApi'`.
 */
import api from '../../../services/apiClient';

// Exported as BOTH named and default to support:
//   import cvasApi from './api/cvasApi'          ← CVASManager.jsx
//   import { cvasApi } from '...cvasApi.js'      ← central api.js aggregator
export const cvasApi = {
  status: () => api.get('/api/v1/cvas/status'),
  health: () => api.get('/api/v1/cvas/health'),
  statistics: () => api.get('/api/v1/cvas/statistics'),
  voices: () => api.get('/api/v1/cvas/voices'),
  languages: () => api.get('/api/v1/cvas/languages'),
  events: () => api.get('/api/v1/cvas/events'),
  history: (limit = 100) => api.get(`/api/v1/cvas/history?limit=${limit}`),
  clearHistory: () => api.delete('/api/v1/cvas/history'),
  config: () => api.get('/api/v1/cvas/configuration'),
  updateConfig: (data) => api.put('/api/v1/cvas/configuration', data),
  test: (topic = 'malware.detected') => api.post(`/api/v1/cvas/test?topic=${encodeURIComponent(topic)}`),
  speak: (data) => api.post('/api/v1/cvas/speak', data),
  reload: () => api.post('/api/v1/cvas/reload'),
  clearQueue: () => api.post('/api/v1/cvas/clear_queue'),
  preview: (data) => api.post('/api/v1/cvas/preview', data),
  enable: () => api.post('/api/v1/cvas/enable'),
  disable: () => api.post('/api/v1/cvas/disable'),
  mute: () => api.post('/api/v1/cvas/mute'),
  unmute: () => api.post('/api/v1/cvas/unmute'),
  reset: () => api.post('/api/v1/cvas/reset'),
  // Alert tones (NativePlayer MP3) — independent from TTS speech
  tonesStatus: () => api.get('/api/v1/cvas/tones/status'),
  enableTones: () => api.post('/api/v1/cvas/tones/enable'),
  disableTones: () => api.post('/api/v1/cvas/tones/disable'),
};

export default cvasApi;
