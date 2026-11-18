/**
 * PKI & Certificate Management API Service
 * Endpoint layer for X.509 certificate lifecycle operations and CA management.
 */
import api from '../../../services/apiClient';

export const pkiApi = {
  // Discover and list all X.509 certificates
  list: () => api.get('/api/v1/certificates'),

  // Get Root CA metadata
  caInfo: () => api.get('/api/v1/certificates/ca/info'),

  // Generate a new Root CA
  generateCa: () => api.post('/api/v1/certificates/ca/generate'),

  // Download CA certificate blob (pem, der, p12)
  downloadCa: (format = 'pem') =>
    api.get(`/api/v1/certificates/ca/download?format=${format}`, { responseType: 'blob' }),

  // Generate a device/client certificate
  generateDevice: (data) => api.post('/api/v1/certificates/generate', data),

  // Revoke (delete) a certificate by ID (filename stem)
  revoke: (id) => api.delete(`/api/v1/certificates/${id}`),

  // Renew an existing certificate
  renew: (id) => api.post(`/api/v1/certificates/${id}/renew`),
  // Alias methods for CA operations
  info: () => api.get('/api/v1/certificates/ca/info'),
  generate: () => api.post('/api/v1/certificates/ca/generate'),
  download: (format = 'pem') =>
    api.get(`/api/v1/certificates/ca/download?format=${format}`, { responseType: 'blob' }),
};

// Alias for backward compatibility
export const certificatesApi = pkiApi;
export default pkiApi;

