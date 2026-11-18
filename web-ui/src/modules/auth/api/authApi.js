import api, { BASE_URL } from '../../../services/apiClient';

/**
 * Dedicated Enterprise Auth Module API Service
 */
export const authApi = {
  /** Authenticate user with username and password */
  login: (credentials) => api.post('/api/v1/auth/login', credentials),

  /** Refresh JWT access token */
  refresh: () => api.post('/api/v1/auth/refresh'),

  /** Revoke token / logout */
  logout: () => api.post('/api/v1/auth/logout'),

  /** Retrieve currently logged in user profile */
  me: () => api.get('/api/v1/auth/me'),

  /** Fetch live public security telemetry and engine metrics */
  getSecurityStatus: () => api.get('/api/v1/auth/security-status'),

  /** Verify MFA 2FA verification code */
  verifyMfa: (data) => api.post('/api/v1/auth/mfa/verify', data),

  /** Self-service password reset request */
  requestPasswordReset: (data) => api.post('/api/v1/auth/password-reset', data),

  /** Fetch active user sessions */
  getSessions: () => api.get('/api/v1/auth/sessions'),
};

export default authApi;
