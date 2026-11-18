/**
 * Base API Client
 * Configures Axios with interceptors, authorization headers, 401 redirects,
 * and automatic retry logic for transient errors.
 */
import axios from 'axios';
import audioAlertService from './audioAlertService';

export const BASE_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

const apiClient = axios.create({
  baseURL: BASE_URL,
  headers: { 'Content-Type': 'application/json' },
  timeout: 15000, // 15s timeout
});

const MAX_RETRIES = 2;

// Automatic retry interceptor for network errors and 5xx status codes
apiClient.interceptors.response.use(undefined, async (err) => {
  const config = err.config;
  if (!config || config.__retryCount >= MAX_RETRIES) {
    // All retries exhausted — play error tone
    const status = err.response?.status;
    if (!status || status >= 400) {
      audioAlertService.playUiTone('error').catch(() => {});
    }
    return Promise.reject(err);
  }

  const isNetwork = !err.response && err.code !== 'ECONNABORTED';
  const is5xx = err.response?.status >= 500;
  if (!isNetwork && !is5xx) {
    // 4xx error (not retried) — play error tone
    audioAlertService.playUiTone('error').catch(() => {});
    return Promise.reject(err);
  }

  config.__retryCount = (config.__retryCount || 0) + 1;
  const delay = 500 * Math.pow(2, config.__retryCount - 1);
  await new Promise(r => setTimeout(r, delay));
  return apiClient(config);
});

// Attach JWT bearer token from localStorage
apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('bunyanx_token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// Handle 401 status globally by cleaning credentials and redirecting to login
apiClient.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err.response?.status === 401) {
      const isAuthPath = window.location.pathname.startsWith('/login');
      const isAuthApi = err.config?.url?.includes('/auth/login');
      if (!isAuthPath && !isAuthApi) {
        localStorage.removeItem('bunyanx_token');
        localStorage.removeItem('bunyanx_user');
        window.location.href = '/login';
      }
    }
    return Promise.reject(err);
  }
);

export default apiClient;
