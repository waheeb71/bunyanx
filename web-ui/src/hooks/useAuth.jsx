/**
 * Auth Context — global login state + JWT management with auto token refresh
 */
import { createContext, useContext, useState, useCallback, useEffect, useRef } from 'react';
import { authApi } from '../services/api';
import audioAlertService from '../services/audioAlertService';

const AuthContext = createContext(null);

/* Parse JWT expiry from payload (no external dependency) */
function getTokenExpiry(token) {
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    return payload.exp * 1000; // convert seconds to ms
  } catch {
    return null;
  }
}

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    const raw = localStorage.getItem('bunyanx_user');
    return raw ? JSON.parse(raw) : null;
  });

  const refreshTimerRef = useRef(null);

  /* Schedule token refresh 2 minutes before expiry */
  const scheduleRefresh = useCallback((token) => {
    if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
    const expiry = getTokenExpiry(token);
    if (!expiry) return;

    const doRefresh = async () => {
      try {
        const { data } = await authApi.refresh();
        if (data?.access_token) {
          localStorage.setItem('bunyanx_token', data.access_token);
          scheduleRefresh(data.access_token); // reschedule for next cycle
          console.info('[Auth] Token refreshed successfully');
        }
      } catch (err) {
        console.warn('[Auth] Token refresh failed:', err);
        localStorage.removeItem('bunyanx_token');
        localStorage.removeItem('bunyanx_user');
        setUser(null);
        if (!window.location.pathname.startsWith('/login')) {
          window.location.href = '/login';
        }
      }
    };

    const msUntilRefresh = expiry - Date.now() - 2 * 60 * 1000;
    if (msUntilRefresh <= 0) {
      // Token is already expired or expiring within 2 minutes — refresh immediately!
      doRefresh();
      return;
    }

    refreshTimerRef.current = setTimeout(doRefresh, msUntilRefresh);
  }, []);

  /* On mount: schedule refresh if token exists */
  useEffect(() => {
    const token = localStorage.getItem('bunyanx_token');
    if (token && user) scheduleRefresh(token);
    return () => {
      if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
    };
  }, [user, scheduleRefresh]);

  const login = useCallback(async (username, password) => {
    const { data } = await authApi.login({ username, password });
    localStorage.setItem('bunyanx_token', data.access_token);
    const me = { username, role: data.role };
    localStorage.setItem('bunyanx_user', JSON.stringify(me));
    setUser(me);
    scheduleRefresh(data.access_token);
    // نغمة تسجيل الدخول
    audioAlertService.playUiTone('login').catch(() => {});
    return data;
  }, [scheduleRefresh]);

  const logout = useCallback(() => {
    if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
    // نغمة تسجيل الخروج قبل مسح البيانات
    audioAlertService.playUiTone('logout').catch(() => {});
    localStorage.removeItem('bunyanx_token');
    localStorage.removeItem('bunyanx_user');
    setUser(null);
  }, []);

  return (
    <AuthContext.Provider value={{ user, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
