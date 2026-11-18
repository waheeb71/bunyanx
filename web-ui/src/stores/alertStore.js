import { create } from 'zustand';
import { formatAlert } from '../utils/alertFormatter';

const MAX_ALERTS = 100;

/**
 * Global alert store — shared across all modules via Zustand.
 * Used by LiveMonitor (WebSocket) to push alerts, and by the Shell
 * notifications panel to display them.
 */
export const useAlertStore = create((set, get) => ({
  alerts: [],
  unreadCount: 0,
  lastAlertTime: null,

  addAlert: (alert) => {
    const rawAlert = {
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      severity: 'info',
      read: false,
      ...alert,
    };
    const newAlert = formatAlert(rawAlert);
    set(state => ({
      alerts: [newAlert, ...state.alerts].slice(0, MAX_ALERTS),
      unreadCount: state.unreadCount + 1,
      lastAlertTime: newAlert.timestamp,
    }));
  },

  markAllRead: () => set(state => {
    if (state.unreadCount === 0 && state.alerts.every(a => a.read)) return state;
    return {
      unreadCount: 0,
      alerts: state.alerts.map(a => a.read ? a : { ...a, read: true }),
    };
  }),

  markRead: (id) => set(state => ({
    alerts: state.alerts.map(a => a.id === id ? { ...a, read: true } : a),
    unreadCount: Math.max(0, state.unreadCount - 1),
  })),

  clearAll: () => set({ alerts: [], unreadCount: 0 }),

  getRecentAlerts: (n = 20) => get().alerts.slice(0, n),
  getCriticalAlerts: () => get().alerts.filter(a => a.severity === 'critical'),
}));
