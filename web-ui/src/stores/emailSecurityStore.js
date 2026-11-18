import { create } from 'zustand';

export const useEmailSecurityStore = create((set) => ({
  tab: 'overview',
  logsFilter: '',
  cachedLogs: [],
  cachedStatus: null,
  cachedConfig: null,
  cachedStats: null,
  cachedWhitelist: null,

  setTab: (tab) => set({ tab }),
  setLogsFilter: (logsFilter) => set({ logsFilter }),
  setCachedLogs: (cachedLogs) => set({ cachedLogs }),
  setCachedStatus: (cachedStatus) => set({ cachedStatus }),
  setCachedConfig: (cachedConfig) => set({ cachedConfig }),
  setCachedStats: (cachedStats) => set({ cachedStats }),
  setCachedWhitelist: (cachedWhitelist) => set({ cachedWhitelist }),

  clearStore: () => set({
    tab: 'overview',
    logsFilter: '',
    cachedLogs: [],
    cachedStatus: null,
    cachedConfig: null,
    cachedStats: null,
    cachedWhitelist: null,
  }),
}));

export default useEmailSecurityStore;
