import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export const useDashboardStore = create(
  persist(
    (set) => ({
      // Tab navigation
      activeTab: 'live',
      setActiveTab: (activeTab) => set({ activeTab }),

      // Events search filters
      eventsFilter: { src_ip: '', verdict: '' },
      setEventsFilter: (eventsFilter) => set({ eventsFilter }),

      // Logs explorer state
      logsState: { activeFile: '', levelParam: '', keywordParam: '' },
      setLogsState: (updates) =>
        set((state) => ({ logsState: { ...state.logsState, ...updates } })),

      // Threat Intel state
      intelState: { lookupIp: '', lookupResult: null },
      setIntelState: (updates) =>
        set((state) => ({ intelState: { ...state.intelState, ...updates } })),

      // Selected event for drawer
      selectedEvent: null,
      setSelectedEvent: (selectedEvent) => set({ selectedEvent }),
    }),
    {
      name: 'bunyanx_dashboard_store',
      partialize: (state) => ({
        activeTab: state.activeTab,
        eventsFilter: state.eventsFilter,
        logsState: state.logsState,
      }),
    }
  )
);

export default useDashboardStore;
