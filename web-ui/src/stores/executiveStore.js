import { create } from 'zustand';

export const useExecutiveStore = create((set) => ({
  sysData: null,
  modulesState: null,
  incidents: [],
  idsAlerts: [],
  malwareStats: null,
  threatTrend: [],
  statsData: null,
  trafficHistory: [],

  setSysData: (sysData) => set({ sysData }),
  setModulesState: (modulesState) => set({ modulesState }),
  setIncidents: (incidents) => set({ incidents }),
  setIdsAlerts: (idsAlerts) => set({ idsAlerts }),
  setMalwareStats: (malwareStats) => set({ malwareStats }),
  setThreatTrend: (threatTrend) => set({ threatTrend }),
  setStatsData: (statsData) => set({ statsData }),
  setTrafficHistory: (trafficHistory) => set({ trafficHistory }),
}));

export default useExecutiveStore;
