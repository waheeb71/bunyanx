import { create } from 'zustand';

export const useGlobeStore = create((set) => ({
  mapMode: 'global',
  timeframe: '24h',
  severityFilter: 'all',
  categoryFilter: 'all',
  isFeedPaused: false,
  audioEnabled: false,
  selectedThreat: null,

  setMapMode: (mode) => set({ mapMode: mode }),
  setTimeframe: (timeframe) => set({ timeframe }),
  setSeverityFilter: (severityFilter) => set({ severityFilter }),
  setCategoryFilter: (categoryFilter) => set({ categoryFilter }),
  toggleFeedPause: () => set((s) => ({ isFeedPaused: !s.isFeedPaused })),
  toggleAudio: () => set((s) => ({ audioEnabled: !s.audioEnabled })),
  setSelectedThreat: (threat) => set({ selectedThreat: threat }),
}));
