import { create } from 'zustand';

export const useFirewallStore = create((set, get) => ({
  tab: 'rules', // rules | blocklist | optimizer | xdp | tester | settings
  search: '',
  filterAction: 'all',
  selectedRuleIds: [],
  toast: null,
  liveStats: null,

  setTab: (tab) => set({ tab }),
  setSearch: (search) => set({ search }),
  setFilterAction: (filterAction) => set({ filterAction }),
  
  toggleRuleSelect: (id) => set((state) => {
    const exists = state.selectedRuleIds.includes(id);
    return {
      selectedRuleIds: exists
        ? state.selectedRuleIds.filter((rId) => rId !== id)
        : [...state.selectedRuleIds, id]
    };
  }),

  selectAllRules: (allIds) => set({ selectedRuleIds: allIds }),
  clearRuleSelect: () => set({ selectedRuleIds: [] }),

  showToast: (message, type = 'info') => {
    set({ toast: { message, type, id: Date.now() } });
    setTimeout(() => {
      if (get().toast?.message === message) {
        set({ toast: null });
      }
    }, 4000);
  },

  hideToast: () => set({ toast: null }),
  setLiveStats: (liveStats) => set({ liveStats }),
}));

export default useFirewallStore;
