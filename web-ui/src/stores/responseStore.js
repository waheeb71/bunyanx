import { create } from 'zustand';

export const useResponseStore = create((set) => ({
  selectedIncident: null,
  filter: 'all',
  search: '',

  setSelectedIncident: (selected) => set({ selectedIncident: selected }),
  setFilter: (filter) => set({ filter }),
  setSearch: (search) => set({ search }),
  
  clearStore: () => set({ selectedIncident: null, filter: 'all', search: '' }),
}));

export default useResponseStore;
