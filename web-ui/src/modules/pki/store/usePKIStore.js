import { create } from 'zustand';

export const usePKIStore = create((set) => ({
  searchTerm: '',
  statusFilter: 'ALL',
  typeFilter: 'ALL',
  sortBy: 'expiry',
  selectedCertId: null,
  activeTab: 'certificates',

  setSearchTerm: (term) => set({ searchTerm: term }),
  setStatusFilter: (filter) => set({ statusFilter: filter }),
  setTypeFilter: (filter) => set({ typeFilter: filter }),
  setSortBy: (sort) => set({ sortBy: sort }),
  setSelectedCertId: (id) => set({ selectedCertId: id }),
  setActiveTab: (tab) => set({ activeTab: tab }),

  resetFilters: () => set({
    searchTerm: '',
    statusFilter: 'ALL',
    typeFilter: 'ALL',
    sortBy: 'expiry',
  }),
}));
