import { create } from 'zustand';

export const useDLPStore = create((set) => ({
  activeTab: 'monitor',
  expandedIp: null,
  rulesSearch: '',
  rulesActiveTab: 'custom',
  auditSeverityFilter: 'ALL',
  auditSearch: '',
  ersForm: {
    src_ip: '10.0.0.5',
    dst_ip: '8.8.8.8',
    protocol: 'DNS',
    dst_port: 53,
    payload_hex: '',
  },
  ersResult: null,
  feedbackEventId: '',
  feedbackLabel: 'true_positive',
  showAdminFeedback: false,

  setActiveTab: (activeTab) => set({ activeTab }),
  setExpandedIp: (expandedIp) => set({ expandedIp }),
  toggleExpandedIp: (ip) => set((state) => ({ expandedIp: state.expandedIp === ip ? null : ip })),
  setRulesSearch: (rulesSearch) => set({ rulesSearch }),
  setRulesActiveTab: (rulesActiveTab) => set({ rulesActiveTab }),
  setAuditSeverityFilter: (auditSeverityFilter) => set({ auditSeverityFilter }),
  setAuditSearch: (auditSearch) => set({ auditSearch }),
  setErsForm: (ersForm) => set({ ersForm }),
  updateErsForm: (fields) => set((state) => ({ ersForm: { ...state.ersForm, ...fields } })),
  setErsResult: (ersResult) => set({ ersResult }),
  setFeedbackEventId: (feedbackEventId) => set({ feedbackEventId }),
  setFeedbackLabel: (feedbackLabel) => set({ feedbackLabel }),
  setShowAdminFeedback: (showAdminFeedback) => set({ showAdminFeedback }),
  toggleShowAdminFeedback: () => set((state) => ({ showAdminFeedback: !state.showAdminFeedback })),

  resetStore: () => set({
    activeTab: 'monitor',
    expandedIp: null,
    rulesSearch: '',
    rulesActiveTab: 'custom',
    auditSeverityFilter: 'ALL',
    auditSearch: '',
    ersForm: { src_ip: '10.0.0.5', dst_ip: '8.8.8.8', protocol: 'DNS', dst_port: 53, payload_hex: '' },
    ersResult: null,
    feedbackEventId: '',
    feedbackLabel: 'true_positive',
    showAdminFeedback: false,
  }),
}));

export default useDLPStore;
