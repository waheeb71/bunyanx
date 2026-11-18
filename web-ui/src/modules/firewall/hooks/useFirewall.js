import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { firewallApi } from '../api/firewallApi';
import { useFirewallStore } from '../../../stores/firewallStore';

export function useFirewall() {
  const qc = useQueryClient();
  
  // Persistent Store State
  const {
    tab,
    setTab,
    search,
    setSearch,
    filterAction,
    setFilterAction,
    selectedRuleIds,
    toggleRuleSelect,
    selectAllRules,
    clearRuleSelect,
    showToast,
    toast,
    hideToast,
    liveStats,
    setLiveStats,
  } = useFirewallStore();

  const [activeModal, setActiveModal] = useState(false); // false | 'add' | 'edit'
  const [editRule, setEditRule] = useState(null);
  const [confirmBulkDeleteModal, setConfirmBulkDeleteModal] = useState(false);

  // Queries
  const { data: rules = [], isLoading, error } = useQuery({
    queryKey: ['firewall-rules'],
    queryFn: () => firewallApi.rules().then((r) => r.data),
    refetchInterval: 10000,
  });

  // Telemetry Polling (5s)
  const { data: statsData } = useQuery({
    queryKey: ['firewall-live-stats'],
    queryFn: () => firewallApi.getStats().then((r) => r.data),
    refetchInterval: 5000,
  });

  useEffect(() => {
    if (statsData) {
      setLiveStats(statsData);
    }
  }, [statsData, setLiveStats]);

  // Mutations
  const createMut = useMutation({
    mutationFn: (d) => firewallApi.createRule(d),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['firewall-rules'] });
      setActiveModal(false);
      showToast('تمت إضافة القاعدة بنجاح', 'success');
    },
    onError: (err) => showToast('فشل الإضافة: ' + (err.response?.data?.detail || err.message), 'error')
  });

  const updateMut = useMutation({
    mutationFn: ({ id, data }) => firewallApi.updateRule(id, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['firewall-rules'] });
      setActiveModal(false);
      setEditRule(null);
      showToast('تم تحديث القاعدة بنجاح', 'success');
    },
    onError: (err) => showToast('فشل التحديث: ' + (err.response?.data?.detail || err.message), 'error')
  });

  const deleteMut = useMutation({
    mutationFn: (id) => firewallApi.deleteRule(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['firewall-rules'] });
      showToast('تم حذف القاعدة بنجاح', 'success');
    },
    onError: (err) => showToast('فشل الحذف: ' + (err.response?.data?.detail || err.message), 'error')
  });

  const toggleMut = useMutation({
    mutationFn: (rule) => firewallApi.updateRule(rule.id, { ...rule, enabled: !rule.enabled }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['firewall-rules'] });
      showToast('تم تغيير حالة القاعدة', 'info');
    },
    onError: (err) => showToast('فشل تبديل الحالة: ' + (err.response?.data?.detail || err.message), 'error')
  });

  // Bulk Operations
  const bulkDeleteMut = useMutation({
    mutationFn: async (ids) => {
      await Promise.all(ids.map((id) => firewallApi.deleteRule(id)));
    },
    onSuccess: (_, ids) => {
      qc.invalidateQueries({ queryKey: ['firewall-rules'] });
      clearRuleSelect();
      setConfirmBulkDeleteModal(false);
      showToast(`تم حذف ${ids.length} قاعدة بنجاح`, 'success');
    },
    onError: (err) => showToast('فشل الحذف الجماعي: ' + (err.response?.data?.detail || err.message), 'error')
  });

  const bulkToggleMut = useMutation({
    mutationFn: async ({ targetRules, enabledState }) => {
      await Promise.all(targetRules.map((rule) => firewallApi.updateRule(rule.id, { ...rule, enabled: enabledState })));
    },
    onSuccess: (_, { targetRules, enabledState }) => {
      qc.invalidateQueries({ queryKey: ['firewall-rules'] });
      showToast(`تم ${enabledState ? 'تفعيل' : 'تعطيل'} ${targetRules.length} قاعدة بنجاح`, 'info');
    },
    onError: (err) => showToast('فشل التعديل الجماعي: ' + (err.response?.data?.detail || err.message), 'error')
  });

  const handleEdit = (rule) => {
    setEditRule(rule);
    setActiveModal('edit');
  };

  const handleSave = (data) => {
    if (editRule) {
      updateMut.mutate({ id: editRule.id, data });
    } else {
      createMut.mutate(data);
    }
  };

  const filteredRules = rules.filter((r) => {
    const matchesAction = filterAction === 'all' || r.action === filterAction;
    if (!matchesAction) return false;
    if (!search) return true;
    const s = search.toLowerCase();
    return (
      r.name?.toLowerCase().includes(s) ||
      r.source_ip?.toLowerCase().includes(s) ||
      r.destination_ip?.toLowerCase().includes(s) ||
      r.protocol?.toLowerCase().includes(s) ||
      r.destination_port?.toString().includes(s) ||
      r.action?.toLowerCase().includes(s)
    );
  });

  const exportRulesCSV = () => {
    const headers = ['ID', 'Priority', 'Name', 'Action', 'Protocol', 'Source IP', 'Destination IP', 'Destination Port', 'Enabled'];
    const rows = filteredRules.map(r => [
      r.id, r.priority, `"${r.name}"`, r.action, r.protocol, r.source_ip, r.destination_ip, r.destination_port, r.enabled ? 'Yes' : 'No'
    ]);
    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `firewall_rules_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    showToast('تم تصدير القواعد بصيغة CSV', 'success');
  };

  const exportRulesJSON = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(rules, null, 2));
    const link = document.createElement('a');
    link.setAttribute('href', dataStr);
    link.setAttribute('download', `firewall_rules_${new Date().toISOString().slice(0, 10)}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    showToast('تم تصدير السياسة بصيغة JSON', 'success');
  };

  return {
    tab,
    setTab,
    search,
    setSearch,
    filterAction,
    setFilterAction,
    selectedRuleIds,
    toggleRuleSelect,
    selectAllRules: () => selectAllRules(filteredRules.map(r => r.id)),
    clearRuleSelect,
    activeModal,
    setActiveModal,
    confirmBulkDeleteModal,
    setConfirmBulkDeleteModal,
    editRule,
    setEditRule,
    isLoading,
    error,
    rules: filteredRules,
    allRulesCount: rules.length,
    handleEdit,
    handleSave,
    onDelete: (id) => deleteMut.mutate(id),
    onToggle: (rule) => toggleMut.mutate(rule),
    onBulkDelete: () => bulkDeleteMut.mutate(selectedRuleIds),
    onBulkToggle: (enabledState) => {
      const selected = rules.filter(r => selectedRuleIds.includes(r.id));
      bulkToggleMut.mutate({ targetRules: selected, enabledState });
    },
    exportRulesCSV,
    exportRulesJSON,
    isSaving: createMut.isPending || updateMut.isPending || bulkDeleteMut.isPending || bulkToggleMut.isPending,
    toast,
    showToast,
    hideToast,
    liveStats,
  };
}

export default useFirewall;
