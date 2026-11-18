import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { aiApi } from '../api/aiApi';

export function usePredictiveAI() {
  const qc = useQueryClient();
  const [tab, setTabState] = useState(() => {
    try { return sessionStorage.getItem('pai_active_tab') || 'overview'; } catch (e) { return 'overview'; }
  });
  const [uploading, setUploading] = useState(null);
  const [showIpInspector, setShowIpInspector] = useState(false);
  const [logsTab, setLogsTabState] = useState(() => {
    try { return sessionStorage.getItem('pai_logs_tab') || 'decisions'; } catch (e) { return 'decisions'; }
  });

  const setTab = (newTab) => {
    setTabState(newTab);
    try { sessionStorage.setItem('pai_active_tab', newTab); } catch (e) { }
  };

  const setLogsTab = (newLogsTab) => {
    setLogsTabState(newLogsTab);
    try { sessionStorage.setItem('pai_logs_tab', newLogsTab); } catch (e) { }
  };

  /* ── Queries ── */
  const { data: config } = useQuery({
    queryKey: ['ai_config'],
    queryFn: () => aiApi.config().then(r => r.data),
  });

  const { data: modelsData, isLoading: modelsLoading, refetch: refetchModels } = useQuery({
    queryKey: ['ai_models'],
    queryFn: () => aiApi.models().then(r => r.data),
    refetchInterval: 20000,
  });

  const { data: budgetData } = useQuery({
    queryKey: ['ai_budget'],
    queryFn: () => aiApi.safetyBudget().then(r => r.data),
    refetchInterval: 5000,
  });

  const { data: intentsData } = useQuery({
    queryKey: ['ai_intents'],
    queryFn: () => aiApi.activeIntents().then(r => r.data),
    refetchInterval: 5000,
  });

  const { data: killchainData } = useQuery({
    queryKey: ['ai_killchain'],
    queryFn: () => aiApi.killchainGraph().then(r => r.data),
    refetchInterval: 10000,
  });

  const { data: killchainStats } = useQuery({
    queryKey: ['ai_killchain_stats'],
    queryFn: () => aiApi.killchainStats().then(r => r.data),
    refetchInterval: 15000,
  });

  const { data: auditData } = useQuery({
    queryKey: ['ai_audit'],
    queryFn: () => aiApi.safetyAudit(30).then(r => r.data),
    refetchInterval: 5000,
  });

  const { data: decisionsData, isLoading: decLoading } = useQuery({
    queryKey: ['ai_AEGIS_decisions'],
    queryFn: () => aiApi.AEGISDecisions(30).then(r => r.data),
    refetchInterval: 5000,
    enabled: tab === 'decisions',
  });

  const { data: uebaData } = useQuery({
    queryKey: ['ai_ueba_metrics'],
    queryFn: () => aiApi.uebaMetrics().then(r => r.data),
    refetchInterval: 15000,
    enabled: tab === 'models',
  });

  const { data: decoysData } = useQuery({
    queryKey: ['ai_active_decoys'],
    queryFn: () => aiApi.AEGISActiveDecoys().then(r => r.data),
    refetchInterval: 8000,
  });

  const { data: AEGISHealth } = useQuery({
    queryKey: ['ai_AEGIS_health'],
    queryFn: () => aiApi.AEGISHealth().then(r => r.data),
    refetchInterval: 30000,
  });

  const { data: tpeReport } = useQuery({
    queryKey: ['ai_tpe_report'],
    queryFn: () => aiApi.tpeLastReport().then(r => r.data),
    refetchInterval: 60000,
    enabled: tab === 'overview',
  });

  // DB history logs
  const { data: logDecisions } = useQuery({
    queryKey: ['log_decisions'],
    queryFn: () => aiApi.logsDecisions(50).then(r => r.data),
    enabled: tab === 'logs' && logsTab === 'decisions',
    refetchInterval: 10000,
  });

  const { data: logIntent } = useQuery({
    queryKey: ['log_intent'],
    queryFn: () => aiApi.logsIntent(50).then(r => r.data),
    enabled: tab === 'logs' && logsTab === 'intent',
    refetchInterval: 10000,
  });

  const { data: logDecoy } = useQuery({
    queryKey: ['log_decoy'],
    queryFn: () => aiApi.logsDecoy(50).then(r => r.data),
    enabled: tab === 'logs' && logsTab === 'decoy',
    refetchInterval: 10000,
  });

  /* ── Mutations ── */
  const updateMut = useMutation({
    mutationFn: (d) => aiApi.updateConfig(d),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ai_config'] }),
  });

  const uploadMut = useMutation({
    mutationFn: ({ id, file }) => aiApi.uploadModel(id, file),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['ai_models'] });
      setUploading(null);
    },
  });

  const refreshAll = () => {
    refetchModels();
    ['ai_budget', 'ai_intents', 'ai_killchain', 'ai_audit', 'ai_AEGIS_decisions',
      'ai_active_decoys', 'ai_AEGIS_health', 'log_decisions', 'log_intent', 'log_decoy']
      .forEach(k => qc.invalidateQueries([k]));
  };

  /* ── Derived Data mapping ── */
  const cfg = config ?? {};
  const models = modelsData?.models ?? [];
  const budget = budgetData?.budget ?? { current_budget: 100, max_budget: 100, regen_rate: '---' };
  const intents = intentsData?.intents ?? [];
  const graphInfo = killchainData || { available: false, top_edges: [] };
  const kcStats = killchainStats?.stats ?? {};
  const auditLogs = auditData?.audit_log ?? [];
  const decisions = decisionsData?.decisions ?? [];
  const decoys = decoysData?.active_decoys ?? [];
  const ueba = uebaData?.metrics ?? {};
  const tpe = tpeReport?.report ?? null;

  return {
    // View States
    tab,
    setTab,
    uploading,
    setUploading,
    showIpInspector,
    setShowIpInspector,
    logsTab,
    setLogsTab,

    // Data States
    cfg,
    models,
    modelsLoading,
    budget,
    intents,
    graphInfo,
    kcStats,
    auditLogs,
    decisions,
    decLoading,
    decoys,
    ueba,
    tpe,
    logDecisions,
    logIntent,
    logDecoy,
    AEGISHealth,

    // Actions & Mutations
    updateMut,
    uploadMut,
    refreshAll,
  };
}

export default usePredictiveAI;
