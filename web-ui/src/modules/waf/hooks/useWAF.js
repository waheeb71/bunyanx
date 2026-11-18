import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { wafApi } from '../api/wafApi';

export function useWAF() {
  const qc = useQueryClient();

  // Core Status Query
  const statusQuery = useQuery({
    queryKey: ['waf-status'],
    queryFn: () => wafApi.status().then(r => r.data),
    refetchInterval: 10000,
    staleTime: 9000,
  });

  // Recent Inspection Events Query
  const eventsQuery = useQuery({
    queryKey: ['waf-events'],
    queryFn: () => wafApi.events({ limit: 100 }).then(r => r.data),
    refetchInterval: 8000,
    staleTime: 5000,
  });

  // Shadow Mode Query
  const shadowStatusQuery = useQuery({
    queryKey: ['shadow-status'],
    queryFn: () => wafApi.shadowModeStatus().then(r => r.data),
    refetchInterval: 3000,
    staleTime: 2500,
  });

  // Settings Query
  const settingsQuery = useQuery({
    queryKey: ['waf-settings'],
    queryFn: () => wafApi.settings().then(r => r.data),
    staleTime: 0,
  });

  // GNN Neural Model Status Query
  const gnnStatusQuery = useQuery({
    queryKey: ['gnn-status'],
    queryFn: () => wafApi.gnnStatus().then(r => r.data),
    refetchInterval: 5000,
    staleTime: 4000,
  });

  // GNN Session Logs Preview Query
  const gnnLogsQuery = useQuery({
    queryKey: ['gnn-logs'],
    queryFn: () => wafApi.gnnLogs().then(r => r.data),
    refetchInterval: 10000,
    staleTime: 8000,
  });

  // GNN Training Status Query (polls faster when training is active)
  const trainingStatusQuery = useQuery({
    queryKey: ['gnn-training-status'],
    queryFn: () => wafApi.trainingStatus().then(r => r.data),
    refetchInterval: (query) => {
      const state = query.state.data?.state;
      return (state === 'running' || state === 'starting') ? 2000 : 10000;
    },
  });

  // Helper mutation invalidator
  const mutateWithInvalidate = (mutationFn, extraKeys = []) => useMutation({
    mutationFn,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['waf-status'] });
      qc.invalidateQueries({ queryKey: ['waf-settings'] });
      extraKeys.forEach(k => qc.invalidateQueries({ queryKey: [k] }));
    }
  });

  // Mutations
  const toggleMut = mutateWithInvalidate(({ feature, enabled }) => wafApi.toggleWaapFeature(feature, enabled));
  const toggleGnnMut = mutateWithInvalidate((enabled) => wafApi.toggleGnn(enabled), ['gnn-status']);
  const setModeMut = mutateWithInvalidate((mode) => wafApi.setWafMode(mode));
  const setMasterMut = mutateWithInvalidate((enabled) => wafApi.setWafMaster(enabled));
  
  // Advanced Settings Mutations
  const configModelMut = mutateWithInvalidate(({ model, data }) => wafApi.configModel(model, data));
  const toggleModelMut = mutateWithInvalidate(({ model, enabled }) => wafApi.toggleModel(model, enabled));
  const configBotMut = mutateWithInvalidate((data) => wafApi.configBot(data));
  const updateRiskThresholdsMut = mutateWithInvalidate((data) => wafApi.updateRiskThresholds(data));
  const configThreatIntelMut = mutateWithInvalidate((data) => wafApi.configThreatIntel(data));
  const configHoneypotMut = mutateWithInvalidate((data) => wafApi.configHoneypot(data));
  const configDeceptionMut = mutateWithInvalidate((data) => wafApi.configDeception(data));
  const configPerformanceMut = mutateWithInvalidate((data) => wafApi.configPerformance(data));
  const configAtoMut = mutateWithInvalidate((data) => wafApi.configAto(data));
  const configGraphqlMut = mutateWithInvalidate((data) => wafApi.configGraphql(data));
  const configPreprocessingMut = mutateWithInvalidate((data) => wafApi.configPreprocessing(data));
  const configDynamicAmplifiersMut = mutateWithInvalidate((data) => wafApi.configDynamicAmplifiers(data));
  const updateWhitelistMut = mutateWithInvalidate(({ ips, cidrs }) => wafApi.updateWhitelist(ips, cidrs));
  const addWhitelistMut = mutateWithInvalidate(({ ips, cidrs }) => wafApi.addWhitelist(ips, cidrs));
  const updateBlacklistMut = mutateWithInvalidate(({ ips, cidrs }) => wafApi.updateBlacklist(ips, cidrs));
  const addBlacklistMut = mutateWithInvalidate(({ ips, cidrs }) => wafApi.addBlacklist(ips, cidrs));
  const reloadSettingsMut = mutateWithInvalidate(() => wafApi.reloadSettings());

  // GNN Specific Mutations
  const flushLogsMut = useMutation({
    mutationFn: () => wafApi.flushLogs(),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['gnn-status'] });
      qc.invalidateQueries({ queryKey: ['gnn-logs'] });
    }
  });

  const startTrainingMut = useMutation({
    mutationFn: (params) => wafApi.startTraining(params || { epochs: 30, n_synthetic: 500 }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['gnn-training-status'] })
  });

  const activateModelMut = useMutation({
    mutationFn: (data) => wafApi.activateModel(data || {}),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['gnn-status'] });
      qc.invalidateQueries({ queryKey: ['waf-status'] });
    }
  });

  // Session & Schema Mutations
  const clearIpSessionMut = useMutation({
    mutationFn: (ip) => wafApi.clearIpSession(ip)
  });

  const uploadApiSchemaMut = useMutation({
    mutationFn: ({ endpoint, schema }) => wafApi.uploadApiSchema(endpoint, schema),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['waf-status'] })
  });

  // Shadow Mode
  const startShadowMut = useMutation({
    mutationFn: (hours = 24) => wafApi.startShadowMode(hours),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['shadow-status'] })
  });

  const stopShadowMut = useMutation({
    mutationFn: () => wafApi.stopShadowMode(),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['shadow-status'] })
  });

  const exportShadowSchemaMut = useMutation({
    mutationFn: () => wafApi.exportShadowSchema().then(r => {
      const blob = new Blob([JSON.stringify(r.data.schema, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'autopilot_schema.json';
      a.click();
    })
  });

  const simulateAttackMut = useMutation({
    mutationFn: (type) => wafApi.simulateAttack(type),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['waf-events'] });
      qc.invalidateQueries({ queryKey: ['waf-status'] });
    }
  });

  return {
    status: statusQuery.data || {},
    statusLoading: statusQuery.isLoading,

    events: eventsQuery.data?.events || [],
    eventsLoading: eventsQuery.isLoading,
    
    shadowStatus: shadowStatusQuery.data || {},
    shadowStatusLoading: shadowStatusQuery.isLoading,

    settings: settingsQuery.data || null,
    settingsLoading: settingsQuery.isLoading,

    gnnStatus: gnnStatusQuery.data || {},
    gnnStatusLoading: gnnStatusQuery.isLoading,

    gnnLogs: gnnLogsQuery.data || {},
    gnnLogsLoading: gnnLogsQuery.isLoading,

    trainingStatus: trainingStatusQuery.data || {},
    trainingStatusLoading: trainingStatusQuery.isLoading,
    
    // Waap Features
    toggleFeature: (feature, enabled) => toggleMut.mutate({ feature, enabled }),
    togglingFeature: toggleMut.isPending,
    toggleGnn: (enabled) => toggleGnnMut.mutate(enabled),
    togglingGnn: toggleGnnMut.isPending,
    
    // Core settings
    setWafMode: (mode) => setModeMut.mutate(mode),
    setWafMaster: (enabled) => setMasterMut.mutate(enabled),
    reloadSettings: () => reloadSettingsMut.mutate(),
    
    // Advanced settings mutators
    configModel: (model, data) => configModelMut.mutate({ model, data }),
    toggleModel: (model, enabled) => toggleModelMut.mutate({ model, enabled }),
    configBot: (data) => configBotMut.mutate(data),
    updateRiskThresholds: (data) => updateRiskThresholdsMut.mutate(data),
    configThreatIntel: (data) => configThreatIntelMut.mutate(data),
    configHoneypot: (data) => configHoneypotMut.mutate(data),
    configDeception: (data) => configDeceptionMut.mutate(data),
    configPerformance: (data) => configPerformanceMut.mutate(data),
    configAto: (data) => configAtoMut.mutate(data),
    configGraphql: (data) => configGraphqlMut.mutate(data),
    configPreprocessing: (data) => configPreprocessingMut.mutate(data),
    configDynamicAmplifiers: (data) => configDynamicAmplifiersMut.mutate(data),
    updateWhitelist: (ips, cidrs) => updateWhitelistMut.mutate({ ips, cidrs }),
    addWhitelist: (ips, cidrs) => addWhitelistMut.mutate({ ips, cidrs }),
    updateBlacklist: (ips, cidrs) => updateBlacklistMut.mutate({ ips, cidrs }),
    addBlacklist: (ips, cidrs) => addBlacklistMut.mutate({ ips, cidrs }),
    
    // GNN & Training Action Mutators
    flushSessionLogs: () => flushLogsMut.mutateAsync(),
    flushingLogs: flushLogsMut.isPending,
    startGnnTraining: (params) => startTrainingMut.mutateAsync(params),
    startingTraining: startTrainingMut.isPending,
    activateGnnModel: (data) => activateModelMut.mutateAsync(data),
    activatingModel: activateModelMut.isPending,

    // Session & Schema
    clearIpSession: (ip) => clearIpSessionMut.mutateAsync(ip),
    uploadApiSchema: (endpoint, schema) => uploadApiSchemaMut.mutateAsync({ endpoint, schema }),

    // Shadow Mode
    startShadowMode: (hours) => startShadowMut.mutate(hours),
    startingShadowMode: startShadowMut.isPending,
    stopShadowMode: () => stopShadowMut.mutate(),
    stoppingShadowMode: stopShadowMut.isPending,
    exportShadowSchema: () => exportShadowSchemaMut.mutateAsync(),
    exportingShadowSchema: exportShadowSchemaMut.isPending,

    // Simulation Demo
    simulateAttack: (type) => simulateAttackMut.mutateAsync(type),
    simulatingAttack: simulateAttackMut.isPending,
  };
}
