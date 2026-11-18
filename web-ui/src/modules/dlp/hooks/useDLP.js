import { useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { dlpApi } from '../dlpApi';
import { useLiveFeedStore } from '../../../stores/liveFeedStore';

const DEFAULT_CONFIG = {
  is_active: true,
  block_on_match: true,
  deception_enabled: true,
  befp_enabled: true,
  befp_block_threshold: 0.80,
  befp_alert_threshold: 0.35,
  w_entropy: 0.30,
  w_velocity: 0.25,
  w_chunking: 0.15,
  w_protocol: 0.20,
  w_accumulation: 0.10,
};

export function useDLP() {
  const qc = useQueryClient();
  const alertsFeed = useLiveFeedStore((s) => s.alertsFeed);

  // Watch live feed for dlp alerts
  useEffect(() => {
    if (!alertsFeed || alertsFeed.length === 0) return;
    const latestAlert = alertsFeed[0];
    if (latestAlert && (latestAlert.module === 'dlp' || latestAlert.topic === 'dlp.incident')) {
      qc.invalidateQueries({ queryKey: ['dlp_status'] });
      qc.invalidateQueries({ queryKey: ['dlp_high_risk'] });
      qc.invalidateQueries({ queryKey: ['dlp_audit'] });
    }
  }, [alertsFeed, qc]);

  // Queries
  const statusQuery = useQuery({
    queryKey: ['dlp_status'],
    queryFn: () => dlpApi.status().then((r) => r.data),
    refetchInterval: 10000,
    staleTime: 5 * 60 * 1000,
    gcTime: 10 * 60 * 1000,
  });

  const configQuery = useQuery({
    queryKey: ['dlp_config'],
    queryFn: () => dlpApi.config().then((r) => r.data),
    placeholderData: DEFAULT_CONFIG,
    staleTime: 5 * 60 * 1000,
    gcTime: 10 * 60 * 1000,
  });

  const rulesQuery = useQuery({
    queryKey: ['dlp_rules'],
    queryFn: () => dlpApi.rules().then((r) => r.data),
    staleTime: 5 * 60 * 1000,
    gcTime: 10 * 60 * 1000,
  });

  const auditQuery = useQuery({
    queryKey: ['dlp_audit'],
    queryFn: () => dlpApi.audit().then((r) => r.data?.records || []),
    refetchInterval: 10000,
    staleTime: 5 * 60 * 1000,
    gcTime: 10 * 60 * 1000,
  });

  const highRiskQuery = useQuery({
    queryKey: ['dlp_high_risk'],
    queryFn: () => dlpApi.highRiskIps().then((r) => r.data),
    refetchInterval: 15000,
    staleTime: 5 * 60 * 1000,
    gcTime: 10 * 60 * 1000,
  });

  const pendingFeedbackQuery = useQuery({
    queryKey: ['dlp_pending_feedback'],
    queryFn: () => dlpApi.pendingFeedback().then((r) => r.data),
    refetchInterval: 30000,
    staleTime: 5 * 60 * 1000,
    gcTime: 10 * 60 * 1000,
  });

  const yamlSettingsQuery = useQuery({
    queryKey: ['dlp_yaml_settings'],
    queryFn: () => dlpApi.yamlSettings().then((r) => r.data),
    staleTime: 5 * 60 * 1000,
    gcTime: 10 * 60 * 1000,
  });

  // Mutations
  const updateConfig = useMutation({
    mutationFn: (d) => dlpApi.updateConfig(d),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['dlp_config'] });
      qc.invalidateQueries({ queryKey: ['dlp_status'] });
    },
  });

  const createRule = useMutation({
    mutationFn: (d) => dlpApi.createRule(d),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['dlp_rules'] });
    },
  });

  const deleteRule = useMutation({
    mutationFn: (id) => dlpApi.deleteRule(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['dlp_rules'] });
    },
  });

  const testErs = useMutation({
    mutationFn: (d) => dlpApi.testErs(d).then((r) => r.data),
  });

  const submitFeedback = useMutation({
    mutationFn: (d) => dlpApi.submitFeedback(d).then((r) => r.data),
  });

  const reviewFeedback = useMutation({
    mutationFn: ({ id, action }) => dlpApi.reviewFeedback(id, action),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['dlp_pending_feedback'] });
    },
  });

  const optimizeWeights = useMutation({
    mutationFn: () => dlpApi.optimizeWeights().then((r) => r.data),
  });

  return {
    // Data
    status: statusQuery.data,
    isFetchingStatus: statusQuery.isFetching,
    config: configQuery.data || DEFAULT_CONFIG,
    rules: rulesQuery.data || [],
    auditLogs: auditQuery.data || [],
    isLoadingAudit: auditQuery.isLoading,
    isErrorAudit: auditQuery.isError,
    highRiskIps: highRiskQuery.data || [],
    isFetchingHighRisk: highRiskQuery.isFetching,
    refetchHighRisk: highRiskQuery.refetch,
    pendingFeedback: pendingFeedbackQuery.data || [],
    isFetchingPendingFeedback: pendingFeedbackQuery.isFetching,
    refetchPendingFeedback: pendingFeedbackQuery.refetch,
    yamlSettings: yamlSettingsQuery.data,

    // Mutations
    updateConfig,
    createRule,
    deleteRule,
    testErs,
    submitFeedback,
    reviewFeedback,
    optimizeWeights,
  };
}

export function useDLPIpProfile(srcIp, enabled = false) {
  return useQuery({
    queryKey: ['dlp-profile', srcIp],
    queryFn: () => dlpApi.ipProfile(srcIp).then((r) => r.data),
    enabled: enabled && !!srcIp,
    staleTime: 5 * 60 * 1000,
    gcTime: 10 * 60 * 1000,
  });
}

export function useDLPMsemProfile(srcIp, enabled = false) {
  return useQuery({
    queryKey: ['dlp-msem-profile', srcIp],
    queryFn: () => dlpApi.msemProfile(srcIp).then((r) => r.data),
    enabled: enabled && !!srcIp,
    staleTime: 5 * 60 * 1000,
    gcTime: 10 * 60 * 1000,
  });
}

export default useDLP;
