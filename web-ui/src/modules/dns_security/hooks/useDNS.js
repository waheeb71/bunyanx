/**
 * useDNS.js — Centralized React-Query hooks for the DNS Security module.
 * All data fetching and mutations live here; components stay clean.
 */
import { useQueryClient, useQuery, useMutation } from '@tanstack/react-query';
import { dnsApi } from '../../../services/api';

export const DEFAULT_CFG = {
  is_active: true,
  enable_dga_detection: true,
  enable_tunneling_detection: true,
  enable_threat_intel: true,
  enable_rate_limiting: true,
  enable_tld_blocking: true,
  enable_dart_detection: true,
  dga_entropy_threshold: 3.8,
  tunneling_query_threshold: 50,
  rate_limit_per_minute: 100,
  sinkhole_ip: '10.0.0.1',
  suspicious_tlds: '.tk,.ml,.ga,.cf,.gq,.xyz,.top,.win,.bid,.onion',
  dnssec_validation: true,
  inspect_doh: true,
  inspect_dot: true,
};

export const DEFAULT_STATS = {
  total_rules: 0,
  active_rules: 0,
  total_queries: 0,
  blocked_count: 0,
  sinkhole_count: 0,
  allowed_count: 0,
  block_rate: 0,
  category_breakdown: {},
  top_blocked: [],
  top_clients: [],
};

export function useDNS() {
  const qc = useQueryClient();

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['dns-config'] });
    qc.invalidateQueries({ queryKey: ['dns-stats'] });
    qc.invalidateQueries({ queryKey: ['dns-rules'] });
    qc.invalidateQueries({ queryKey: ['dns-dart-alerts'] });
    qc.invalidateQueries({ queryKey: ['dns-steering'] });
    qc.invalidateQueries({ queryKey: ['dns-queries'] });
  };

  const configQuery = useQuery({
    queryKey: ['dns-config'],
    queryFn: () => dnsApi.getConfig().then(r => r.data),
    retry: false,
    placeholderData: DEFAULT_CFG,
  });
  const config = configQuery.data || DEFAULT_CFG;

  const statsQuery = useQuery({
    queryKey: ['dns-stats'],
    queryFn: () => dnsApi.stats().then(r => r.data),
    retry: false,
    placeholderData: DEFAULT_STATS,
    refetchInterval: 10000,
  });
  const stats = statsQuery.data || DEFAULT_STATS;

  const rulesQuery = useQuery({
    queryKey: ['dns-rules'],
    queryFn: () => dnsApi.rules().then(r => r.data),
    retry: false,
    placeholderData: [],
  });
  const rules = rulesQuery.data || [];

  const dartAlertsQuery = useQuery({
    queryKey: ['dns-dart-alerts'],
    queryFn: () => dnsApi.listDartAlerts().then(r => r.data),
    retry: false,
    placeholderData: [],
    refetchInterval: 10000,
  });
  const dartAlerts = dartAlertsQuery.data || [];

  const steeringQuery = useQuery({
    queryKey: ['dns-steering'],
    queryFn: () => dnsApi.listSteeringRules().then(r => r.data),
    retry: false,
    placeholderData: [],
  });
  const steeringRules = steeringQuery.data || [];

  const queriesQuery = useQuery({
    queryKey: ['dns-queries'],
    queryFn: () => dnsApi.getQueries({ limit: 150 }).then(r => r.data),
    retry: false,
    placeholderData: [],
    refetchInterval: 4000,
  });
  const queries = queriesQuery.data || [];

  const updateConfig = useMutation({ mutationFn: d => dnsApi.updateConfig(d), onSuccess: invalidate });
  const createRule   = useMutation({ mutationFn: d => dnsApi.createRule(d),   onSuccess: invalidate });
  const updateRule   = useMutation({ mutationFn: ({ id, d }) => dnsApi.updateRule(id, d), onSuccess: invalidate });
  const deleteRule   = useMutation({ mutationFn: id => dnsApi.deleteRule(id), onSuccess: invalidate });

  // DART alerts SOC review actions
  const reviewAlert = useMutation({ mutationFn: id => dnsApi.reviewDartAlert(id), onSuccess: invalidate });
  const flagFalsePositive = useMutation({ mutationFn: id => dnsApi.flagDartFalsePositive(id), onSuccess: invalidate });

  // Steering Rules mutations
  const createSteering = useMutation({ mutationFn: d => dnsApi.createSteeringRule(d), onSuccess: invalidate });
  const deleteSteering = useMutation({ mutationFn: name => dnsApi.deleteSteeringRule(name), onSuccess: invalidate });

  // Threat Intel manual trigger
  const syncThreatIntel = useMutation({ mutationFn: () => dnsApi.refreshThreatIntel() });

  // Clear live queries
  const clearQueries = useMutation({ mutationFn: () => dnsApi.clearQueries(), onSuccess: invalidate });

  const refetchAll = () => {
    qc.refetchQueries({ queryKey: ['dns-config'] });
    qc.refetchQueries({ queryKey: ['dns-stats'] });
    qc.refetchQueries({ queryKey: ['dns-rules'] });
    qc.refetchQueries({ queryKey: ['dns-dart-alerts'] });
    qc.refetchQueries({ queryKey: ['dns-steering'] });
    qc.refetchQueries({ queryKey: ['dns-queries'] });
  };

  const isFetching = configQuery.isFetching || statsQuery.isFetching || rulesQuery.isFetching || dartAlertsQuery.isFetching || steeringQuery.isFetching || queriesQuery.isFetching;

  return {
    config,
    stats,
    rules,
    dartAlerts,
    steeringRules,
    queries,
    isFetching,
    refetchAll,
    updateConfig,
    createRule,
    updateRule,
    deleteRule,
    reviewAlert,
    flagFalsePositive,
    createSteering,
    deleteSteering,
    syncThreatIntel,
    clearQueries,
  };
}

