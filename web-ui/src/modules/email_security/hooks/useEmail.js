/**
 * useEmail.js — Centralized React-Query hooks for the Email Security module.
 */
import { useQueryClient, useQuery, useMutation } from '@tanstack/react-query';
import { emailApi } from '../api/emailApi';
import { useEmailSecurityStore } from '../../../stores/emailSecurityStore';

const DEFAULT_STATS = {
  total_inspected: 0, total_blocked: 0, total_quarantined: 0, total_allowed: 0,
  phishing_detected: 0, spam_detected: 0, ai_mimicry_detected: 0, visual_desync_detected: 0,
  avg_risk_score: 0, decision_breakdown: {}, top_blocked_senders: [],
};

const DEFAULT_CFG = {
  enabled: true, mode: 'monitor',
  monitored_ports: [25, 587, 465, 143, 993, 110, 995],
  preprocessing: {}, phishing: {}, url_scanner: {}, attachment_guard: {},
  sender_reputation: {}, spam_filter: {}, smtp_commands: {},
  thresholds: {}, risk_scoring: {}, logging: {},
  vsde_config: {}, plsf_config: {},
};

export function useEmail() {
  const qc    = useQueryClient();
  const store = useEmailSecurityStore();

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['email_config'] });
    qc.invalidateQueries({ queryKey: ['email_status'] });
    qc.invalidateQueries({ queryKey: ['email_stats'] });
  };

  /* ── Status ─────────────────────────────────────────────────── */
  const cachedStatus = store.cachedStatus;
  const { data: status = cachedStatus } = useQuery({
    queryKey: ['email_status'],
    queryFn:  () => emailApi.status().then(r => {
      store.setCachedStatus(r.data);
      return r.data;
    }),
    refetchInterval: 15000,
    placeholderData: cachedStatus,
  });

  /* ── Config ──────────────────────────────────────────────────── */
  const cachedConfig = store.cachedConfig;
  const { data: config = cachedConfig || DEFAULT_CFG } = useQuery({
    queryKey: ['email_config'],
    queryFn:  () => emailApi.config().then(r => {
      store.setCachedConfig(r.data);
      return r.data;
    }),
    placeholderData: cachedConfig || DEFAULT_CFG,
    staleTime: 0,
  });

  /* ── Config Schema (YAML defaults — for advanced form) ────────── */
  const { data: configSchema = null } = useQuery({
    queryKey: ['email_config_schema'],
    queryFn:  () => emailApi.configSchema().then(r => r.data).catch(() => null),
    staleTime: 300_000,   // schema is static — refresh every 5 min
  });

  /* ── Stats ───────────────────────────────────────────────────── */
  const cachedStats = store.cachedStats;
  const { data: stats = cachedStats || DEFAULT_STATS } = useQuery({
    queryKey: ['email_stats'],
    queryFn:  () => emailApi.stats().then(r => {
      store.setCachedStats(r.data);
      return r.data;
    }),
    placeholderData: cachedStats || DEFAULT_STATS,
    refetchInterval: 20000,
  });

  /* ── Whitelist ───────────────────────────────────────────────── */
  const cachedWhitelist = store.cachedWhitelist;
  const { data: whitelist = cachedWhitelist || { emails: [], domains: [], ips: [] } } = useQuery({
    queryKey: ['email_whitelist'],
    queryFn:  () => emailApi.whitelist().then(r => {
      store.setCachedWhitelist(r.data);
      return r.data;
    }),
    placeholderData: cachedWhitelist || { emails: [], domains: [], ips: [] },
  });

  /* ── Model Metrics (PLSF training report) ────────────────────── */
  const { data: modelMetrics = null } = useQuery({
    queryKey: ['email_model_metrics'],
    queryFn:  () => emailApi.modelMetrics().then(r => r.data).catch(() => null),
    staleTime: 60_000,
  });

  /* ── Mutations ───────────────────────────────────────────────── */
  const updateConfig = useMutation({
    mutationFn: d => emailApi.updateConfig(d),
    onSuccess: (res) => {
      if (res?.data?.config) {
        store.setCachedConfig(res.data.config);
        qc.setQueryData(['email_config'], res.data.config);
      }
      invalidate();
    },
  });

  const resetConfig = useMutation({
    mutationFn: () => emailApi.resetConfig(),
    onSuccess: () => {
      store.setCachedConfig(null);
      invalidate();
    },
  });

  const addToWhitelist = useMutation({
    mutationFn: d => emailApi.addToWhitelist(d),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['email_whitelist'] }),
  });

  const removeFromWhitelist = useMutation({
    mutationFn: ({ type, val }) => emailApi.removeFromWhitelist(type, val),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['email_whitelist'] }),
  });

  return {
    status, config, configSchema, stats, whitelist, modelMetrics,
    updateConfig, resetConfig, addToWhitelist, removeFromWhitelist,
  };
}
