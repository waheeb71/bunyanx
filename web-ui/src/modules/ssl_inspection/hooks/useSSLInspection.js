/**
 * useSSLInspection.js — Centralized React-Query hooks for the SSL Inspection module.
 */
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import sslApi from '../api/sslApi';

export function useSSLInspection() {
  const qc = useQueryClient();

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['ssl_policies'] });
    qc.invalidateQueries({ queryKey: ['ssl_certs'] });
    qc.invalidateQueries({ queryKey: ['ssl_stats'] });
    qc.invalidateQueries({ queryKey: ['ssl_logs'] });
    qc.invalidateQueries({ queryKey: ['ssl_status'] });
  };

  // Queries
  const { data: policies = [], isLoading: policiesLoading } = useQuery({
    queryKey: ['ssl_policies'],
    queryFn: () => sslApi.policies().then(r => r.data || []),
    staleTime: 10000,
  });

  const { data: certs = [], isLoading: certsLoading } = useQuery({
    queryKey: ['ssl_certs'],
    queryFn: () => sslApi.certificates().then(r => r.data || []),
    staleTime: 10000,
  });

  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['ssl_stats'],
    queryFn: () => sslApi.statistics().then(r => r.data || {}),
    refetchInterval: 5000,
  });

  const { data: logs = [], isLoading: logsLoading } = useQuery({
    queryKey: ['ssl_logs'],
    queryFn: () => sslApi.logs().then(r => r.data || []).catch(() => []),
    refetchInterval: 5000,
  });

  const { data: status, isLoading: statusLoading } = useQuery({
    queryKey: ['ssl_status'],
    queryFn: () => sslApi.status().then(r => r.data || {}),
    retry: 1,
  });

  // Mutations
  const deletePolicy = useMutation({
    mutationFn: (id) => sslApi.deletePolicy(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ssl_policies'] }),
  });

  const createPolicy = useMutation({
    mutationFn: (form) => sslApi.createPolicy(form).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ssl_policies'] }),
  });

  const uploadCert = useMutation({
    mutationFn: (payload) => sslApi.uploadCert(payload).then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ssl_certs'] }),
  });

  const updateConfig = useMutation({
    mutationFn: (d) => sslApi.updateConfig(d),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ssl_status'] }),
  });

  const inspectedCount = Number(stats?.inspected ?? 0);
  const bypassedCount = Number(stats?.bypassed ?? 0);
  const blockedCount = Number(stats?.blocked ?? 0);
  const totalDecisions = Number(stats?.total_decisions ?? (inspectedCount + bypassedCount + blockedCount));

  // Determine active Root CA
  const activeRootCA = (certs && certs.length > 0)
    ? (certs.find(c => (c.cert_type === 'ROOT_CA' || c.is_ca) && c.is_active) ||
       certs.find(c => c.cert_type === 'ROOT_CA' || c.is_ca) ||
       certs[0])
    : null;

  return {
    policies,
    policiesLoading,
    certs,
    certsLoading,
    stats,
    statsLoading,
    logs,
    logsLoading,
    status,
    statusLoading,
    totalDecisions,
    inspectedCount,
    bypassedCount,
    blockedCount,
    activeRootCA,
    deletePolicy,
    createPolicy,
    uploadCert,
    updateConfig,
    refetch: invalidate,
  };
}

export default useSSLInspection;
