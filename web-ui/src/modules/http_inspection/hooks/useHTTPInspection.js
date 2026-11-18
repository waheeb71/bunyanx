import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { httpApi } from '../api/httpApi';

export function useHTTPInspection() {
  const qc = useQueryClient();

  // Queries
  const patternsQuery = useQuery({
    queryKey: ['http_patterns'],
    queryFn: () => httpApi.patterns().then(r => r.data),
  });

  const configQuery = useQuery({
    queryKey: ['http_config'],
    queryFn: () => httpApi.config().then(r => r.data),
  });

  const logsQuery = useQuery({
    queryKey: ['http_logs'],
    queryFn: () => httpApi.logs().then(r => r.data),
    refetchInterval: 5000
  });

  // Mutations
  const updateConfigMut = useMutation({
    mutationFn: (d) => httpApi.updateConfig(d),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['http_config'] }),
  });

  const addPatternMut = useMutation({
    mutationFn: (d) => httpApi.addPattern(d),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['http_patterns'] }),
  });

  const deletePatternMut = useMutation({
    mutationFn: (id) => httpApi.deletePattern(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['http_patterns'] }),
  });

  const updatePatternMut = useMutation({
    mutationFn: ({ id, data }) => httpApi.updatePattern(id, data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['http_patterns'] }),
  });

  return {
    patterns: patternsQuery.data || [],
    patternsLoading: patternsQuery.isLoading,
    refetchPatterns: patternsQuery.refetch,

    config: configQuery.data || {},
    configLoading: configQuery.isLoading,
    refetchConfig: configQuery.refetch,

    logs: logsQuery.data || [],
    logsLoading: logsQuery.isLoading,
    refetchLogs: logsQuery.refetch,

    updateConfig: updateConfigMut.mutateAsync,
    updatingConfig: updateConfigMut.isPending,
    addPattern: addPatternMut.mutateAsync,
    addingPattern: addPatternMut.isPending,
    deletePattern: deletePatternMut.mutateAsync,
    deletingPattern: deletePatternMut.isPending,
    updatePattern: updatePatternMut.mutateAsync,
    updatingPattern: updatePatternMut.isPending,
  };
}

