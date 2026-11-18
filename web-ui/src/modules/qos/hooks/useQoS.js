import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { qosApi } from '../api/qosApi';

const EMPTY_OBJ = {};

export function useQoS() {
  const qc = useQueryClient();

  // Queries
  const statusQuery = useQuery({
    queryKey: ['qos_status'],
    queryFn: () => qosApi.status().then(r => r.data),
    refetchInterval: 5000,
    staleTime: 4000,
  });

  const configQuery = useQuery({
    queryKey: ['qos_config'],
    queryFn: () => qosApi.config().then(r => r.data),
    staleTime: 10000,
  });

  const statsQuery = useQuery({
    queryKey: ['qos_stats'],
    queryFn: () => qosApi.stats().then(r => r.data),
    refetchInterval: 5000,
    staleTime: 3000,
  });

  // Mutations
  const resetBucketMut = useMutation({
    mutationFn: (ip) => qosApi.resetBucket(ip),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['qos_stats'] }),
  });

  const updateConfigMut = useMutation({
    mutationFn: (newCfg) => qosApi.updateConfig(newCfg),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['qos_status'] });
      qc.invalidateQueries({ queryKey: ['qos_config'] });
      qc.invalidateQueries({ queryKey: ['qos_stats'] });
    },
  });

  const refetchAll = () => {
    statusQuery.refetch();
    configQuery.refetch();
    statsQuery.refetch();
  };

  return {
    status: statusQuery.data || EMPTY_OBJ,
    statusLoading: statusQuery.isLoading,
    statusError: statusQuery.error,
    
    config: configQuery.data || EMPTY_OBJ,
    configLoading: configQuery.isLoading,
    configError: configQuery.error,

    stats: statsQuery.data || EMPTY_OBJ,
    statsLoading: statsQuery.isLoading,
    statsError: statsQuery.error,

    refetchAll,

    resetBucket: resetBucketMut.mutateAsync,
    resettingBucket: resetBucketMut.isPending,
    updateConfig: updateConfigMut.mutateAsync,
    updatingConfig: updateConfigMut.isPending,
  };
}

