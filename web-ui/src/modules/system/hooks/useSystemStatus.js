import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import systemApi from '../api/systemApi';

export function useSystemStatus() {
  const queryClient = useQueryClient();

  const statusQuery = useQuery({
    queryKey: ['system-status'],
    queryFn: async () => {
      const res = await systemApi.getStatus();
      return res.data;
    },
    refetchInterval: 4000,
    staleTime: 2000,
    retry: 2,
  });

  const modulesQuery = useQuery({
    queryKey: ['system-modules'],
    queryFn: async () => {
      const res = await systemApi.getModules();
      return res.data;
    },
    staleTime: 10000,
    retry: 2,
  });

  const toggleModuleMutation = useMutation({
    mutationFn: ({ name, enabled }) => systemApi.toggleModule(name, enabled),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['system-modules'] });
      queryClient.invalidateQueries({ queryKey: ['system-status'] });
    },
  });

  const haSyncMutation = useMutation({
    mutationFn: () => systemApi.syncHa(),
  });

  return {
    status: statusQuery.data || {},
    isStatusLoading: statusQuery.isLoading,
    isStatusError: statusQuery.isError,
    statusError: statusQuery.error,
    refetchStatus: statusQuery.refetch,

    modules: modulesQuery.data || {},
    isModulesLoading: modulesQuery.isLoading,

    toggleModule: toggleModuleMutation.mutateAsync,
    isToggling: toggleModuleMutation.isPending,

    syncHa: haSyncMutation.mutateAsync,
    isSyncingHa: haSyncMutation.isPending,
  };
}

export function useOtaUpdate() {
  const checkUpdateQuery = useQuery({
    queryKey: ['ota-check'],
    queryFn: async () => {
      const res = await systemApi.checkUpdate();
      return res.data;
    },
    enabled: false, // Explicit trigger
    retry: false,
  });

  const applyUpdateMutation = useMutation({
    mutationFn: (data) => systemApi.applyUpdate(data),
  });

  const updateHistoryQuery = useQuery({
    queryKey: ['ota-history'],
    queryFn: async () => {
      const res = await systemApi.getUpdateHistory();
      return res.data;
    },
    enabled: false,
  });

  return {
    checkResult: checkUpdateQuery.data,
    isChecking: checkUpdateQuery.isFetching,
    checkError: checkUpdateQuery.error,
    runCheck: checkUpdateQuery.refetch,

    applyUpdate: applyUpdateMutation.mutateAsync,
    isApplying: applyUpdateMutation.isPending,

    historyLog: updateHistoryQuery.data,
    fetchHistory: updateHistoryQuery.refetch,
  };
}
