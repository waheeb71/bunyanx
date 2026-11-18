import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import systemApi from '../api/systemApi';

export function useConfigManager() {
  const queryClient = useQueryClient();
  const [selectedVersion, setSelectedVersion] = useState(null);

  const versionsQuery = useQuery({
    queryKey: ['config-versions'],
    queryFn: async () => {
      const res = await systemApi.getConfigVersions();
      return res.data?.versions || [];
    },
    staleTime: 10000,
    retry: 2,
  });

  const versions = versionsQuery.data || [];
  const activeVersion = versions[0]?.version_id || null;

  const diffQuery = useQuery({
    queryKey: ['config-diff', activeVersion, selectedVersion],
    queryFn: async () => {
      if (!selectedVersion || selectedVersion === activeVersion) return null;
      const res = await systemApi.getConfigDiff(activeVersion, selectedVersion);
      return { target: selectedVersion, changes: res.data?.diff || {} };
    },
    enabled: Boolean(selectedVersion && selectedVersion !== activeVersion),
    staleTime: 30000,
  });

  const rollbackMutation = useMutation({
    mutationFn: (versionId) => systemApi.rollbackConfig(versionId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['config-versions'] });
      queryClient.invalidateQueries({ queryKey: ['system-status'] });
      setSelectedVersion(null);
    },
  });

  const snapshotMutation = useMutation({
    mutationFn: () => systemApi.takeConfigSnapshot(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['config-versions'] });
    },
  });

  return {
    versions,
    activeVersion,
    isVersionsLoading: versionsQuery.isLoading,
    versionsError: versionsQuery.error,
    refetchVersions: versionsQuery.refetch,

    selectedVersion,
    setSelectedVersion,

    diff: diffQuery.data,
    isDiffLoading: diffQuery.isFetching,
    diffError: diffQuery.error,

    rollback: rollbackMutation.mutateAsync,
    isRollingBack: rollbackMutation.isPending,
    rollbackError: rollbackMutation.error,

    takeSnapshot: snapshotMutation.mutateAsync,
    isTakingSnapshot: snapshotMutation.isPending,
  };
}
