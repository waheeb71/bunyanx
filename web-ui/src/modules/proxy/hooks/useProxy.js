import { useQueryClient, useQuery, useMutation } from '@tanstack/react-query';
import { proxyApi } from '../api/proxyApi';

export function useProxy(tab) {
  const qc = useQueryClient();

  const { data: status } = useQuery({
    queryKey: ['proxy_status'],
    queryFn: () => proxyApi.status().then(r => r.data),
    refetchInterval: 8000,
  });

  const { data: config, isLoading: configLoading } = useQuery({
    queryKey: ['proxy_config'],
    queryFn: () => proxyApi.config().then(r => r.data),
  });

  const { data: vips, isLoading: vipsLoading } = useQuery({
    queryKey: ['proxy_vips'],
    queryFn: () => proxyApi.vips().then(r => r.data),
    enabled: tab === 'vips',
  });

  const updateMut = useMutation({
    mutationFn: (data) => proxyApi.updateConfig(data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['proxy_config'] });
      qc.invalidateQueries({ queryKey: ['proxy_status'] });
    },
  });

  const addVipMut = useMutation({
    mutationFn: (data) => proxyApi.addVip(data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['proxy_vips'] }),
  });

  const deleteVipMut = useMutation({
    mutationFn: (name) => proxyApi.deleteVip(name),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['proxy_vips'] }),
  });

  const cfg = config ?? {};
  const isEnabled = cfg.is_active;

  const { data: stats } = useQuery({
    queryKey: ['proxy_stats'],
    queryFn: () => proxyApi.stats().then(r => r.data),
    refetchInterval: 3000,
    enabled: !!isEnabled,
  });

  const { data: sessions } = useQuery({
    queryKey: ['proxy_sessions'],
    queryFn: () => proxyApi.sessions().then(r => r.data),
    refetchInterval: 3000,
    enabled: !!isEnabled && tab === 'sessions',
  });

  return {
    status,
    config: cfg,
    configLoading,
    vips,
    vipsLoading,
    stats,
    sessions,
    updateConfig: updateMut.mutate,
    updateConfigAsync: updateMut.mutateAsync,
    updateConfigPending: updateMut.isPending,
    addVip: addVipMut.mutate,
    addVipAsync: addVipMut.mutateAsync,
    addVipPending: addVipMut.isPending,
    deleteVip: deleteVipMut.mutate,
    deleteVipAsync: deleteVipMut.mutateAsync,
    deleteVipPending: deleteVipMut.isPending,
    pacUrl: proxyApi.getPacUrl(),
    wpadUrl: proxyApi.getWpadUrl(),
  };
}
