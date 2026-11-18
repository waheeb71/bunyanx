import { useQuery } from '@tanstack/react-query';
import { netopsApi } from '../api/netopsApi';

export function useNetOps() {
  const socketsQuery = useQuery({
    queryKey: ['netops-sockets'],
    queryFn: () => netopsApi.sockets().then(r => r.data),
    refetchInterval: 3000,
    staleTime: 0
  });

  const connectionsQuery = useQuery({
    queryKey: ['netops-connections'],
    queryFn: () => netopsApi.connections().then(r => r.data),
    refetchInterval: 3000,
    staleTime: 0
  });

  const portsQuery = useQuery({
    queryKey: ['netops-ports'],
    queryFn: () => netopsApi.ports().then(r => r.data),
    refetchInterval: 3000,
    staleTime: 0
  });

  const modulesQuery = useQuery({
    queryKey: ['netops-modules'],
    queryFn: () => netopsApi.modules().then(r => r.data),
    refetchInterval: 3000,
    staleTime: 0
  });

  const eventbusQuery = useQuery({
    queryKey: ['netops-eventbus'],
    queryFn: () => netopsApi.eventbus().then(r => r.data),
    refetchInterval: 3000,
    staleTime: 0
  });

  const websocketsQuery = useQuery({
    queryKey: ['netops-websockets'],
    queryFn: () => netopsApi.websockets().then(r => r.data),
    refetchInterval: 3000,
    staleTime: 0
  });

  const refetchAll = () => {
    socketsQuery.refetch();
    connectionsQuery.refetch();
    portsQuery.refetch();
    modulesQuery.refetch();
    eventbusQuery.refetch();
    websocketsQuery.refetch();
  };

  return {
    sockets: socketsQuery.data || {},
    socketsLoading: socketsQuery.isLoading,
    connections: connectionsQuery.data?.connections || [],
    connectionsLoading: connectionsQuery.isLoading,
    ports: portsQuery.data?.ports || [],
    portsLoading: portsQuery.isLoading,
    modules: modulesQuery.data?.modules || [],
    modulesCount: modulesQuery.data?.count || 0,
    modulesLoading: modulesQuery.isLoading,
    eventbus: eventbusQuery.data || {},
    eventbusLoading: eventbusQuery.isLoading,
    websockets: websocketsQuery.data || {},
    websocketsLoading: websocketsQuery.isLoading,
    refetchAll,
  };
}
