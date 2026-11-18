/**
 * useVPN.js — Centralized React-Query hooks for the VPN (WireGuard) module.
 */
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import vpnApi from '../api/vpnApi';


const DEFAULT_CONFIG = {
  enabled: true, listen_port: 51820, server_ip: '10.99.0.1/24', dns: '', mtu: 1420,
};

const DEFAULT_DIAGNOSTICS = {
  interface_status: 'inactive', port_status: 'closed', crypto_status: 'inactive', ha_status: 'connected',
};

export function useVPN() {
  const qc = useQueryClient();

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['vpn-status'] });
    qc.invalidateQueries({ queryKey: ['vpn-config'] });
    qc.invalidateQueries({ queryKey: ['vpn-peers'] });
    qc.invalidateQueries({ queryKey: ['vpn-sessions'] });
    qc.invalidateQueries({ queryKey: ['vpn-sessions-summary'] });
    qc.invalidateQueries({ queryKey: ['vpn-logs'] });
    qc.invalidateQueries({ queryKey: ['vpn-diagnostics'] });
  };

  // Queries
  const { data: statusData, isLoading: statusLoading } = useQuery({
    queryKey: ['vpn-status'],
    queryFn: () => vpnApi.status().then(r => r.data),
  });

  const status = statusData?.status ?? 'Interface down';
  const interfaceName = statusData?.interface ?? 'wg0';
  const isActive = status !== 'Interface down' && (status.toLowerCase().includes('interface:') || status.toLowerCase().includes('active') || status.toLowerCase().includes('wg'));

  const { data: config = DEFAULT_CONFIG } = useQuery({
    queryKey: ['vpn-config'],
    queryFn: () => vpnApi.config().then(r => r.data),
    placeholderData: DEFAULT_CONFIG,
  });

  const { data: peers = [], isLoading: peersLoading } = useQuery({
    queryKey: ['vpn-peers'],
    queryFn: () => vpnApi.peers().then(r => r.data.peers || []),
    placeholderData: [],
  });

  const { data: sessions = [] } = useQuery({
    queryKey: ['vpn-sessions'],
    queryFn: () => vpnApi.sessions().then(r => r.data.sessions || []),
    placeholderData: [],
    refetchInterval: isActive ? 10000 : false,
  });

  const { data: sessionSummary = { active_sessions: 0 } } = useQuery({
    queryKey: ['vpn-sessions-summary'],
    queryFn: () => vpnApi.sessionSummary().then(r => r.data || { active_sessions: 0 }),
    placeholderData: { active_sessions: 0 },
    refetchInterval: isActive ? 10000 : false,
  });

  const { data: logsData } = useQuery({
    queryKey: ['vpn-logs'],
    queryFn: () => vpnApi.logs().then(r => r.data),
    refetchInterval: isActive ? 10000 : false,
  });

  const vpnLogs = logsData?.logs || [];
  const vpnAlerts = logsData?.alerts || [];

  const { data: diagnostics = DEFAULT_DIAGNOSTICS } = useQuery({
    queryKey: ['vpn-diagnostics'],
    queryFn: () => vpnApi.diagnostics().then(r => r.data || DEFAULT_DIAGNOSTICS),
    placeholderData: DEFAULT_DIAGNOSTICS,
    refetchInterval: isActive ? 10000 : false,
  });

  // Mutations
  const toggleMutation = useMutation({
    mutationFn: () => isActive ? vpnApi.stop() : vpnApi.start(),
    onSuccess: () => {
      setTimeout(invalidate, 600);
    },
  });

  const saveConfig = useMutation({
    mutationFn: (cfg) => vpnApi.updateConfig(cfg),
    onSuccess: invalidate,
  });

  const addPeer = useMutation({
    mutationFn: (peerData) => vpnApi.addPeer(peerData),
    onSuccess: () => {
      invalidate();
    },
  });

  const removePeer = useMutation({
    mutationFn: (pubkey) => vpnApi.removePeer(pubkey),
    onSuccess: () => {
      invalidate();
    },
  });

  const terminateSession = useMutation({
    mutationFn: (sessionId) => vpnApi.terminateSession(sessionId),
    onSuccess: () => {
      invalidate();
    },
  });

  const generateKeys = useMutation({
    mutationFn: () => vpnApi.generateKeys().then(r => r.data),
  });

  return {
    status,
    interfaceName,
    isActive,
    config,
    peers,
    peersLoading,
    sessions,
    sessionSummary,
    vpnLogs,
    vpnAlerts,
    diagnostics,
    isLoading: statusLoading,
    toggleMutation,
    saveConfig,
    addPeer,
    removePeer,
    terminateSession,
    generateKeys,
    refetch: invalidate,
  };
}
