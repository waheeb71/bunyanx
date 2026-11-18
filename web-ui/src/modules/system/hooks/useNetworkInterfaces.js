import { useState, useEffect, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import systemApi from '../api/systemApi';

export function useNetworkInterfaces() {
  const queryClient = useQueryClient();

  const [pendingRoles, setPendingRoles] = useState({});
  const [pendingModes, setPendingModes] = useState({});
  const [stage, setStage] = useState('idle'); // idle | applying | awaiting_confirm | confirmed | error
  const [errorMessage, setErrorMessage] = useState('');

  const interfacesQuery = useQuery({
    queryKey: ['hw-interfaces'],
    queryFn: async () => {
      const res = await systemApi.getInterfaces();
      return res.data?.interfaces || res.data || [];
    },
    refetchInterval: stage === 'idle' ? 8000 : false,
    staleTime: 4000,
    retry: 2,
    placeholderData: (prev) => prev || [],
  });

  const nics = Array.isArray(interfacesQuery.data) ? interfacesQuery.data : [];

  // Initialize local pending states when NIC data arrives if empty
  useEffect(() => {
    if (nics.length && Object.keys(pendingRoles).length === 0) {
      const roles = {};
      const modes = {};
      nics.forEach((n) => {
        roles[n.mac] = n.role || 'unassigned';
        modes[n.mac] = 'dhcp';
      });
      setPendingRoles(roles);
      setPendingModes(modes);
    }
  }, [nics]);

  const applyMutation = useMutation({
    mutationFn: (assignments) => systemApi.assignInterfaces(assignments),
    onSuccess: () => setStage('awaiting_confirm'),
    onError: (err) => {
      setStage('error');
      setErrorMessage(err.response?.data?.detail || 'فشل تطبيق الإعدادات.');
    },
  });

  const confirmMutation = useMutation({
    mutationFn: () => systemApi.confirmInterfaces(),
    onSuccess: () => {
      setStage('confirmed');
      queryClient.invalidateQueries({ queryKey: ['hw-interfaces'] });
      setTimeout(() => setStage('idle'), 3500);
    },
    onError: (err) => {
      setStage('error');
      setErrorMessage(err.response?.data?.detail || 'فشل تأكيد التغييرات.');
    },
  });

  const handleApply = useCallback(() => {
    const assignments = Object.entries(pendingRoles)
      .filter(([mac]) => {
        const nic = nics.find((n) => n.mac === mac);
        return nic && !nic.locked;
      })
      .map(([mac, role]) => ({
        mac,
        role,
        mode: pendingModes[mac] || 'dhcp',
      }));

    setStage('applying');
    applyMutation.mutate({ assignments });
  }, [pendingRoles, pendingModes, nics, applyMutation]);

  const hasChanges = nics.some((n) => {
    if (n.locked) return false;
    return pendingRoles[n.mac] !== (n.role || 'unassigned');
  });

  const updateRole = (mac, role) => {
    setPendingRoles((prev) => ({ ...prev, [mac]: role }));
  };

  const updateMode = (mac, mode) => {
    setPendingModes((prev) => ({ ...prev, [mac]: mode }));
  };

  return {
    nics,
    isLoading: interfacesQuery.isLoading,
    isError: interfacesQuery.isError,
    pendingRoles,
    pendingModes,
    stage,
    errorMessage,
    hasChanges,
    updateRole,
    updateMode,
    handleApply,
    confirmChanges: () => confirmMutation.mutate(),
    cancelChanges: () => {
      setStage('idle');
      queryClient.invalidateQueries({ queryKey: ['hw-interfaces'] });
    },
  };
}
