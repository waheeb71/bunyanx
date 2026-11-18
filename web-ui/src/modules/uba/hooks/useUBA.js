import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { ubaApi } from '../api/ubaApi';

export function useUBA() {
  const qc = useQueryClient();
  const [tab, setTab] = useState('dashboard');
  const [selectedUser, setSelectedUser] = useState(null);
  const [userSearch, setUserSearch] = useState('');

  // Demo simulation states
  const [demoUsername, setDemoUsername] = useState('admin');
  const [demoService, setDemoService] = useState('SSH:22');
  const [demoRiskScore, setDemoRiskScore] = useState(0.85);
  const [demoAccessResult, setDemoAccessResult] = useState(null);
  const [demoLabyrinthResult, setDemoLabyrinthResult] = useState(null);
  const [demoLoading, setDemoLoading] = useState(false);

  const handleSimulateAccess = async () => {
    setDemoLoading(true);
    setDemoAccessResult(null);
    setDemoLabyrinthResult(null);
    try {
      const res = await ubaApi.demoFileAccess({
        username: demoUsername,
        target_service: demoService,
        simulated_risk_score: parseFloat(demoRiskScore)
      });
      setDemoAccessResult(res.data);
    } catch (err) {
      setDemoAccessResult({ error: err.response?.data?.detail || 'فشلت عملية المحاكاة' });
    } finally {
      setDemoLoading(false);
    }
  };

  const handleSimulateBaitInteraction = async () => {
    if (!demoAccessResult?.response_data) return;
    setDemoLoading(true);
    try {
      const res = await ubaApi.demoOpenHoneytoken(demoAccessResult.response_data);
      setDemoLabyrinthResult(res.data);
      qc.invalidateQueries({ queryKey: ['uba_status'] });
      qc.invalidateQueries({ queryKey: ['uba_alerts'] });
    } catch (err) {
      setDemoLabyrinthResult({ error: err.response?.data?.detail || 'فشل التفاعل مع الطعم' });
    } finally {
      setDemoLoading(false);
    }
  };

  /* Queries */
  const { data: status }       = useQuery({ queryKey:['uba_status'], queryFn: () => ubaApi.status().then(r=>r.data), refetchInterval:15000 });
  const { data: alerts }       = useQuery({ queryKey:['uba_alerts'], queryFn: () => ubaApi.alerts().then(r=>r.data), refetchInterval:10000 });
  const { data: globalEvents } = useQuery({ queryKey:['uba_global_events'], queryFn: () => ubaApi.events({ limit:50 }).then(r=>r.data), refetchInterval:10000 });
  const { data: usersData }    = useQuery({ queryKey:['uba_users', userSearch], queryFn: () => ubaApi.users({ limit:50, username:userSearch||undefined }).then(r=>r.data) });
  const { data: profile }      = useQuery({ queryKey:['uba_profile', selectedUser], queryFn: () => ubaApi.userProfile(selectedUser).then(r=>r.data), enabled:!!selectedUser });
  const { data: userEvents }   = useQuery({ queryKey:['uba_user_events', selectedUser], queryFn: () => ubaApi.userEvents(selectedUser, { limit:100 }).then(r=>r.data), enabled:!!selectedUser });
  const { data: config }       = useQuery({ queryKey:['uba_config'], queryFn: () => ubaApi.config().then(r=>r.data) });

  /* Mutations */
  const resetMut = useMutation({
    mutationFn: (name) => ubaApi.resetUser(name),
    onSuccess: () => { 
      qc.invalidateQueries({queryKey:['uba_users']}); 
      qc.invalidateQueries({queryKey:['uba_profile', selectedUser]}); 
      qc.invalidateQueries({queryKey:['uba_status']});
      qc.invalidateQueries({queryKey:['uba_global_events']});
      qc.invalidateQueries({queryKey:['uba_alerts']});
    }
  });

  const cfgMut = useMutation({
    mutationFn: (payload) => ubaApi.updateConfig(payload),
    onSuccess: () => {
      qc.invalidateQueries({queryKey:['uba_config']});
      qc.invalidateQueries({queryKey:['uba_status']});
    }
  });

  return {
    tab,
    setTab,
    selectedUser,
    setSelectedUser,
    userSearch,
    setUserSearch,
    demoUsername,
    setDemoUsername,
    demoService,
    setDemoService,
    demoRiskScore,
    setDemoRiskScore,
    demoAccessResult,
    setDemoLabyrinthResult,
    demoLabyrinthResult,
    demoLoading,
    handleSimulateAccess,
    handleSimulateBaitInteraction,
    status,
    alerts,
    globalEvents,
    usersData,
    profile,
    userEvents,
    config,
    onResetUser: (name) => resetMut.mutate(name),
    isResetting: resetMut.isPending,
    onUpdateConfig: (cfg) => cfgMut.mutate(cfg),
    isConfigSaving: cfgMut.isPending,
  };
}

export default useUBA;
