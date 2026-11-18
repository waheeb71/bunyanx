/**
 * useIDSIPS.js — Centralized React-Query hooks for the IDS/IPS module.
 * All data queries, mutations, and status derivations live here.
 */
import { useState, useMemo, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { idsApi, firewallApi } from '../../../services/api';
import { useLiveFeedStore } from '../../../stores/liveFeedStore';
import api from '../../../services/apiClient';

const DEFAULT_TRAPS = [
  { label: 'فحص المنافذ (SSH Banner)', value: 'SSH-2.0-OpenSSH_7.2p2 (VULNERABLE)' },
  { label: 'فحص قاعدة البيانات', value: '5.5.99-MariaDB-log (HONEYPOT)' },
  { label: 'فخ HTTP (Apache Banner)', value: 'Apache/2.2.15 (CentOS) (EXPOSED)' },
  { label: 'فخ SMTP (Mail Server)', value: 'Postfix SMTP 2.1.1 (LEGACY)' },
];

export function useIDSIPS() {
  const qc = useQueryClient();

  // Tab State Persistence
  const [tab, setTabState] = useState(() => {
    try {
      return sessionStorage.getItem('ids_ips_active_tab') || 'alerts';
    } catch {
      return 'alerts';
    }
  });

  const setTab = useCallback((newTab) => {
    setTabState(newTab);
    try {
      sessionStorage.setItem('ids_ips_active_tab', newTab);
    } catch {}
  }, []);

  // Notification Toast State
  const [notification, setNotification] = useState(null);

  const notify = useCallback((message, type = 'success') => {
    setNotification({ message, type, id: Date.now() });
    setTimeout(() => setNotification(null), 4000);
  }, []);

  // Timeframe filter (hours back to query)
  const [hours, setHours] = useState(24);

  // Queries: DB Persistent Alerts
  const { data: dbAlerts = [], isLoading: alertsLoading, refetch: refetchAlerts } = useQuery({
    queryKey: ['ids-alerts', hours],
    queryFn: () => idsApi.alerts(0, 100, hours).then(r => r.data || []),
    refetchInterval: 10000,
  });

  // Queries: IDS Stats (KPIs)
  const { data: idsStats } = useQuery({
    queryKey: ['ids-stats', hours],
    queryFn: () => api.get('/api/v1/ids_ips/stats', { params: { hours } }).then(r => r.data),
    refetchInterval: 15000,
  });

  // Live WebSocket Feed Alerts
  const allLiveAlerts = useLiveFeedStore(s => s.alertsFeed || []);
  const liveAlerts = useMemo(() => {
    return allLiveAlerts.filter(a => 
      a.event_type === 'ids_ips' || 
      a.event_type === 'ids' || 
      a.event_type === 'ips' || 
      a.category?.toLowerCase().includes('ids') || 
      a.category?.toLowerCase().includes('ips') ||
      a.title?.toLowerCase().includes('ids') ||
      a.title?.toLowerCase().includes('ips')
    );
  }, [allLiveAlerts]);

  // Combined & Deduplicated Alerts
  const alerts = useMemo(() => {
    const map = new Map();
    // Add DB persistent alerts first
    dbAlerts.forEach(a => {
      const key = a.id ? String(a.id) : `${a.src_ip}-${a.time}-${a.sig_id}`;
      map.set(key, { ...a, is_live: false });
    });
    // Add or override with live WebSocket alerts
    liveAlerts.forEach(a => {
      const key = a.id ? String(a.id) : `${a.src_ip || a.source_ip}-${a.time || 'now'}-${a.sig_id || 0}`;
      map.set(key, {
        id: a.id || key,
        sig_id: a.sig_id || a.signature_id || 100001,
        sample_id: a.sample_id || '',
        category: a.category || a.title || 'IDS/IPS Event',
        severity: (a.severity || 'info').toLowerCase(),
        src_ip: a.src_ip || a.source_ip || '0.0.0.0',
        dst_ip: a.dst_ip || a.destination_ip || '0.0.0.0',
        proto: a.proto || a.protocol || 'TCP',
        time: a.time || new Date().toLocaleTimeString('ar-EG', { hour12: false }),
        is_live: true,
      });
    });
    return Array.from(map.values()).sort((a, b) => (b.id > a.id ? 1 : -1));
  }, [dbAlerts, liveAlerts]);

  // Queries: Module Config
  const { data: config } = useQuery({
    queryKey: ['ids-config'],
    queryFn: () => idsApi.getConfig().then(r => r.data),
    refetchInterval: 10000,
  });

  // Queries: PHANTOM Status
  const { data: phantomStatus } = useQuery({
    queryKey: ['phantom-status'],
    queryFn: () => idsApi.phantomStatus().then(r => r.data),
    refetchInterval: 5000,
  });

  // Queries: PHANTOM Drift
  const { data: phantomDrift } = useQuery({
    queryKey: ['phantom-drift'],
    queryFn: () => idsApi.phantomDrift().then(r => r.data),
    refetchInterval: 5000,
  });

  // Queries: Deception Traps
  const { data: traps = [] } = useQuery({
    queryKey: ['deception-traps'],
    queryFn: () => idsApi.deceptionTraps().then(r => r.data),
    placeholderData: DEFAULT_TRAPS,
  });

  // Queries: IPS Signatures
  const { data: rules = [], isFetching: rulesLoading } = useQuery({
    queryKey: ['ids-rules'],
    queryFn: () => idsApi.rules().then(r => r.data),
    placeholderData: [],
  });

  // Mutations
  const blockMutation = useMutation({
    mutationFn: ({ ip, reason }) => firewallApi.blockIp(ip, reason, 3600),
    onSuccess: (_, vars) => {
      notify(`تم حجب عنوان IP: ${vars.ip} بنجاح عبر Firewall/eBPF`, 'success');
      qc.invalidateQueries({ queryKey: ['blocked-ips'] });
    },
    onError: (err) => {
      notify(`فشل حجب IP: ${err.response?.data?.detail || err.message}`, 'error');
    }
  });

  const feedbackMutation = useMutation({
    mutationFn: ({ sampleId, label, isCorrect }) => idsApi.feedback(sampleId, label, isCorrect).then(r => r.data),
    onSuccess: () => {
      notify('تم إرسال التقييم بنجاح لمُحرك التعلم المستمر OCL', 'success');
      qc.invalidateQueries({ queryKey: ['phantom-drift'] });
    },
    onError: (err) => {
      notify(`فشل إرسال التقييم: ${err.response?.data?.detail || err.message}`, 'error');
    }
  });

  const updateConfig = useMutation({
    mutationFn: (d) => idsApi.updateConfig(d).then(r => r.data),
    onSuccess: () => {
      notify('تم تحديث إعدادات محرك IDS/IPS بنجاح', 'success');
      qc.invalidateQueries({ queryKey: ['ids-config'] });
    },
    onError: (err) => {
      notify(`فشل تحديث الإعدادات: ${err.response?.data?.detail || err.message}`, 'error');
    }
  });

  const createRule = useMutation({
    mutationFn: (d) => idsApi.createRule(d).then(r => r.data),
    onSuccess: () => {
      notify('تمت إضافة توقيع IPS الجديد بنجاح', 'success');
      qc.invalidateQueries({ queryKey: ['ids-rules'] });
    },
    onError: (err) => {
      notify(`فشل إضافة التوقيع: ${err.response?.data?.detail || err.message}`, 'error');
    }
  });

  const deleteRule = useMutation({
    mutationFn: (id) => idsApi.deleteRule(id),
    onSuccess: () => {
      notify('تم حذف توقيع IPS بنجاح', 'success');
      qc.invalidateQueries({ queryKey: ['ids-rules'] });
    },
    onError: (err) => {
      notify(`فشل حذف التوقيع: ${err.response?.data?.detail || err.message}`, 'error');
    }
  });

  const cfg = config ?? { mode: 'monitoring', is_active: true };
  const critical = idsStats?.critical ?? alerts.filter(a => a.severity === 'critical').length;
  const warning = (idsStats?.high ?? 0) + alerts.filter(a => a.severity === 'warning').length;
  const isBlocking = cfg.mode === 'blocking';

  return {
    tab,
    setTab,
    hours,
    setHours,
    idsStats,
    alerts,
    alertsLoading,
    refetchAlerts,
    cfg,
    phantomStatus,
    phantomDrift,
    traps,
    rules,
    rulesLoading,
    critical,
    warning,
    isBlocking,
    notification,
    notify,
    blockMutation,
    feedbackMutation,
    updateConfig,
    createRule,
    deleteRule,
  };
}
