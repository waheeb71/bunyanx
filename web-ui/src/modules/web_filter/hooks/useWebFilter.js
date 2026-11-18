import { useState, useEffect, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { webFilterApi, logManagerApi } from '../../../services/api';

export function useWebFilter() {
  const qc = useQueryClient();
  const [toast, setToast] = useState(null);
  const [liveStreamPaused, setLiveStreamPaused] = useState(false);

  const showToast = useCallback((msg, type = 'success') => {
    setToast({ msg, type, id: Date.now() });
    setTimeout(() => setToast(null), 4000);
  }, []);

  // Queries
  const statusQuery = useQuery({
    queryKey: ['wf_status'],
    queryFn: () => webFilterApi.status().then(r => r.data),
    refetchInterval: 10000,
  });

  const categoriesQuery = useQuery({
    queryKey: ['wf_categories'],
    queryFn: () => webFilterApi.categories().then(r => r.data),
  });

  const domainsQuery = useQuery({
    queryKey: ['wf_domains'],
    queryFn: () => webFilterApi.domains().then(r => r.data),
  });

  const configQuery = useQuery({
    queryKey: ['wf_config'],
    queryFn: () => webFilterApi.config().then(r => r.data),
  });

  const logsQuery = useQuery({
    queryKey: ['wf_logs'],
    queryFn: () => logManagerApi.searchEvents({ category: 'WEB_FILTER', limit: 100 }).then(r => {
      const evts = r.data?.events || r.data?.data || r.data || [];
      return Array.isArray(evts) ? evts : [];
    }),
    refetchInterval: liveStreamPaused ? false : 3000,
  });

  // Mutations
  const addDomainMut = useMutation({
    mutationFn: (d) => webFilterApi.addDomain(d),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['wf_domains'] });
      qc.invalidateQueries({ queryKey: ['wf_status'] });
      showToast('تمت إضافة قاعدة تجاوز النطاق بنجاح');
    },
    onError: (err) => {
      showToast('فشل إضافة النطاق: ' + (err.response?.data?.detail || err.message), 'error');
    }
  });

  const deleteDomainMut = useMutation({
    mutationFn: (id) => webFilterApi.deleteDomain(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['wf_domains'] });
      qc.invalidateQueries({ queryKey: ['wf_status'] });
      showToast('تم حذف قاعدة تجاوز النطاق');
    },
    onError: (err) => {
      showToast('فشل حذف القاعدة: ' + (err.response?.data?.detail || err.message), 'error');
    }
  });

  const addCatMut = useMutation({
    mutationFn: (d) => webFilterApi.addCategory(d),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['wf_categories'] });
      qc.invalidateQueries({ queryKey: ['wf_status'] });
      showToast('تم إضافة التصنيف المخصص بنجاح');
    },
    onError: (err) => {
      showToast('فشل إضافة التصنيف: ' + (err.response?.data?.detail || err.message), 'error');
    }
  });

  const deleteCatMut = useMutation({
    mutationFn: (id) => webFilterApi.deleteCategory(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['wf_categories'] });
      qc.invalidateQueries({ queryKey: ['wf_status'] });
      showToast('تم حذف التصنيف المخصص');
    },
    onError: (err) => {
      showToast('فشل حذف التصنيف: ' + (err.response?.data?.detail || err.message), 'error');
    }
  });

  const updateCatMut = useMutation({
    mutationFn: ({ id, d }) => webFilterApi.updateCategory(id, d),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['wf_categories'] });
      showToast('تم تحديث إجراء السياسة بنجاح');
    },
    onError: (err) => {
      showToast('فشل تحديث التصنيف: ' + (err.response?.data?.detail || err.message), 'error');
    }
  });

  const updateConfigMut = useMutation({
    mutationFn: (d) => webFilterApi.updateConfig(d),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['wf_config'] });
      qc.invalidateQueries({ queryKey: ['wf_status'] });
      showToast('تم تحديث الإعدادات العامة للمحرك');
    },
    onError: (err) => {
      showToast('فشل تحديث الإعدادات: ' + (err.response?.data?.detail || err.message), 'error');
    }
  });

  const trainMut = useMutation({
    mutationFn: () => webFilterApi.train(),
    onSuccess: () => {
      showToast('تم إرسال طلب إعادة تدريب النموذج بالخلفية بنجاح.');
      setTimeout(() => {
        qc.invalidateQueries({ queryKey: ['wf_status'] });
      }, 3000);
    },
    onError: (err) => {
      showToast('فشلت عملية بدء التدريب: ' + (err.response?.data?.detail || err.message), 'error');
    }
  });

  return {
    status: statusQuery.data || {},
    statusLoading: statusQuery.isLoading,
    categories: categoriesQuery.data || [],
    categoriesLoading: categoriesQuery.isLoading,
    domains: domainsQuery.data || [],
    domainsLoading: domainsQuery.isLoading,
    config: configQuery.data || {},
    configLoading: configQuery.isLoading,
    logs: logsQuery.data || [],
    logsLoading: logsQuery.isLoading,
    refetchLogs: logsQuery.refetch,

    liveStreamPaused,
    setLiveStreamPaused,
    toast,
    showToast,

    addDomain: addDomainMut.mutateAsync,
    addingDomain: addDomainMut.isPending,
    deleteDomain: deleteDomainMut.mutateAsync,
    deletingDomain: deleteDomainMut.isPending,
    addCategory: addCatMut.mutateAsync,
    addingCategory: addCatMut.isPending,
    deleteCategory: deleteCatMut.mutateAsync,
    updateCategory: updateCatMut.mutateAsync,
    updateConfig: updateConfigMut.mutateAsync,
    updatingConfig: updateConfigMut.isPending,
    trainModel: trainMut.mutateAsync,
    trainingModel: trainMut.isPending,
  };
}
