import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { pkiApi } from '../api/pkiApi';
import { useToast } from '../../../components/Toast';
import { usePKIStore } from '../store/usePKIStore';

const daysUntil = (isoDate) => Math.floor((new Date(isoDate) - Date.now()) / 86400000);

export function usePKI() {
  const toast = useToast();
  const queryClient = useQueryClient();
  const {
    searchTerm,
    statusFilter,
    typeFilter,
    sortBy,
    selectedCertId,
    setSelectedCertId,
  } = usePKIStore();

  // 1. Fetch certificate inventory
  const certsQuery = useQuery({
    queryKey: ['certificates'],
    queryFn: async () => {
      const res = await pkiApi.list();
      return res.data.certificates || [];
    },
    staleTime: 30000,
  });

  // 2. Fetch Root CA info
  const caInfoQuery = useQuery({
    queryKey: ['ca-info'],
    queryFn: async () => {
      const res = await pkiApi.caInfo();
      return res.data;
    },
    staleTime: 60000,
  });

  // 3. Issue Device Certificate Mutation
  const generateDeviceMutation = useMutation({
    mutationFn: (data) => pkiApi.generateDevice(data),
    onSuccess: (res, variables) => {
      toast.success(res.data.message || `تم إصدار شهادة لـ ${variables.cn} بنجاح`, 'إصدار شهادة');
      queryClient.invalidateQueries(['certificates']);
    },
    onError: (err) => {
      toast.error(err.response?.data?.detail || 'فشل إصدار الشهادة', 'خطأ في العملية');
    },
  });

  // 4. Renew Certificate Mutation
  const renewMutation = useMutation({
    mutationFn: (id) => pkiApi.renew(id),
    onSuccess: (res, certId) => {
      toast.success(res.data.message || `تم تجديد الشهادة (${certId}) بنجاح`, 'تجديد شهادة');
      queryClient.invalidateQueries(['certificates']);
    },
    onError: (err) => {
      toast.error(err.response?.data?.detail || 'فشل تجديد الشهادة', 'خطأ في التجديد');
    },
  });

  // 5. Revoke Certificate Mutation
  const revokeMutation = useMutation({
    mutationFn: (id) => pkiApi.revoke(id),
    onSuccess: (res, certId) => {
      toast.success(res.data.message || `تم إلغاء الشهادة (${certId}) بنجاح`, 'إلغاء شهادة');
      queryClient.invalidateQueries(['certificates']);
      if (selectedCertId === certId) {
        setSelectedCertId(null);
      }
    },
    onError: (err) => {
      toast.error(err.response?.data?.detail || 'فشل إلغاء الشهادة', 'خطأ في الإلغاء');
    },
  });

  // 6. Generate Root CA Mutation
  const generateCaMutation = useMutation({
    mutationFn: () => pkiApi.generateCa(),
    onSuccess: (res) => {
      toast.success(res.data.message || 'تم إنشاء سلطة التصديق الرئيسية (Root CA) بنجاح', 'إنشاء CA');
      queryClient.invalidateQueries(['ca-info']);
      queryClient.invalidateQueries(['certificates']);
    },
    onError: (err) => {
      toast.error(err.response?.data?.detail || 'فشل إنشاء سلطة التصديق الرئيسية', 'خطأ في الإنشاء');
    },
  });

  // Download CA Cert Blob
  const downloadCa = async (format = 'pem') => {
    try {
      const res = await pkiApi.downloadCa(format);
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `bunyanx-ca.${format}`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      toast.success(`تم تحميل ملف سلطة CA بصيغة ${format.toUpperCase()}`, 'تنزيل الشهادة');
    } catch (err) {
      toast.error(err.response?.data?.detail || 'فشل تنزيل ملف CA', 'خطأ في التنزيل');
    }
  };

  const certs = certsQuery.data || [];

  // Filtered & Sorted certificates
  const filteredCerts = certs.filter((cert) => {
    const days = daysUntil(cert.expiry);
    
    // Status filter
    if (statusFilter === 'VALID' && (days < 30)) return false;
    if (statusFilter === 'EXPIRING' && (days < 0 || days >= 30)) return false;
    if (statusFilter === 'EXPIRED' && days >= 0) return false;

    // Type filter
    if (typeFilter !== 'ALL' && cert.type !== typeFilter) return false;

    // Search filter
    if (searchTerm.trim()) {
      const q = searchTerm.toLowerCase();
      const cn = (cert.cn || '').toLowerCase();
      const issuer = (cert.issuer || '').toLowerCase();
      const usage = (cert.usage || '').toLowerCase();
      return cn.includes(q) || issuer.includes(q) || usage.includes(q);
    }

    return true;
  });

  // Sort
  const sortedCerts = [...filteredCerts].sort((a, b) => {
    if (sortBy === 'cn') return (a.cn || '').localeCompare(b.cn || '');
    if (sortBy === 'issuer') return (a.issuer || '').localeCompare(b.issuer || '');
    if (sortBy === 'type') return (a.type || '').localeCompare(b.type || '');
    // Default: soonest expiry first
    return new Date(a.expiry || '9999-12-31') - new Date(b.expiry || '9999-12-31');
  });

  const selectedCert = certs.find((c) => c.id === selectedCertId) || null;

  return {
    certs: sortedCerts,
    rawCerts: certs,
    selectedCert,
    isLoading: certsQuery.isLoading,
    isRefetching: certsQuery.isRefetching,
    error: certsQuery.error,
    refetch: certsQuery.refetch,

    caInfo: caInfoQuery.data,
    isCaLoading: caInfoQuery.isLoading,

    generateDeviceMutation,
    renewMutation,
    revokeMutation,
    generateCaMutation,
    downloadCa,
    daysUntil,
  };
}
