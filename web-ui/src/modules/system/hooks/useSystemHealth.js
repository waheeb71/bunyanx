import { useQuery } from '@tanstack/react-query';
import systemApi from '../api/systemApi';

export function useSystemHealth() {
  const healthQuery = useQuery({
    queryKey: ['system-health-detailed'],
    queryFn: async () => {
      const res = await systemApi.getHealthDetailed();
      return res.data;
    },
    refetchInterval: 5000,
    staleTime: 3000,
    placeholderData: (prev) => prev,
    retry: 2,
  });

  const securityValidationQuery = useQuery({
    queryKey: ['security-validation'],
    queryFn: async () => {
      const res = await systemApi.getSecurityValidation();
      return res.data;
    },
    staleTime: 15000,
    placeholderData: (prev) => prev,
    retry: 2,
  });

  const securityWarningsQuery = useQuery({
    queryKey: ['security-warnings'],
    queryFn: async () => {
      const res = await systemApi.getSecurityWarnings();
      return res.data?.warnings || [];
    },
    staleTime: 15000,
    placeholderData: (prev) => prev,
    retry: 2,
  });

  return {
    health: healthQuery.data || null,
    isHealthLoading: healthQuery.isLoading,
    isHealthError: healthQuery.isError,
    healthError: healthQuery.error,
    refetchHealth: healthQuery.refetch,

    securityValidation: securityValidationQuery.data || null,
    isSecurityLoading: securityValidationQuery.isLoading,

    securityWarnings: securityWarningsQuery.data || [],
    isWarningsLoading: securityWarningsQuery.isLoading,
  };
}
