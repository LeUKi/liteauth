import { useQuery } from '@tanstack/react-query';
import { api, queryKeys } from './api';

export function useSession() {
  return useQuery({
    queryKey: queryKeys.session,
    queryFn: ({ signal }) => api.session(signal),
    staleTime: 30_000,
    retry: false,
  });
}
