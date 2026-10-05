import { Navigate } from '@tanstack/react-router';
import type { ReactNode } from 'react';
import { useSession } from '../lib/session';
import { Loading, Page, QueryError } from './ui';

export function AuthGuard({ children, admin = false, request }: { children: ReactNode; admin?: boolean; request?: string }) {
  const session = useSession();
  if (session.isPending) return <Page><Loading /></Page>;
  if (session.isError) return <Page><QueryError error={session.error} retry={session.refetch} /></Page>;
  if (!session.data.user) return <Navigate to="/login" search={request ? { request } : {}} replace />;
  if (admin && !session.data.user.is_admin) return <Navigate to="/apps" replace />;
  return children;
}
