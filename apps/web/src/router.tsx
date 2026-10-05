import { createRootRoute, createRoute, createRouter, Navigate } from '@tanstack/react-router';
import { z } from 'zod';
import { AuthGuard } from './components/auth-guard';
import { Layout } from './components/layout';
import { Button, Loading, Page, Panel, QueryError } from './components/ui';
import { useSession } from './lib/session';
import { AdminPage } from './pages/admin';
import { AdminUserDetailPage } from './pages/admin-user-detail';
import { AppDetailPage } from './pages/app-detail';
import { AppsPage } from './pages/apps';
import { ConsentPage } from './pages/consent';
import { CredentialsPage } from './pages/credentials';
import { LoginPage } from './pages/login';

const searchSchema = z.object({ request: z.string().min(1).max(256).optional(), error: z.string().max(128).optional() });

const rootRoute = createRootRoute({
  component: Layout,
  errorComponent: ({ reset }) => <Page narrow><Panel><div className="empty-state"><h1>页面暂不可用</h1><Button variant="secondary" onClick={reset}>重试</Button></div></Panel></Page>,
  notFoundComponent: () => <Page narrow><Panel><div className="empty-state"><h1>页面不存在</h1><Button onClick={() => window.location.assign('/')}>返回首页</Button></div></Panel></Page>,
});

const indexRoute = createRoute({ getParentRoute: () => rootRoute, path: '/', component: IndexPage });
export const loginRoute = createRoute({ getParentRoute: () => rootRoute, path: '/login', validateSearch: (search) => searchSchema.parse(search), component: LoginPage });
export const credentialsRoute = createRoute({ getParentRoute: () => rootRoute, path: '/credentials', validateSearch: (search) => searchSchema.pick({ error: true }).parse(search), component: () => <AuthGuard><CredentialsPage /></AuthGuard> });
const appsRoute = createRoute({ getParentRoute: () => rootRoute, path: '/apps', component: () => <AuthGuard><AppsPage /></AuthGuard> });
export const appDetailRoute = createRoute({ getParentRoute: () => rootRoute, path: '/apps/$id', component: () => <AuthGuard><AppDetailPage /></AuthGuard> });
export const consentRoute = createRoute({ getParentRoute: () => rootRoute, path: '/consent', validateSearch: (search) => searchSchema.pick({ request: true }).parse(search), component: ConsentPage });
const adminRoute = createRoute({ getParentRoute: () => rootRoute, path: '/admin', component: () => <AuthGuard admin><AdminPage /></AuthGuard> });
export const adminUserDetailRoute = createRoute({ getParentRoute: () => rootRoute, path: '/admin/users/$userId', component: () => <AuthGuard admin><AdminUserDetailPage /></AuthGuard> });

function IndexPage() {
  const session = useSession();
  if (session.isPending) return <Page><Loading /></Page>;
  if (session.isError) return <Page><QueryError error={session.error} retry={session.refetch} /></Page>;
  return session.data.user ? <Navigate to="/apps" replace /> : <Navigate to="/login" search={{}} replace />;
}

export const router = createRouter({ routeTree: rootRoute.addChildren([indexRoute, loginRoute, credentialsRoute, appsRoute, appDetailRoute, consentRoute, adminRoute, adminUserDetailRoute]), defaultPreload: 'intent' });

declare module '@tanstack/react-router' {
  interface Register { router: typeof router }
}
