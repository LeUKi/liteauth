import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Link, Outlet, useLocation, useNavigate } from '@tanstack/react-router';
import { LogOut } from 'lucide-react';
import { api, errorMessage } from '../lib/api';
import { useSession } from '../lib/session';
import { Button, Notice } from './ui';

const repositoryUrl = 'https://github.com/LeUKi/liteauth';

export function SiteFooter() {
  return (
    <footer className="site-footer" aria-label="站点信息">
      <span className="site-footer-segment"><a href={repositoryUrl} target="_blank" rel="noopener noreferrer">LiteAuth</a></span>
      <span className="site-footer-segment"><span aria-hidden="true">· </span>Made with ❤️ by lafish</span>
      <span className="site-footer-segment"><span aria-hidden="true">· </span>v{__LITEAUTH_VERSION__}</span>
      <span className="site-footer-segment"><span aria-hidden="true">· </span>build @ {__LITEAUTH_BUILD_TIME__}</span>
    </footer>
  );
}

export function Layout() {
  const session = useSession();
  const user = session.data?.user;
  const pathname = useLocation({ select: (location) => location.pathname });
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const logout = useMutation({
    mutationFn: api.logout,
    onSuccess: async () => {
      queryClient.clear();
      await navigate({ to: '/login', search: {}, replace: true });
    },
  });
  const authorizationPage = pathname === '/login' || pathname === '/consent';
  return (
    <>
      <a className="skip-link" href="#main">跳到内容</a>
      <header className="topbar">
        <div className="topbar-inner">
          <Link to="/" className="wordmark" aria-label="LiteAuth 首页">LiteAuth</Link>
          {user && !authorizationPage && (
            <nav className="main-nav" aria-label="主导航">
              <Link to="/apps" activeProps={{ className: 'active' }}>LiteAuth 应用</Link>
              <Link to="/credentials" activeProps={{ className: 'active' }}>Connect 密钥</Link>
              {user.is_admin && <Link to="/admin" activeProps={{ className: 'active' }}>管理</Link>}
            </nav>
          )}
          <div className="account-menu">
            {user && (
              <>
                <span className="account-name" title={user.username}>{user.username}</span>
                <Button variant="ghost" className="button-icon" busy={logout.isPending} onClick={() => logout.mutate()} aria-label="退出登录" title="退出登录">
                  {!logout.isPending && <LogOut size={17} />}
                </Button>
              </>
            )}
          </div>
        </div>
      </header>
      {logout.isError && <div className="global-notice"><Notice>{errorMessage(logout.error)}</Notice></div>}
      <Outlet />
    </>
  );
}
