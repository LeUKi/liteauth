import type { AppInput } from '@liteauth/contracts';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link, useLocation, useNavigate } from '@tanstack/react-router';
import { ArrowLeft, RotateCw } from 'lucide-react';
import { useEffect, useState } from 'react';
import { AppForm } from '../components/app-form';
import { LoginRecords } from '../components/login-records';
import { ReturnedFields } from '../components/returned-fields';
import { Button, Confirm, Loading, Notice, Page, PageHeading, Panel, QueryError, SecretValue, ValueRow } from '../components/ui';
import { ApiFailure, api, errorMessage, queryKeys } from '../lib/api';
import { appDetailRoute } from '../router';

export function AppDetailPage() {
  const { id } = appDetailRoute.useParams();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const hash = useLocation({ select: (location) => location.hash });
  const [saved, setSaved] = useState(false);
  const detail = useQuery({ queryKey: queryKeys.app(id), queryFn: ({ signal }) => api.apps.get(id, signal) });
  useEffect(() => {
    if (detail.data?.app.id && hash === 'login-records') document.getElementById('login-records')?.scrollIntoView({ block: 'start' });
  }, [detail.data?.app.id, hash]);
  const secret = useQuery({ queryKey: queryKeys.appSecret(id), queryFn: ({ signal }) => api.apps.secret(id, signal), enabled: detail.data?.app.client_type === 'confidential', gcTime: 0, staleTime: 0, retry: false });
  const update = useMutation({
    mutationFn: (input: AppInput) => api.apps.update(id, input),
    onMutate: () => setSaved(false),
    onSuccess: async (result) => {
      queryClient.setQueryData(queryKeys.app(id), { app: result.app });
      await queryClient.invalidateQueries({ queryKey: queryKeys.apps });
      await queryClient.invalidateQueries({ queryKey: ['login-context'] });
      setSaved(true);
    },
  });
  const remove = useMutation({ mutationFn: () => api.apps.delete(id), onSuccess: async () => { await queryClient.invalidateQueries({ queryKey: queryKeys.apps }); queryClient.removeQueries({ queryKey: queryKeys.app(id) }); queryClient.removeQueries({ queryKey: queryKeys.appSecret(id) }); await navigate({ to: '/apps' }); } });
  const rotate = useMutation({
    mutationFn: async () => {
      await api.apps.rotateSecret(id);
      await queryClient.resetQueries({ queryKey: queryKeys.appSecret(id), exact: true });
    },
  });
  const app = detail.data?.app;
  return <Page><PageHeading title={app?.name ?? '应用设置'} back={<Link to="/apps" className="back-link"><ArrowLeft size={15} />LiteAuth 应用</Link>} />{detail.isPending ? <Loading /> : detail.isError ? <QueryError error={detail.error} retry={detail.refetch} /> : app && <div className="stack section-stack">
    {app.disabled && <Notice kind="neutral">此应用已停用</Notice>}
    <Panel><div className="panel-heading"><h2>LiteAuth 应用凭据</h2><span className="badge">{app.client_type === 'confidential' ? '服务端应用' : '浏览器 / 原生应用'}</span></div><ValueRow label="Client ID" value={app.client_id} copy />{app.client_type === 'confidential' && <>
      {secret.isPending || rotate.isPending ? <div className="value-row"><span className="value-label">Client Secret</span><span className="muted" role="status">正在读取</span></div> : secret.isError ? <div className="stack compact-stack"><Notice>{secret.error instanceof ApiFailure && secret.error.status === 403 ? '仅应用所有者可查看密钥' : errorMessage(secret.error)}</Notice>{!(secret.error instanceof ApiFailure && secret.error.status === 403) && <Button variant="secondary" onClick={() => void secret.refetch()}>重新读取密钥</Button>}</div> : secret.data.status === 'available' && secret.data.client_secret ? <SecretValue value={secret.data.client_secret} /> : secret.data.status === 'legacy_unavailable' ? <div className="value-row"><span className="value-label">Client Secret</span><span className="muted">轮换后可查看密钥</span></div> : null}
      {!(secret.error instanceof ApiFailure && secret.error.status === 403) && <div className="panel-footer"><Confirm title="轮换应用密钥？" description="旧密钥将立即失效，请同步更新接入网站。" confirmLabel="轮换密钥" onConfirm={() => rotate.mutateAsync()}><Button variant="secondary" busy={rotate.isPending} disabled={app.disabled || secret.isPending}><RotateCw size={15} />轮换密钥</Button></Confirm></div>}
    </>}</Panel>
    <Panel><div className="panel-heading"><h2>应用设置</h2></div>{saved && <Notice kind="success">已保存</Notice>}<AppForm app={app} onSubmit={(input) => update.mutate(input)} pending={update.isPending} error={update.error} /></Panel>
    <Panel><div className="panel-heading"><h2>接入地址</h2></div><ValueRow label="授权地址" value={new URL('/api/auth/oauth2/authorize', window.location.origin).href} copy /><ValueRow label="Token 地址" value={new URL('/api/auth/oauth2/token', window.location.origin).href} copy /><ValueRow label="OAuth 用户信息地址" value={new URL('/api/user', window.location.origin).href} copy /><ValueRow label="OIDC 用户信息地址" value={new URL('/api/auth/oauth2/userinfo', window.location.origin).href} copy /><ValueRow label="OpenID 配置" value={new URL('/api/auth/.well-known/openid-configuration', window.location.origin).href} copy /></Panel>
    <ReturnedFields />
    <LoginRecords appId={id} />
    <Panel className="danger-panel"><div><h2>删除应用</h2></div><Confirm title="删除 LiteAuth 应用？" description="应用及其授权将失效，接入网站将无法继续使用此应用登录。" confirmLabel="删除应用" onConfirm={() => remove.mutateAsync()}><Button variant="danger">删除应用</Button></Confirm></Panel>
  </div>}</Page>;
}
