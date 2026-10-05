import { useMutation, useQuery } from '@tanstack/react-query';
import { Link, Navigate } from '@tanstack/react-router';
import { Check } from 'lucide-react';
import { Button, Loading, Notice, Page, Panel, QueryError } from '../components/ui';
import { api, errorMessage, followRedirect, queryKeys } from '../lib/api';
import { useSession } from '../lib/session';
import { consentRoute } from '../router';

const scopeNames: Record<string, string> = { openid: '账号标识', profile: '用户名与个人资料', email: '邮箱信息' };

export function ConsentPage() {
  const { request } = consentRoute.useSearch();
  const session = useSession();
  const consent = useQuery({ queryKey: queryKeys.consent(request ?? ''), queryFn: ({ signal }) => api.consent.get(request!, signal), enabled: Boolean(request && session.data?.user), staleTime: 0, retry: false });
  const respond = useMutation({ mutationFn: (accept: boolean) => api.consent.respond(request!, accept), onSuccess: followRedirect });
  if (!request) return <Page narrow><Panel><div className="empty-state"><Notice>授权请求无效</Notice><Link to="/" className="button button-secondary">返回首页</Link></div></Panel></Page>;
  if (session.isPending) return <Page narrow><Loading /></Page>;
  if (session.isError) return <Page narrow><QueryError error={session.error} retry={session.refetch} /></Page>;
  if (!session.data.user) return <Navigate to="/login" search={{ request }} replace />;
  const context = consent.data;
  const requiresLite = context?.eligibility.reason === 'lite_required';
  const requiresLevel = context?.eligibility.reason === 'trust_level_required';
  return <Page narrow>{consent.isPending ? <Loading /> : consent.isError ? <QueryError error={consent.error} retry={consent.refetch} /> : context && <Panel className="consent-panel"><h1>{context.application.name}</h1><div className="consent-account"><span>@{session.data.user.username}</span><span className="badge">{context.login_method === 'lite_self_app' ? 'Lite 用户登录' : '非 Lite 用户登录'}</span></div><div className="muted">最低等级：{context.application.min_trust_level} 级 · 当前已验证等级：{context.eligibility.trust_level ?? '—'} 级</div>
    {!context.eligibility.allowed ? <div className="stack"><Notice kind="neutral">{requiresLite ? '此应用仅允许 Lite 用户登录' : requiresLevel ? `此应用要求等级达到 ${context.application.min_trust_level} 级；当前已验证等级：${context.eligibility.trust_level ?? '—'} 级` : '请重新登录后授权'}</Notice><Link to="/login" search={{ request }} className="button button-primary">{requiresLite ? '使用 Lite 登录' : requiresLevel ? '重新验证' : '重新登录'}</Link></div> : <><h2 className="consent-subtitle">允许访问</h2><ul className="scope-list">{context.scopes.filter((scope, index, scopes) => scopes.indexOf(scope) === index).map((scope) => <li key={scope}><Check size={16} aria-hidden="true" /><span>{scopeNames[scope] ?? scope}</span></li>)}</ul>{respond.isError && <Notice>{errorMessage(respond.error)}</Notice>}<div className="consent-actions"><Button variant="secondary" disabled={respond.isPending || consent.isFetching} onClick={() => respond.mutate(false)}>拒绝</Button><Button busy={respond.isPending && respond.variables === true} disabled={respond.isPending || consent.isFetching} onClick={() => respond.mutate(true)}>允许</Button></div></>}
  </Panel>}</Page>;
}
