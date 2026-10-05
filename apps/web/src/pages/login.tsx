import { zodResolver } from '@hookform/resolvers/zod';
import { credentialInputSchema, liteLoginSchema } from '@liteauth/contracts';
import type { LiteLoginInput } from '@liteauth/contracts';
import { useMutation, useQuery } from '@tanstack/react-query';
import { Navigate } from '@tanstack/react-router';
import { ArrowRight } from 'lucide-react';
import { useEffect, useState } from 'react';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { ConnectSetup } from '../components/connect-setup';
import { Button, Field, Loading, Notice, Page, Panel } from '../components/ui';
import { ApiFailure, api, errorMessage, followRedirect, queryKeys } from '../lib/api';
import { useSession } from '../lib/session';
import { loginRoute } from '../router';

const callbackErrors: Record<string, string> = {
  access_denied: '登录已取消',
  invalid_state: '登录请求已失效，请重试',
  expired_request: '登录请求已过期，请重新发起',
  credential_invalid: 'Connect 密钥无效，请重新填写',
  credential_changed: '账号信息已更新，请重新开始登录',
  identity_mismatch: '登录账号不一致，请使用对应账号重试',
  user_mismatch: '登录账号不一致，请使用对应账号重试',
  policy_changed: '应用要求已更新，请重新登录',
  trust_level_required: '当前等级不满足应用要求，请重新验证',
};

const hostedLoginSchema = z.object({ username: liteLoginSchema.shape.username, request: liteLoginSchema.shape.request });
const manualLoginSchema = credentialInputSchema.extend(hostedLoginSchema.shape);

export function LoginPage() {
  const { request, error: callbackError } = loginRoute.useSearch();
  const session = useSession();
  const context = useQuery({ queryKey: queryKeys.login(request), queryFn: ({ signal }) => api.login.context(request, signal), staleTime: 0, retry: false });
  const [showCredentials, setShowCredentials] = useState(false);
  const form = useForm<LiteLoginInput>({ resolver: zodResolver(showCredentials ? manualLoginSchema : hostedLoginSchema), defaultValues: { username: '' }, shouldUnregister: true });
  const official = useMutation({ mutationFn: () => api.login.official(context.data?.request ?? undefined), onSuccess: followRedirect });
  const lite = useMutation({
    mutationFn: (input: LiteLoginInput) => api.login.lite({ ...input, request: context.data?.request ?? undefined }),
    onSuccess: followRedirect,
    onError: (failure) => {
      if (failure instanceof ApiFailure && failure.code === 'credentials_required') {
        setShowCredentials(true);
      }
    },
  });
  const { setFocus } = form;
  useEffect(() => {
    if (showCredentials && !lite.isPending) setFocus('client_id');
  }, [showCredentials, lite.isPending, setFocus]);
  if (session.data?.user && !request && !callbackError) return <Navigate to="/apps" replace />;
  const ready = context.isSuccess && !context.isFetching;
  const busy = official.isPending || lite.isPending;
  const liteOnly = context.data?.application?.lite_only === true;
  const minimumLevel = context.data?.application?.min_trust_level ?? 0;
  const requiresLevel = context.data?.eligibility.reason === 'trust_level_required';
  const canContinue = Boolean(request && ready && session.data?.user && context.data?.eligibility.allowed);
  const credentialsNeeded = lite.error instanceof ApiFailure && lite.error.code === 'credentials_required';
  const failure = official.error ?? (credentialsNeeded ? null : lite.error);
  const username = form.register('username');
  function reverify() {
    if (session.data?.login_method === 'official_connect' && !liteOnly && context.data?.official_available) official.mutate();
    else if (session.data?.user) {
      form.setValue('username', session.data.user.username);
      lite.mutate({ username: session.data.user.username });
    }
  }
  return <Page narrow><Panel className="login-panel"><div className="login-heading"><h1>{context.data?.application?.name ?? '登录'}</h1>{context.data?.application && <span className="muted">登录并授权</span>}</div>
    {callbackError && <Notice>{callbackErrors[callbackError] ?? '登录未完成，请重试'}</Notice>}
    {context.isError && <div className="stack"><Notice>{errorMessage(context.error)}</Notice><Button variant="secondary" onClick={() => void context.refetch()}>重新加载</Button></div>}
    {failure && <Notice>{errorMessage(failure)}</Notice>}
    {context.data?.application && <div className="login-policy">最低等级：{minimumLevel} 级</div>}
    {requiresLevel && <div className="stack compact-stack"><Notice kind="neutral">此应用要求等级达到 {minimumLevel} 级；当前已验证等级：{context.data?.eligibility.trust_level ?? '—'} 级</Notice><Button variant="ghost" disabled={!ready || busy} onClick={reverify}>重新验证</Button></div>}
    {canContinue && <div className="continue-session"><span className="muted">当前账号：{session.data?.user?.username}</span><a href={`/auth/resume?request=${encodeURIComponent(context.data?.request ?? request!)}`} className="button button-primary">继续<ArrowRight size={16} /></a></div>}
    <Button type="button" variant="secondary" className="button-full login-button" disabled={!ready || !context.data?.official_available || liteOnly || busy} busy={official.isPending} onClick={() => official.mutate()}><span>非 Lite 用户登录</span>{!official.isPending && <ArrowRight size={16} aria-hidden="true" />}</Button>
    {!ready && !context.isError && <span className="login-policy" role="status">正在读取登录方式</span>}
    {ready && !context.data?.official_available && !liteOnly && <span className="login-policy" role="status">非 Lite 用户登录暂不可用</span>}
    {liteOnly && <div className="login-policy" role="status">此应用仅允许 Lite 用户登录</div>}
    <div className="form-divider"><span>Lite 用户登录</span></div>
    <form onSubmit={form.handleSubmit((values) => lite.mutate(values))} className="stack" noValidate><fieldset disabled={busy} className="stack">
      <Field label="Linux.do 用户名" htmlFor="login-username" error={form.formState.errors.username?.message}><div className="input-prefix"><span aria-hidden="true">@</span><input id="login-username" autoComplete="username" autoCapitalize="none" spellCheck={false} aria-invalid={Boolean(form.formState.errors.username)} aria-describedby={form.formState.errors.username ? 'login-username-error' : undefined} {...username} onChange={(event) => { event.target.value = event.target.value.replace(/^@+/, ''); void username.onChange(event); }} /></div></Field>
      {showCredentials && <><Field label="Connect Client ID" htmlFor="login-client-id" error={form.formState.errors.client_id?.message}><input id="login-client-id" autoComplete="off" spellCheck={false} aria-invalid={Boolean(form.formState.errors.client_id)} aria-describedby={form.formState.errors.client_id ? 'login-client-id-error' : undefined} {...form.register('client_id')} /></Field><Field label="Connect Client Secret" htmlFor="login-client-secret" error={form.formState.errors.client_secret?.message}><input id="login-client-secret" type="password" autoComplete="off" spellCheck={false} aria-invalid={Boolean(form.formState.errors.client_secret)} aria-describedby={form.formState.errors.client_secret ? 'login-client-secret-error' : undefined} {...form.register('client_secret')} /></Field><ConnectSetup /></>}
      <Button className="button-full login-button" type="submit" busy={lite.isPending} disabled={!ready || official.isPending}>{showCredentials ? '验证并登录' : 'Lite 用户登录'}{!lite.isPending && <ArrowRight size={16} aria-hidden="true" />}</Button>
      <Button type="button" variant="ghost" className="credentials-toggle" onClick={() => { form.unregister(['client_id', 'client_secret']); form.clearErrors(); setShowCredentials(!showCredentials); lite.reset(); }}>{showCredentials ? '使用已托管的密钥' : '填写 / 更新 Connect 密钥'}</Button>
    </fieldset></form>
    {context.isPending && <span className="sr-only"><Loading label="正在读取登录方式" /></span>}
  </Panel></Page>;
}
