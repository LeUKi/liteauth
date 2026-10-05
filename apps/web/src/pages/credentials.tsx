import { zodResolver } from '@hookform/resolvers/zod';
import { credentialInputSchema } from '@liteauth/contracts';
import type { CredentialInput } from '@liteauth/contracts';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useForm } from 'react-hook-form';
import { ConnectSetup } from '../components/connect-setup';
import { Button, Confirm, Field, Loading, Notice, Page, PageHeading, Panel, QueryError, ValueRow, formatDate } from '../components/ui';
import { api, errorMessage, followRedirect, queryKeys } from '../lib/api';
import { credentialsRoute } from '../router';

export function CredentialsPage() {
  const { error: callbackError } = credentialsRoute.useSearch();
  const queryClient = useQueryClient();
  const credentials = useQuery({ queryKey: queryKeys.credentials, queryFn: ({ signal }) => api.credentials.get(signal) });
  const form = useForm<CredentialInput>({ resolver: zodResolver(credentialInputSchema), defaultValues: { client_id: '', client_secret: '' } });
  const verify = useMutation({ mutationFn: api.credentials.verify, onSuccess: followRedirect });
  const remove = useMutation({ mutationFn: api.credentials.delete, onSuccess: () => queryClient.invalidateQueries({ queryKey: queryKeys.credentials }) });
  const credential = credentials.data?.credential;
  return <Page><PageHeading title="Connect 密钥" />{credentials.isPending ? <Loading /> : credentials.isError ? <QueryError error={credentials.error} retry={credentials.refetch} /> : <div className="stack section-stack">
    {callbackError && <Notice>验证未完成，请重新提交</Notice>}
    {credential && <Panel><div className="panel-heading"><h2>已托管的 Connect 密钥</h2><span className={`badge ${credential.status === 'active' ? 'badge-green' : ''}`}>{credential.status === 'active' ? '有效' : '已撤销'}</span></div><ValueRow label="Client ID" value={credential.client_id} copy /><div className="value-row"><span className="value-label">更新时间</span><span>{formatDate(credential.updated_at)}</span></div><div className="panel-footer"><Confirm title="删除 Connect 密钥？" description="删除后，将无法使用这组密钥发起新的 Lite 登录。" confirmLabel="删除" onConfirm={() => remove.mutateAsync()}><Button variant="danger">删除密钥</Button></Confirm></div></Panel>}
    <Panel><div className="panel-heading"><h2>{credential ? '更新 Connect 密钥' : '提交 Connect 密钥'}</h2></div><ConnectSetup /><form className="stack credentials-form" onSubmit={form.handleSubmit((input) => verify.mutate(input))} noValidate><fieldset disabled={verify.isPending} className="stack"><Field label="Connect Client ID" htmlFor="credential-client-id" error={form.formState.errors.client_id?.message}><input id="credential-client-id" autoComplete="off" spellCheck={false} aria-invalid={Boolean(form.formState.errors.client_id)} aria-describedby={form.formState.errors.client_id ? 'credential-client-id-error' : undefined} {...form.register('client_id')} /></Field><Field label="Connect Client Secret" htmlFor="credential-client-secret" error={form.formState.errors.client_secret?.message}><input id="credential-client-secret" type="password" autoComplete="off" spellCheck={false} aria-invalid={Boolean(form.formState.errors.client_secret)} aria-describedby={form.formState.errors.client_secret ? 'credential-client-secret-error' : undefined} {...form.register('client_secret')} /></Field>{verify.isError && <Notice>{errorMessage(verify.error)}</Notice>}<div className="form-actions"><Button type="submit" busy={verify.isPending}>{credential ? '验证并更新' : '验证并保存'}</Button></div></fieldset></form></Panel>
  </div>}</Page>;
}
