import { zodResolver } from '@hookform/resolvers/zod';
import { appInputSchema } from '@liteauth/contracts';
import type { App, AppInput } from '@liteauth/contracts';
import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { errorMessage } from '../lib/api';
import { Button, Field, Notice, Switch } from './ui';

const formSchema = z.object({
  name: z.string().min(1, '请填写应用名称').max(80, '应用名称不能超过 80 个字符'),
  redirects: z.string().min(1, '请填写回调地址'),
  lite_only: z.boolean(),
  min_trust_level: z.number().int().min(0).max(4),
  client_type: z.enum(['confidential', 'public']),
  pkce_required: z.boolean(),
}).superRefine((value, context) => {
  const result = appInputSchema.safeParse(toInput(value));
  if (!result.success) for (const issue of result.error.issues) {
    context.addIssue({ code: 'custom', message: issue.message, path: [issue.path[0] === 'redirect_uris' ? 'redirects' : issue.path[0] ?? 'name'] });
  }
});

type FormValues = z.infer<typeof formSchema>;
function toInput(value: FormValues): AppInput {
  return { name: value.name, redirect_uris: value.redirects.split('\n').map((line) => line.trim()).filter(Boolean), lite_only: value.lite_only, min_trust_level: value.min_trust_level, client_type: value.client_type, pkce_required: value.pkce_required };
}

export function AppForm({ app, onSubmit, pending, error, submitLabel = '保存', onCancel }: { app?: App; onSubmit: (input: AppInput) => void; pending: boolean; error?: unknown; submitLabel?: string; onCancel?: () => void }) {
  const form = useForm<FormValues>({
    resolver: zodResolver(formSchema),
    defaultValues: { name: app?.name ?? '', redirects: app?.redirect_uris.join('\n') ?? '', lite_only: app?.lite_only ?? false, min_trust_level: app?.min_trust_level ?? 0, client_type: app?.client_type ?? 'confidential', pkce_required: app?.pkce_required ?? true },
  });
  const { reset } = form;
  useEffect(() => {
    if (app) reset({ name: app.name, redirects: app.redirect_uris.join('\n'), lite_only: app.lite_only, min_trust_level: app.min_trust_level ?? 0, client_type: app.client_type, pkce_required: app.pkce_required });
  }, [app, reset]);
  const type = form.watch('client_type');
  const liteOnly = form.watch('lite_only');
  const identifier = app?.id ?? 'new';
  return <form className="stack" onSubmit={form.handleSubmit((value) => onSubmit(appInputSchema.parse(toInput(value))))} noValidate><fieldset className="stack" disabled={pending}>
    <Field label="应用名称" htmlFor={`${identifier}-name`} error={form.formState.errors.name?.message}><input id={`${identifier}-name`} autoComplete="off" aria-invalid={Boolean(form.formState.errors.name)} aria-describedby={form.formState.errors.name ? `${identifier}-name-error` : undefined} {...form.register('name')} /></Field>
    <Field label="回调地址（每行一个）" htmlFor={`${identifier}-redirects`} error={form.formState.errors.redirects?.message}><textarea id={`${identifier}-redirects`} rows={3} placeholder="https://example.com/callback" spellCheck={false} autoComplete="off" aria-invalid={Boolean(form.formState.errors.redirects)} aria-describedby={form.formState.errors.redirects ? `${identifier}-redirects-error` : undefined} {...form.register('redirects')} /></Field>
    {!app && <Field label="应用类型" htmlFor={`${identifier}-type`} error={form.formState.errors.client_type?.message}><select id={`${identifier}-type`} {...form.register('client_type', { onChange: (event: { target: { value: string } }) => { if (event.target.value === 'public') form.setValue('pkce_required', true, { shouldDirty: true }); } })}><option value="confidential">服务端应用</option><option value="public">浏览器 / 原生应用</option></select></Field>}
    <Field label="最低等级" htmlFor={`${identifier}-min-level`} error={form.formState.errors.min_trust_level?.message}><select id={`${identifier}-min-level`} {...form.register('min_trust_level', { valueAsNumber: true })}>{[0, 1, 2, 3, 4].map((level) => <option key={level} value={level}>{level} 级</option>)}</select></Field>
    <div className="settings-group"><Switch label="仅允许 Lite 用户登录" checked={liteOnly} onCheckedChange={(checked) => form.setValue('lite_only', checked, { shouldDirty: true })} disabled={pending} />{liteOnly && <div className="setting-note">阻止新的非 Lite 授权；已有授权按原有效期继续。</div>}<Switch label="启用 PKCE" checked={form.watch('pkce_required')} onCheckedChange={(checked) => form.setValue('pkce_required', checked, { shouldDirty: true, shouldValidate: true })} disabled={type === 'public' || pending} />{form.formState.errors.pkce_required && <span className="field-error" role="alert">{form.formState.errors.pkce_required.message}</span>}</div>
    {error != null && <Notice>{errorMessage(error)}</Notice>}
    <div className="form-actions">{app && form.formState.isDirty && <span className="unsaved-status" role="status">未保存</span>}{onCancel && <Button type="button" variant="secondary" onClick={onCancel}>取消</Button>}<Button type="submit" busy={pending} disabled={Boolean(app) && !form.formState.isDirty}>{submitLabel}</Button></div>
  </fieldset></form>;
}
