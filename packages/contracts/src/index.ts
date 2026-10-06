import { z } from 'zod';

export const loginMethodSchema = z.enum(['official_connect', 'lite_self_app']);
export type LoginMethod = z.infer<typeof loginMethodSchema>;

export const userSchema = z.object({
  id: z.string(),
  linuxdo_id: z.number().int().positive(),
  username: z.string(),
  name: z.string(),
  avatar_url: z.string().nullable().optional(),
  is_admin: z.boolean(),
  disabled: z.boolean().optional(),
  official_verified_at: z.string().nullable(),
});
export type User = z.infer<typeof userSchema>;
export type AdminUserSummary = User & {
  connect_client_id: string | null; last_login_method: LoginMethod | null;
  last_trust_level: number | null; last_authenticated_at: string | null; created_at: string;
};
export type AdminUserFilters = { q?: string; disabled?: boolean; cursor?: string; limit?: number };
export type AdminUsersPage = { users: AdminUserSummary[]; next_cursor: string | null };
export type AdminUserDetail = { user: AdminUserSummary; credentials: {
  client_id: string; status: 'active' | 'revoked'; created_at: string; updated_at: string;
}[] };
export const sessionSchema = z.object({ user: userSchema.nullable(), login_method: loginMethodSchema.nullable() });
export type SessionResponse = z.infer<typeof sessionSchema>;

export const redirectUriSchema = z.string().trim().max(2048).url().refine((value) => {
  const url = new URL(value);
  const rawHostname = /^https?:\/\/(\[[^\]]+\]|[^/?#:]+)(?::\d+)?(?:[/?#]|$)/i.exec(value)?.[1]?.toLowerCase();
  if (value.includes('#') || url.username || url.password || !rawHostname) return false;
  if (url.protocol === 'http:') return ['localhost', '127.0.0.1', '[::1]'].includes(rawHostname);
  return url.protocol === 'https:' && !['localhost', '[::1]'].includes(url.hostname) && !url.hostname.startsWith('127.') && !/^localhost\.+$/i.test(url.hostname);
}, '请输入 HTTPS 回调地址，本地调试可使用 HTTP');

export const appInputSchema = z.object({
  name: z.string().trim().min(1, '请填写应用名称').max(80),
  redirect_uris: z.array(redirectUriSchema).min(1, '请至少填写一个回调地址').max(10).transform((values) => [...new Set(values)]),
  lite_only: z.boolean().default(false),
  min_trust_level: z.number().int().min(0).max(4).optional(),
  client_type: z.enum(['confidential', 'public']).default('confidential'),
  pkce_required: z.boolean().default(true),
}).refine((value) => value.client_type !== 'public' || value.pkce_required, { message: '公共应用必须启用 PKCE', path: ['pkce_required'] });
export type AppInput = z.infer<typeof appInputSchema>;
export const appSchema = z.object({
  id: z.string(), client_id: z.string(), name: z.string(), redirect_uris: z.array(z.string()),
  lite_only: z.boolean(), min_trust_level: z.number().int().min(0).max(4), client_type: z.enum(['confidential', 'public']), pkce_required: z.boolean(),
  disabled: z.boolean(), created_at: z.string(),
});
export type App = z.infer<typeof appSchema>;
export type AppsResponse = { apps: App[] };
export type AdminAppsPage = AppsResponse & { next_cursor: string | null };
export type AppResponse = { app: App; client_secret?: string };

export const credentialInputSchema = z.object({
  client_id: z.string().trim().min(1, '请填写 Client ID').max(512),
  client_secret: z.string().min(1, '请填写 Client Secret').max(2048),
});
export type CredentialInput = z.infer<typeof credentialInputSchema>;
export const liteLoginSchema = z.object({
  username: z.string().trim().regex(/^[A-Za-z0-9_.-]{1,64}$/, '请填写有效的用户名'),
  client_id: credentialInputSchema.shape.client_id.optional(),
  client_secret: credentialInputSchema.shape.client_secret.optional(),
  request: z.string().max(256).optional(),
}).superRefine((value, ctx) => {
  if (value.client_id && value.client_secret === undefined) ctx.addIssue({ code: 'custom', message: '请填写 Client Secret', path: ['client_secret'] });
  if (value.client_secret && value.client_id === undefined) ctx.addIssue({ code: 'custom', message: '请填写 Client ID', path: ['client_id'] });
});
export type LiteLoginInput = z.infer<typeof liteLoginSchema>;
export type Credential = { client_id: string; updated_at: string; status: 'active' | 'revoked' };
export type CredentialsResponse = { credential: Credential | null };
export type Eligibility = { allowed: boolean; reason: 'login_required' | 'lite_required' | 'trust_level_required' | 'official_only_account' | 'official_login_required' | null; trust_level: number | null };
export type LoginContext = { request: string | null; application: Pick<App, 'id' | 'name' | 'lite_only' | 'min_trust_level'> | null; official_available: boolean; lite_available: boolean; eligibility: Eligibility };
export type RedirectResponse = { redirect_url: string };
export type ConsentContext = { request: string; application: Pick<App, 'id' | 'name' | 'lite_only' | 'min_trust_level'>; scopes: string[]; login_method: LoginMethod; eligibility: Eligibility };
export type ApiError = { error: { code: string; message: string } };
export type AppSecretResponse = { status: 'available' | 'legacy_unavailable' | 'not_applicable'; client_secret: string | null };
export type AuditResult = 'success' | 'denied' | 'failed' | 'canceled' | 'expired' | 'pending';
export type AuditChangeValue = string | number | boolean | string[] | null;
export type AuditChanges = Record<string, { before: AuditChangeValue; after: AuditChangeValue }>;
export type AuditEntry = {
  id: string; action: string; actor_id: string | null; actor_type: 'user' | 'system' | 'unknown';
  actor_linuxdo_id: number | null; actor_username: string | null; actor_name: string | null;
  target_id: string | null; target_type: string | null; target_name: string | null;
  client_id: string | null; app_name: string | null; login_method: LoginMethod | null; trust_level: number | null;
  result: AuditResult; reason: string | null; request_id: string | null; changes: AuditChanges | null; created_at: string;
  subject_user_id?: string | null; subject_linuxdo_id?: number | null; subject_username?: string | null;
  upstream_client_id?: string | null; connect_transaction_id?: string | null; identity_confirmed?: boolean;
  verification_purpose?: 'login' | 'credential_validation' | null;
};
export type ConnectRecord = AuditEntry & {
  subject_user_id: string | null; subject_linuxdo_id: number | null; subject_username: string | null;
  upstream_client_id: string | null; connect_transaction_id: string | null; identity_confirmed: boolean;
  verification_purpose: 'login' | 'credential_validation' | null;
};
export type ConnectRecordsPage = { entries: ConnectRecord[]; next_cursor: string | null };
export type AdminConnectFilters = { upstream_client_id?: string; result?: AuditResult; from?: string; to?: string; cursor?: string; limit?: number };
export type AuditPage = { entries: AuditEntry[]; next_cursor: string | null };
export type AuditFilters = { cursor?: string; user?: string; client_id?: string; action?: string; result?: AuditResult; from?: string; to?: string; limit?: number };
export const consentInputSchema = z.object({ request: z.string().min(1).max(256), accept: z.boolean() });
export const officialLoginSchema = z.object({ request: z.string().max(256).optional() });
export const disableInputSchema = z.object({ disabled: z.boolean() });
