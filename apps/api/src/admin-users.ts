import { z } from 'zod';
import type { AdminAppsPage, AdminConnectFilters, AdminUserDetail, AdminUserFilters, AdminUsersPage, AdminUserSummary, App, ConnectRecord, ConnectRecordsPage, LoginMethod } from '@liteauth/contracts';
import { LOG_RETENTION_MS } from './audit';
import type { Env } from './env';
import { invariant } from './errors';

const paginationSchema = z.object({ cursor: z.string().max(512).optional(), limit: z.coerce.number().int().min(1).max(100).default(50) });
const userFiltersSchema = paginationSchema.extend({
  q: z.string().trim().max(128).optional(),
  disabled: z.preprocess((value) => value === 'true' ? true : value === 'false' ? false : value, z.boolean().optional()),
});
const connectFiltersSchema = paginationSchema.extend({
  upstream_client_id: z.string().trim().max(512).optional(),
  result: z.enum(['success', 'denied', 'failed', 'canceled', 'expired', 'pending']).optional(),
  from: z.iso.datetime({ offset: true }).optional(), to: z.iso.datetime({ offset: true }).optional(),
}).refine((value) => !value.from || !value.to || Date.parse(value.from) <= Date.parse(value.to));

function validated<T>(schema: z.ZodType<T>, value: unknown): T {
  const result = schema.safeParse(value);
  invariant(result.success, 400, 'invalid_filters', '请检查筛选条件');
  return result.data;
}

export const parseAdminUserFilters = (query: Record<string, string>): AdminUserFilters => validated(userFiltersSchema, query);
export const parseAdminConnectFilters = (query: Record<string, string>): AdminConnectFilters => validated(connectFiltersSchema, query);

export async function requireAdmin(env: Env, actorId: string): Promise<void> {
  const actor = await env.DB.prepare('SELECT is_admin, disabled FROM user WHERE id = ?').bind(actorId).first<{ is_admin: number; disabled: number }>();
  invariant(actor?.is_admin && !actor.disabled, 403, 'admin_required', '没有权限');
}

type Bind = string | number;
function appendCursor(cursor: string | undefined, conditions: string[], binds: Bind[], timeColumn: string, idColumn: string) {
  if (!cursor) return;
  let value: unknown;
  try { value = JSON.parse(atob(cursor)); }
  catch { invariant(false, 400, 'invalid_cursor', '分页信息已失效，请重新加载'); }
  const parsed = z.tuple([z.number().int().nonnegative(), z.string().min(1).max(256)]).safeParse(value);
  invariant(parsed.success, 400, 'invalid_cursor', '分页信息已失效，请重新加载');
  conditions.push(`(${timeColumn} < ? OR (${timeColumn} = ? AND ${idColumn} < ?))`);
  binds.push(parsed.data[0], parsed.data[0], parsed.data[1]);
}
function nextCursor(rows: { id: string; created_at: number }[], limit: number): string | null {
  const last = rows[limit - 1];
  return rows.length > limit && last ? btoa(JSON.stringify([last.created_at, last.id])) : null;
}

type UserRow = {
  id: string; linuxdo_id: number; username: string; name: string; image: string | null; is_admin: number; disabled: number;
  connect_client_id: string | null; last_login_method: string | null; last_trust_level: number | null; last_authenticated_at: number | null; created_at: number;
};
const userSelect = `SELECT u.id,u.linuxdo_id,u.username,u.name,u.image,u.is_admin,u.disabled,u.created_at,
  u.last_authenticated_at,u.last_login_method,u.last_trust_level,
  (SELECT c.client_id FROM upstream_credential c WHERE c.owner_user_id=u.id AND c.kind='self' AND c.status='active') AS connect_client_id
  FROM user u`;

function presentUser(row: UserRow): AdminUserSummary {
  const method: LoginMethod | null = row.last_login_method === 'official_connect' || row.last_login_method === 'lite_self_app' ? row.last_login_method : null;
  return { id: row.id, linuxdo_id: row.linuxdo_id, username: row.username, name: row.name, avatar_url: row.image,
    is_admin: Boolean(row.is_admin), disabled: Boolean(row.disabled), connect_client_id: row.connect_client_id,
    last_login_method: method, last_trust_level: row.last_trust_level,
    last_authenticated_at: row.last_authenticated_at === null ? null : new Date(row.last_authenticated_at).toISOString(),
    created_at: new Date(row.created_at).toISOString() };
}

async function existingUser(env: Env, userId: string): Promise<UserRow> {
  const row = await env.DB.prepare(`${userSelect} WHERE u.id=?`).bind(userId).first<UserRow>();
  invariant(row, 404, 'user_not_found', '账号不存在');
  return row;
}

export async function listUsers(env: Env, actorId: string, input: AdminUserFilters = {}): Promise<AdminUsersPage> {
  await requireAdmin(env, actorId);
  const filters = validated(userFiltersSchema, input);
  const conditions = ['1=1'];
  const binds: Bind[] = [];
  if (filters.disabled !== undefined) { conditions.push('u.disabled=?'); binds.push(Number(filters.disabled)); }
  if (filters.q) {
    const term = filters.q.replace(/^@/, '');
    const escaped = `%${term.replaceAll('\\', '\\\\').replaceAll('%', '\\%').replaceAll('_', '\\_')}%`;
    conditions.push(`(u.id=? OR CAST(u.linuxdo_id AS TEXT)=? OR u.username LIKE ? ESCAPE '\\' OR u.name LIKE ? ESCAPE '\\'
      OR EXISTS (SELECT 1 FROM upstream_credential c WHERE c.owner_user_id=u.id AND c.kind='self' AND c.client_id=?))`);
    binds.push(term, term, escaped, escaped, filters.q);
  }
  appendCursor(filters.cursor, conditions, binds, 'u.created_at', 'u.id');
  const result = await env.DB.prepare(`${userSelect} WHERE ${conditions.join(' AND ')} ORDER BY u.created_at DESC,u.id DESC LIMIT ?`)
    .bind(...binds, filters.limit + 1).all<UserRow>();
  return { users: result.results.slice(0, filters.limit).map(presentUser), next_cursor: nextCursor(result.results, filters.limit) };
}

export async function getAdminUser(env: Env, actorId: string, userId: string): Promise<AdminUserDetail> {
  await requireAdmin(env, actorId);
  const user = presentUser(await existingUser(env, userId));
  const credentials = await env.DB.prepare(`SELECT client_id,status,created_at,updated_at FROM upstream_credential
    WHERE owner_user_id=? AND kind='self' AND status IN ('active','revoked') ORDER BY updated_at DESC,client_id DESC`)
    .bind(userId).all<{ client_id: string; status: 'active' | 'revoked'; created_at: number; updated_at: number }>();
  return { user, credentials: credentials.results.map((row) => ({ client_id: row.client_id, status: row.status,
    created_at: new Date(row.created_at).toISOString(), updated_at: new Date(row.updated_at).toISOString() })) };
}

type AppRow = { id: string; client_id: string; name: string | null; redirect_uris: string; token_endpoint_auth_method: string;
  require_pkce: number; disabled: number; created_at: number; lite_only: number; min_trust_level: number };
function presentApp(row: AppRow): App {
  return { id: row.id, client_id: row.client_id, name: row.name ?? '', redirect_uris: JSON.parse(row.redirect_uris) as string[],
    client_type: row.token_endpoint_auth_method === 'none' ? 'public' : 'confidential', pkce_required: Boolean(row.require_pkce),
    disabled: Boolean(row.disabled), lite_only: Boolean(row.lite_only), min_trust_level: row.min_trust_level,
    created_at: new Date(row.created_at).toISOString() };
}

export async function listUserApps(env: Env, actorId: string, userId: string, input: Pick<AdminUserFilters, 'cursor' | 'limit'> = {}): Promise<AdminAppsPage> {
  await requireAdmin(env, actorId);
  await existingUser(env, userId);
  const filters = validated(paginationSchema, input);
  const conditions = ['c.user_id=?', 'a.deleted_at IS NULL'];
  const binds: Bind[] = [userId];
  appendCursor(filters.cursor, conditions, binds, 'COALESCE(c.created_at,0)', 'c.id');
  const result = await env.DB.prepare(`SELECT c.id,c.client_id,c.name,c.redirect_uris,c.token_endpoint_auth_method,
    c.require_pkce,c.disabled,COALESCE(c.created_at,0) AS created_at,a.lite_only,a.min_trust_level
    FROM oauth_client c JOIN app_settings a ON a.client_id=c.client_id WHERE ${conditions.join(' AND ')}
    ORDER BY COALESCE(c.created_at,0) DESC,c.id DESC LIMIT ?`).bind(...binds, filters.limit + 1).all<AppRow>();
  return { apps: result.results.slice(0, filters.limit).map(presentApp), next_cursor: nextCursor(result.results, filters.limit) };
}

type ConnectRow = Omit<ConnectRecord, 'created_at' | 'changes' | 'identity_confirmed'> & {
  created_at: number; changes: string | null; identity_confirmed: number;
};

export async function listConnectRecords(env: Env, actorId: string, userId: string, input: AdminConnectFilters = {}): Promise<ConnectRecordsPage> {
  await requireAdmin(env, actorId);
  await existingUser(env, userId);
  const filters = validated(connectFiltersSchema, input);
  const conditions = [
    `(a.action='connect.verification' AND (a.subject_user_id=? OR a.actor_id=?)
      OR a.event_key IS NULL AND a.action IN ('credential.verified','account.login','account.login_failed') AND a.actor_id=?)`,
    'a.created_at>=?',
  ];
  const binds: Bind[] = [userId, userId, userId, Date.now() - LOG_RETENTION_MS];
  if (filters.upstream_client_id) { conditions.push('a.upstream_client_id=?'); binds.push(filters.upstream_client_id); }
  if (filters.result) { conditions.push('a.result=?'); binds.push(filters.result); }
  if (filters.from) { conditions.push('a.created_at>=?'); binds.push(Date.parse(filters.from)); }
  if (filters.to) { conditions.push('a.created_at<=?'); binds.push(Date.parse(filters.to)); }
  appendCursor(filters.cursor, conditions, binds, 'a.created_at', 'a.id');
  const result = await env.DB.prepare(`SELECT a.id,a.action,a.actor_id,a.actor_type,a.actor_linuxdo_id,a.actor_username,a.actor_name,
    a.target_id,a.target_type,a.target_name,a.client_id,a.app_name,a.login_method,a.trust_level,a.result,a.reason,a.request_id,a.changes,a.created_at,
    a.subject_user_id,a.subject_linuxdo_id,a.subject_username,a.upstream_client_id,a.connect_transaction_id,a.identity_confirmed,a.verification_purpose
    FROM audit a WHERE ${conditions.join(' AND ')} ORDER BY a.created_at DESC,a.id DESC LIMIT ?`)
    .bind(...binds, filters.limit + 1).all<ConnectRow>();
  return { entries: result.results.slice(0, filters.limit).map((row) => ({ ...row, identity_confirmed: Boolean(row.identity_confirmed),
    changes: row.changes ? JSON.parse(row.changes) as ConnectRecord['changes'] : null,
    created_at: new Date(row.created_at).toISOString() })), next_cursor: nextCursor(result.results, filters.limit) };
}
