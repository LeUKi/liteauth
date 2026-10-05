import { appInputSchema, type App, type AppInput, type AppResponse, type AppsResponse, type AppSecretResponse } from '@liteauth/contracts';
import type { LiteAuth } from './auth';
import { decryptAppSecret } from './app-secrets';
import { audit, authorizationOutcomeStatement } from './audit';
import { connectOutcomeStatement } from './connect-audit';
import { setAppPolicy } from './db/policy';
import type { Env } from './env';
import { invariant } from './errors';

type AppRow = { id: string; client_id: string; user_id: string; name: string | null; redirect_uris: string;
  lite_only: number; min_trust_level: number; token_endpoint_auth_method: string; require_pkce: number; disabled: number; created_at: number };
const select = `SELECT c.id, c.client_id, c.user_id, c.name, c.redirect_uris, c.token_endpoint_auth_method,
  c.require_pkce, c.disabled, c.created_at, a.lite_only, a.min_trust_level FROM oauth_client c
  JOIN app_settings a ON a.client_id = c.client_id WHERE a.deleted_at IS NULL`;

function present(row: AppRow): App {
  return { id: row.id, client_id: row.client_id, name: row.name ?? '', redirect_uris: JSON.parse(row.redirect_uris) as string[],
    lite_only: Boolean(row.lite_only), min_trust_level: row.min_trust_level, client_type: row.token_endpoint_auth_method === 'none' ? 'public' : 'confidential',
    pkce_required: Boolean(row.require_pkce), disabled: Boolean(row.disabled), created_at: new Date(row.created_at).toISOString() };
}

async function ownedApp(env: Env, id: string, userId: string, isAdmin: boolean) {
  const row = await env.DB.prepare(`${select} AND c.id = ? AND (? = 1 OR c.user_id = ?)`)
    .bind(id, Number(isAdmin), userId).first<AppRow>();
  invariant(row, 404, 'app_not_found', '应用不存在');
  return row;
}

function applicationType(redirectUris: string[]): 'web' | 'native' {
  // The shared contract permits HTTP only for exact local loopback callbacks.
  return redirectUris.some((uri) => new URL(uri).protocol === 'http:') ? 'native' : 'web';
}

export async function listApps(env: Env, userId: string, isAdmin = false): Promise<AppsResponse> {
  const rows = await env.DB.prepare(`${select} AND (? = 1 OR c.user_id = ?) ORDER BY c.created_at DESC LIMIT 200`)
    .bind(Number(isAdmin), userId).all<AppRow>();
  return { apps: rows.results.map(present) };
}

export async function getApp(env: Env, id: string, userId: string, isAdmin = false): Promise<AppResponse> {
  return { app: present(await ownedApp(env, id, userId, isAdmin)) };
}

export async function readAppSecret(env: Env, id: string, userId: string, isAdmin = false): Promise<AppSecretResponse> {
  const row = await ownedApp(env, id, userId, isAdmin);
  invariant(row.user_id === userId, 403, 'owner_required', '只有应用所有者可以查看密钥');
  if (row.token_endpoint_auth_method === 'none') return { status: 'not_applicable', client_secret: null };
  const stored = await env.DB.prepare(`SELECT c.client_secret, c.secret_ciphertext FROM oauth_client c
    JOIN app_settings a ON a.client_id = c.client_id
    WHERE c.id = ? AND c.user_id = ? AND a.deleted_at IS NULL`)
    .bind(id, userId).first<{ client_secret: string | null; secret_ciphertext: string | null }>();
  invariant(stored, 404, 'app_not_found', '应用不存在');
  if (!stored.secret_ciphertext) return { status: 'legacy_unavailable', client_secret: null };
  invariant(stored.client_secret, 500, 'secret_unavailable', '暂时无法读取密钥，请重试');
  let secret: string;
  try { secret = await decryptAppSecret(env, row.client_id, stored.client_secret, stored.secret_ciphertext); }
  catch { invariant(false, 500, 'secret_unavailable', '暂时无法读取密钥，请重试'); }
  await audit(env.DB, 'app.secret_viewed', userId, id, { clientId: row.client_id, appName: row.name ?? '' });
  return { status: 'available', client_secret: secret };
}

export async function createApp(env: Env, auth: LiteAuth, headers: Headers, input: AppInput): Promise<AppResponse> {
  const data = appInputSchema.parse(input);
  const client = await auth.api.createOAuthClient({ headers, body: {
    client_name: data.name, redirect_uris: data.redirect_uris, scope: 'openid profile',
    token_endpoint_auth_method: data.client_type === 'public' ? 'none' : 'client_secret_post',
    grant_types: ['authorization_code'], response_types: ['code'], application_type: applicationType(data.redirect_uris),
  } });
  // Until settings exist the issuance adapter fails closed for the newly created client.
  await env.DB.batch([
    env.DB.prepare('INSERT INTO app_settings (client_id, lite_only, min_trust_level) VALUES (?, ?, ?)')
      .bind(client.client_id, Number(data.lite_only), data.min_trust_level ?? 0),
    env.DB.prepare('UPDATE oauth_client SET require_pkce = ?, disabled = 0 WHERE client_id = ?').bind(Number(data.pkce_required), client.client_id),
  ]);
  const row = await env.DB.prepare(`${select} AND c.client_id = ?`).bind(client.client_id).first<AppRow>();
  invariant(row, 500, 'app_create_failed', '创建失败，请重试');
  await audit(env.DB, 'app.created', row.user_id, row.id, { clientId: row.client_id, appName: row.name ?? '' });
  return { app: present(row), ...(client.client_secret ? { client_secret: client.client_secret } : {}) };
}

export async function updateApp(env: Env, id: string, userId: string, isAdmin: boolean, input: AppInput): Promise<AppResponse> {
  const data = appInputSchema.parse(input);
  const row = await ownedApp(env, id, userId, isAdmin);
  invariant(data.client_type === present(row).client_type, 400, 'client_type_immutable', '应用类型创建后不能修改');
  await env.DB.prepare(`UPDATE oauth_client SET name = ?, redirect_uris = ?, application_type = ?, require_pkce = ?, updated_at = ?
    WHERE id = ? AND EXISTS (SELECT 1 FROM app_settings WHERE client_id = oauth_client.client_id AND deleted_at IS NULL)`)
    .bind(data.name, JSON.stringify(data.redirect_uris), applicationType(data.redirect_uris), Number(data.pkce_required), Date.now(), id).run();
  await setAppPolicy(env.DB, row.client_id, data.lite_only, data.min_trust_level);
  await audit(env.DB, 'app.updated', userId, id, {
    clientId: row.client_id, appName: data.name,
    changes: {
      name: { before: row.name ?? '', after: data.name },
      redirect_uris: { before: JSON.parse(row.redirect_uris) as string[], after: data.redirect_uris },
      lite_only: { before: Boolean(row.lite_only), after: data.lite_only },
      min_trust_level: { before: row.min_trust_level, after: data.min_trust_level ?? row.min_trust_level },
      pkce_required: { before: Boolean(row.require_pkce), after: data.pkce_required },
    },
  });
  return getApp(env, id, userId, isAdmin);
}

export function revokeAppStatements(env: Env, clientId: string, reason = 'app_unavailable'): D1PreparedStatement[] {
  return [
    authorizationOutcomeStatement(env.DB, 'grant', "g.client_id = ? AND g.state = 'pending'", [clientId], 'canceled', reason),
    authorizationOutcomeStatement(env.DB, 'request', "r.client_id = ? AND r.status IN ('pending','processing')", [clientId], 'canceled', reason),
    env.DB.prepare(`UPDATE oauth_access_token SET revoked = ? WHERE client_id = ? AND revoked IS NULL`).bind(Date.now(), clientId),
    env.DB.prepare(`UPDATE oauth_refresh_token SET revoked = ? WHERE client_id = ? AND revoked IS NULL`).bind(Date.now(), clientId),
    env.DB.prepare("UPDATE grant_ledger SET state = 'canceled' WHERE client_id = ? AND state = 'pending'").bind(clientId),
    env.DB.prepare("UPDATE authorization_request SET status = 'canceled' WHERE client_id = ? AND status IN ('pending','processing')").bind(clientId),
    connectOutcomeStatement(env.DB, "t.status IN ('pending','consumed') AND t.request_id IN (SELECT id FROM authorization_request WHERE client_id = ?)", [clientId], 'canceled', reason),
    env.DB.prepare(`UPDATE connect_transaction SET status = 'canceled', encrypted_payload = NULL
      WHERE status IN ('pending','consumed') AND request_id IN (SELECT id FROM authorization_request WHERE client_id = ?)`).bind(clientId),
    env.DB.prepare('DELETE FROM verification WHERE identifier IN (SELECT code_id FROM grant_ledger WHERE client_id = ?)').bind(clientId),
    env.DB.prepare('DELETE FROM oauth_consent WHERE client_id = ?').bind(clientId),
  ];
}

export async function deleteApp(env: Env, id: string, userId: string, isAdmin: boolean): Promise<void> {
  const row = await ownedApp(env, id, userId, isAdmin);
  await env.DB.batch([
    env.DB.prepare('UPDATE app_settings SET deleted_at = ? WHERE client_id = ?').bind(Date.now(), row.client_id),
    env.DB.prepare('UPDATE oauth_client SET disabled = 1, client_secret = NULL, secret_ciphertext = NULL, updated_at = ? WHERE id = ?').bind(Date.now(), id),
    ...revokeAppStatements(env, row.client_id, 'app_deleted'),
  ]);
  await audit(env.DB, 'app.deleted', userId, id, { clientId: row.client_id, appName: row.name ?? '', targetName: row.name ?? '' });
}

export async function rotateAppSecret(env: Env, auth: LiteAuth, headers: Headers, id: string, userId: string, isAdmin: boolean): Promise<{ client_secret: string }> {
  const row = await ownedApp(env, id, userId, isAdmin);
  invariant(row.user_id === userId, 403, 'owner_required', '请由应用所有者轮换密钥');
  invariant(row.token_endpoint_auth_method !== 'none' && !row.disabled, 400, 'rotation_unavailable', '此应用无法轮换密钥');
  const result = await auth.api.rotateClientSecret({ headers, body: { client_id: row.client_id } });
  const current = await env.DB.prepare('SELECT deleted_at FROM app_settings WHERE client_id = ?').bind(row.client_id).first<{ deleted_at: number | null }>();
  if (!current || current.deleted_at !== null) {
    await env.DB.prepare(`UPDATE oauth_client SET client_secret = NULL, secret_ciphertext = NULL WHERE client_id = ?
      AND EXISTS (SELECT 1 FROM app_settings WHERE client_id = oauth_client.client_id AND deleted_at IS NOT NULL)`)
      .bind(row.client_id).run();
    invariant(false, 404, 'app_not_found', '应用不存在');
  }
  invariant(result.client_secret, 500, 'rotation_failed', '轮换失败，请重试');
  await audit(env.DB, 'app.secret_rotated', userId, id, { clientId: row.client_id, appName: row.name ?? '' });
  return { client_secret: result.client_secret };
}
