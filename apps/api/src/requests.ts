import { hash, randomId } from './crypto';
import { TRANSACTION_TTL, type Env } from './env';
import { invariant } from './errors';

export type AuthorizationRequestRow = {
  id: string; client_id: string; signed_query: string; browser_hash: string; auth_event_id: string | null;
  stage: string; status: string; expires_at: number;
};

export type DownstreamAppPolicy = { lite_only: number | boolean; min_trust_level: number };

export function appEligibility(policy: DownstreamAppPolicy, event: { login_method: string; trust_level: number | null; official_verified_at?: number | null } | null) {
  const trustLevel = event?.trust_level ?? null;
  if (!event) return { allowed: false, reason: 'login_required' as const, trust_level: null };
  if (event.official_verified_at != null && policy.lite_only) return { allowed: false, reason: 'official_only_account' as const, trust_level: trustLevel };
  if (event.official_verified_at != null && event.login_method === 'lite_self_app') return { allowed: false, reason: 'official_login_required' as const, trust_level: trustLevel };
  if (policy.lite_only && event.login_method !== 'lite_self_app') return { allowed: false, reason: 'lite_required' as const, trust_level: trustLevel };
  if (trustLevel === null || trustLevel < policy.min_trust_level) return { allowed: false, reason: 'trust_level_required' as const, trust_level: trustLevel };
  return { allowed: true, reason: null, trust_level: trustLevel };
}

export async function getRequest(env: Env, id: string, browserToken: string) {
  const request = await env.DB.prepare('SELECT * FROM authorization_request WHERE id = ?').bind(id).first<AuthorizationRequestRow>();
  invariant(request && request.status === 'pending' && request.expires_at > Date.now() && request.browser_hash === await hash(browserToken), 400, 'request_expired', '登录请求已过期，请重新开始');
  const app = await env.DB.prepare(`SELECT c.id, c.client_id, c.name, c.disabled, a.lite_only, a.min_trust_level FROM oauth_client c
    JOIN app_settings a ON a.client_id = c.client_id WHERE c.client_id = ? AND a.deleted_at IS NULL`).bind(request.client_id)
    .first<{ id: string; client_id: string; name: string; disabled: number; lite_only: number; min_trust_level: number }>();
  invariant(app && !app.disabled, 400, 'app_unavailable', '此应用暂不可用');
  return { request, app };
}

/** Replace library-signed OAuth URLs with browser-bound opaque handles after library validation. */
export async function captureRedirect(env: Env, redirectUrl: string, browserToken: string, authEventId: string | null, existingId?: string) {
  const url = new URL(redirectUrl, env.APP_ORIGIN);
  if (url.origin !== env.APP_ORIGIN || !['/login', '/consent'].includes(url.pathname)) return redirectUrl;
  const clientId = url.searchParams.get('client_id');
  if (!clientId && !url.searchParams.has('sig')) return redirectUrl;
  invariant(clientId && url.searchParams.get('sig'), 400, 'invalid_request', '登录请求无效');
  const id = existingId ?? randomId('req_');
  const expiration = Number(url.searchParams.get('exp')) * 1000;
  await env.DB.prepare(`INSERT INTO authorization_request
    (id, client_id, signed_query, browser_hash, auth_event_id, stage, status, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?) ON CONFLICT(id) DO UPDATE SET signed_query = excluded.signed_query,
    auth_event_id = excluded.auth_event_id, stage = excluded.stage, status = 'pending', expires_at = excluded.expires_at
    WHERE authorization_request.status IN ('pending', 'processing')`)
    .bind(id, clientId, url.searchParams.toString(), await hash(browserToken), authEventId, url.pathname === '/consent' ? 'consent' : 'login', Date.now(), Math.min(expiration || Date.now() + TRANSACTION_TTL, Date.now() + TRANSACTION_TTL)).run();
  return `${env.APP_ORIGIN}${url.pathname}?request=${id}`;
}
