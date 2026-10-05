import { appInputSchema, disableInputSchema, credentialInputSchema, liteLoginSchema, officialLoginSchema, consentInputSchema, type LoginMethod } from '@liteauth/contracts';
import { Hono, type Context } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import { getCookie, setCookie } from 'hono/cookie';
import { secureHeaders } from 'hono/secure-headers';
import { APIError } from 'better-auth';
import { createAuth, type AuthSession, type LiteAuth } from './auth';
import { beginConnect, revokeCredentials } from './connect';
import { cookieName, TRANSACTION_TTL, type Env } from './env';
import { hash, randomId } from './crypto';
import { HttpError, invariant } from './errors';
import { appEligibility, captureRedirect, getRequest } from './requests';
import { rateLimit } from './db/policy';
import { createApp, deleteApp, getApp, listApps, readAppSecret, rotateAppSecret, updateApp } from './apps';
import { disableApp, disableUser, listAudit, listLoginRecords, listUsers, getAdminUser, listUserApps, listConnectRecords, parseAdminUserFilters, parseAdminConnectFilters } from './admin';
import { cleanup, cleanupHistory, HISTORY_CRON } from './cleanup';
import { audit, authorizationOutcomeStatement, parseAuditFilters } from './audit';

type Variables = { auth: LiteAuth; checkedSession?: AuthSession | null; browserToken?: string };
type AppEnv = { Bindings: Env; Variables: Variables };
type Ctx = Context<AppEnv>;
const app = new Hono<AppEnv>();
const MAX_BODY_SIZE = 64 * 1024;
const protocolPaths = new Set(['/api/user', '/api/auth/oauth2/token', '/api/auth/oauth2/userinfo', '/api/auth/oauth2/introspect', '/api/auth/oauth2/revoke', '/oauth2/token', '/oauth2/userinfo', '/oauth2/introspect', '/oauth2/revoke']);

function isProtocolPath(path: string) {
  return protocolPaths.has(path);
}

app.use('*', secureHeaders());
app.use('*', async (c, next) => {
  c.set('auth', createAuth(c.env));
  c.header('Cache-Control', 'no-store');
  await next();
});

app.use('*', async (c, next) => {
  const publicMetadata = c.req.path === '/api/auth/jwks' || c.req.path.startsWith('/api/auth/.well-known/') || c.req.path.startsWith('/.well-known/');
  if (protocolPaths.has(c.req.path) || publicMetadata) {
    const origin = c.req.header('Origin');
    if (origin) {
      c.header('Access-Control-Allow-Origin', origin);
      c.header('Vary', 'Origin');
      c.header('Access-Control-Allow-Methods', publicMetadata ? 'GET, OPTIONS' : 'POST, GET, OPTIONS');
      c.header('Access-Control-Allow-Headers', 'Authorization, Content-Type');
    }
    if (c.req.method === 'OPTIONS') return c.body(null, 204);
  } else if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(c.req.method)) {
    invariant(c.req.header('Origin') === c.env.APP_ORIGIN, 403, 'invalid_origin', '请求无效，请刷新页面后重试');
  }
  await next();
});
app.use('*', bodyLimit({
  maxSize: MAX_BODY_SIZE,
  onError: (c) => isProtocolPath(c.req.path)
    ? c.json({ error: 'invalid_request', error_description: 'Payload too large' }, 413)
    : c.json({ error: { code: 'payload_too_large', message: '请求内容过大' } }, 413),
}));

async function sessionOf(c: Ctx, required = false) {
  if (c.get('checkedSession') === undefined) {
    const session = await c.get('auth').api.getSession({ headers: c.req.raw.headers });
    if (session) {
      const valid = await c.env.DB.prepare(`SELECT e.id FROM auth_event e JOIN user u ON u.id = e.user_id
        WHERE e.id = ? AND e.user_id = ? AND e.revoked_at IS NULL AND u.disabled = 0`)
        .bind(session.session.authEventId, session.user.id).first();
      c.set('checkedSession', valid ? session : null);
    } else c.set('checkedSession', null);
  }
  const value = c.get('checkedSession') ?? null;
  if (required) invariant(value, 401, 'login_required', '请先登录');
  return value;
}

async function sessionEvent(c: Ctx) {
  const session = await sessionOf(c);
  return session ? c.env.DB.prepare('SELECT login_method, trust_level FROM auth_event WHERE id = ? AND user_id = ? AND revoked_at IS NULL')
    .bind(session.session.authEventId, session.user.id).first<{ login_method: LoginMethod; trust_level: number | null }>() : null;
}

function browserToken(c: Ctx) {
  const cached = c.get('browserToken');
  if (cached) return cached;
  const name = cookieName(c.env, 'browser');
  const token = getCookie(c, name) ?? randomId('browser_');
  if (!getCookie(c, name)) setCookie(c, name, token, { path: '/', httpOnly: true, secure: c.env.APP_ORIGIN.startsWith('https:'), sameSite: 'Lax', maxAge: 7 * 24 * 3600 });
  c.set('browserToken', token);
  return token;
}

function internalHeaders(c: Ctx, protocol = false) {
  const headers = new Headers(c.req.raw.headers);
  if (protocol) {
    headers.delete('Cookie'); headers.delete('Origin'); headers.delete('Referer');
  } else {
    headers.set('Cookie', `${headers.get('Cookie') ?? ''}; ${cookieName(c.env, 'browser')}=${browserToken(c)}`);
  }
  return headers;
}

function jsonHeaders(c: Ctx) {
  const headers = internalHeaders(c);
  headers.set('Content-Type', 'application/json');
  headers.set('Origin', c.env.APP_ORIGIN);
  headers.set('Accept', 'application/json');
  return headers;
}

async function safeInput<T>(c: Ctx, schema: { parse(value: unknown): T }) {
  let value: unknown;
  try { value = await c.req.json(); } catch { throw new HttpError(400, 'invalid_request', '请检查填写内容'); }
  try { return schema.parse(value); } catch { throw new HttpError(400, 'invalid_request', '请检查填写内容'); }
}

async function forwardProvider(c: Ctx, response: Response, requestId?: string, asJson = false) {
  let redirect = response.headers.get('Location');
  if (!redirect && response.ok && response.headers.get('Content-Type')?.includes('application/json')) {
    const body = await response.clone().json() as { redirect?: boolean; url?: string };
    if (body.redirect && typeof body.url === 'string') redirect = body.url;
  }
  if (redirect) {
    const session = await sessionOf(c);
    const normalized = await captureRedirect(c.env, redirect, browserToken(c), session?.session.authEventId ?? null, requestId);
    const target = new URL(normalized, c.env.APP_ORIGIN);
    if (requestId && (target.origin !== c.env.APP_ORIGIN || !['/login', '/consent'].includes(target.pathname))) {
      await c.env.DB.prepare("UPDATE authorization_request SET status = 'completed' WHERE id = ? AND status IN ('pending', 'processing')").bind(requestId).run();
    }
    if (asJson) return c.json({ redirect_url: normalized });
    const headers = new Headers(response.headers);
    headers.set('Location', normalized);
    return c.newResponse(null, 302, responseHeaders(headers));
  }
  return c.newResponse(response.body, response.status as 200, responseHeaders(response.headers));
}

function responseHeaders(headers: Headers): Record<string, string | string[]> {
  const output: Record<string, string | string[]> = Object.fromEntries(headers);
  const cookies = headers.getSetCookie();
  if (cookies.length) output['Set-Cookie'] = cookies;
  return output;
}

async function beginAuthorization(c: Ctx) {
  const url = new URL(c.req.url);
  if (url.searchParams.has('resource')) return c.json({ error: 'invalid_target', error_description: 'Resource indicators are not supported' }, 400);
  if (!url.searchParams.get('scope')) url.searchParams.set('scope', 'profile');
  const clientId = url.searchParams.get('client_id') ?? '';
  const token = browserToken(c);
  await rateLimit(c.env.DB, `authorize:${c.req.header('CF-Connecting-IP') ?? await hash(token)}`, 30);
  const session = await sessionOf(c);
  const requestId = randomId('req_');
  await c.env.DB.prepare(`INSERT INTO authorization_request (id, client_id, signed_query, browser_hash, auth_event_id, stage, status, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?, 'authorize', 'processing', ?, ?)`)
    .bind(requestId, clientId, url.searchParams.toString(), await hash(token), session?.session.authEventId ?? null, Date.now(), Date.now() + TRANSACTION_TTL).run();
  url.pathname = '/api/auth/oauth2/authorize';
  const auth = createAuth(c.env, clientId, requestId);
  const response = await auth.handler(new Request(url, { method: 'GET', headers: internalHeaders(c) }));
  if (!response.ok && !response.headers.get('Location')) await c.env.DB.batch([
    authorizationOutcomeStatement(c.env.DB, 'request', "r.id = ? AND r.status IN ('pending','processing')", [requestId], 'failed', 'authorization_failed'),
    c.env.DB.prepare("UPDATE authorization_request SET status = 'canceled' WHERE id = ? AND status IN ('pending','processing')").bind(requestId),
  ]);
  return forwardProvider(c, response, requestId);
}

app.get('/api/health', (c) => c.json({ status: 'ok' }));
app.get('/api/session', async (c) => {
  const session = await sessionOf(c);
  if (!session) return c.json({ user: null, login_method: null });
  const event = await c.env.DB.prepare('SELECT login_method FROM auth_event WHERE id = ?').bind(session.session.authEventId).first<{ login_method: LoginMethod }>();
  return c.json({ user: { id: session.user.id, linuxdo_id: session.user.linuxdoId, username: session.user.username, name: session.user.name, avatar_url: session.user.image ?? null, is_admin: session.user.isAdmin, disabled: session.user.disabled }, login_method: event?.login_method ?? null });
});
app.get('/api/login-context', async (c) => {
  const id = c.req.query('request');
  if (!id) { browserToken(c); return c.json({ request: null, application: null, official_available: true, eligibility: appEligibility({ lite_only: 0, min_trust_level: 0 }, await sessionEvent(c)) }); }
  const { app: downstream } = await getRequest(c.env, id, browserToken(c));
  return c.json({ request: id, application: { id: downstream.id, name: downstream.name, lite_only: Boolean(downstream.lite_only), min_trust_level: downstream.min_trust_level }, official_available: !downstream.lite_only, eligibility: appEligibility(downstream, await sessionEvent(c)) });
});
app.post('/api/login/official', async (c) => {
  const input = await safeInput(c, officialLoginSchema);
  await rateLimit(c.env.DB, `login:${c.req.header('CF-Connecting-IP') ?? await hash(browserToken(c))}`, 15);
  return c.json(await beginConnect(c.env, browserToken(c), 'official_connect', input));
});
app.post('/api/login/lite', async (c) => {
  const input = await safeInput(c, liteLoginSchema);
  await rateLimit(c.env.DB, `login:${c.req.header('CF-Connecting-IP') ?? await hash(browserToken(c))}`, 15);
  return c.json(await beginConnect(c.env, browserToken(c), 'lite_self_app', input));
});
app.get('/auth/connect/callback', async (c) => {
  const url = new URL(c.req.url); url.pathname = '/api/auth/connect/callback';
  return forwardProvider(c, await c.get('auth').handler(new Request(url, { headers: c.req.raw.headers })));
});
app.get('/auth/resume', async (c) => {
  const id = c.req.query('request');
  invariant(id, 400, 'invalid_request', '登录请求无效');
  const { request, app: downstream } = await getRequest(c.env, id, browserToken(c));
  const session = await sessionOf(c, true);
  invariant(session && request.auth_event_id === session.session.authEventId, 400, 'identity_mismatch', '登录账号已变化，请重新开始');
  const response = await createAuth(c.env, downstream.client_id, id).handler(new Request(`${c.env.APP_ORIGIN}/api/auth/connect/resume`, {
    method: 'POST', headers: jsonHeaders(c),
    body: JSON.stringify({ oauth_query: request.signed_query }),
  }));
  return forwardProvider(c, response, id);
});
app.get('/api/credentials', async (c) => {
  const session = await sessionOf(c, true);
  const credential = await c.env.DB.prepare("SELECT client_id, updated_at, status FROM upstream_credential WHERE owner_user_id = ? AND kind = 'self' AND status = 'active'")
    .bind(session!.user.id).first<{ client_id: string; updated_at: number; status: string }>();
  return c.json({ credential: credential ? { ...credential, updated_at: new Date(credential.updated_at).toISOString() } : null });
});
app.post('/api/credentials/verify', async (c) => {
  const session = await sessionOf(c, true);
  const input = await safeInput(c, credentialInputSchema);
  await rateLimit(c.env.DB, `verify:${session!.user.id}`, 10);
  const user = await c.env.DB.prepare('SELECT id, linuxdo_id, username, credential_epoch, disabled FROM user WHERE id = ?').bind(session!.user.id).first<{ id: string; linuxdo_id: number; username: string; credential_epoch: number; disabled: number }>();
  invariant(user, 401, 'login_required', '请先登录');
  return c.json(await beginConnect(c.env, browserToken(c), 'lite_self_app', { username: user.username }, user, input));
});
app.delete('/api/credentials', async (c) => { const session = await sessionOf(c, true); await revokeCredentials(c.env, session!.user.id); return c.json({ ok: true }); });
app.post('/api/logout', async (c) => {
  const session = await sessionOf(c);
  const response = await c.get('auth').handler(new Request(`${c.env.APP_ORIGIN}/api/auth/sign-out`, { method: 'POST', headers: jsonHeaders(c), body: '{}' }));
  if (response.ok && session) await audit(c.env.DB, 'account.logout', session.user.id, session.user.id);
  return forwardProvider(c, response);
});
app.get('/api/apps', async (c) => { const session = await sessionOf(c, true); return c.json(await listApps(c.env, session!.user.id)); });
app.get('/api/apps/:id', async (c) => { const session = await sessionOf(c, true); return c.json(await getApp(c.env, c.req.param('id'), session!.user.id, Boolean(session!.user.isAdmin))); });
app.get('/api/apps/:id/secret', async (c) => { const session = await sessionOf(c, true); return c.json(await readAppSecret(c.env, c.req.param('id'), session!.user.id, Boolean(session!.user.isAdmin))); });
app.get('/api/apps/:id/login-records', async (c) => { const session = await sessionOf(c, true); return c.json(await listLoginRecords(c.env, session!.user.id, c.req.param('id'), Boolean(session!.user.isAdmin), parseAuditFilters(c.req.query()))); });
app.post('/api/apps', async (c) => {
  const session = await sessionOf(c, true); await rateLimit(c.env.DB, `app-create:${session!.user.id}`, 10);
  return c.json(await createApp(c.env, c.get('auth'), c.req.raw.headers, await safeInput(c, appInputSchema)), 201);
});
app.patch('/api/apps/:id', async (c) => { const session = await sessionOf(c, true); return c.json(await updateApp(c.env, c.req.param('id'), session!.user.id, Boolean(session!.user.isAdmin), await safeInput(c, appInputSchema))); });
app.delete('/api/apps/:id', async (c) => { const session = await sessionOf(c, true); await deleteApp(c.env, c.req.param('id'), session!.user.id, Boolean(session!.user.isAdmin)); return c.json({ ok: true }); });
app.post('/api/apps/:id/rotate-secret', async (c) => { const session = await sessionOf(c, true); return c.json(await rotateAppSecret(c.env, c.get('auth'), c.req.raw.headers, c.req.param('id'), session!.user.id, Boolean(session!.user.isAdmin))); });
app.get('/api/admin/users', async (c) => { const session = await sessionOf(c, true); return c.json(await listUsers(c.env, session!.user.id, parseAdminUserFilters(c.req.query()))); });
app.get('/api/admin/users/:id', async (c) => { const session = await sessionOf(c, true); return c.json(await getAdminUser(c.env, session!.user.id, c.req.param('id'))); });
app.get('/api/admin/users/:id/apps', async (c) => { const session = await sessionOf(c, true); return c.json(await listUserApps(c.env, session!.user.id, c.req.param('id'), parseAdminUserFilters(c.req.query()))); });
app.get('/api/admin/users/:id/connect-records', async (c) => { const session = await sessionOf(c, true); return c.json(await listConnectRecords(c.env, session!.user.id, c.req.param('id'), parseAdminConnectFilters(c.req.query()))); });
app.get('/api/admin/audit', async (c) => { const session = await sessionOf(c, true); return c.json(await listAudit(c.env, session!.user.id, parseAuditFilters(c.req.query()))); });
app.get('/api/admin/apps', async (c) => { const session = await sessionOf(c, true); invariant(session!.user.isAdmin, 403, 'admin_required', '没有权限'); return c.json(await listApps(c.env, session!.user.id, true)); });
app.post('/api/admin/users/:id/disable', async (c) => { const session = await sessionOf(c, true); const input = await safeInput(c, disableInputSchema); await disableUser(c.env, session!.user.id, c.req.param('id'), input.disabled); return c.json({ ok: true }); });
app.post('/api/admin/apps/:id/disable', async (c) => { const session = await sessionOf(c, true); const input = await safeInput(c, disableInputSchema); await disableApp(c.env, session!.user.id, c.req.param('id'), input.disabled); return c.json({ ok: true }); });
app.get('/api/consent', async (c) => {
  const id = c.req.query('request'); invariant(id, 400, 'invalid_request', '授权请求无效');
  const { request, app: downstream } = await getRequest(c.env, id, browserToken(c));
  const session = await sessionOf(c, true);
  invariant(request.stage === 'consent' && request.auth_event_id === session!.session.authEventId, 400, 'request_expired', '授权请求已变化，请重新开始');
  const event = await sessionEvent(c);
  invariant(event, 401, 'login_required', '请先登录');
  return c.json({ request: id, application: { id: downstream.id, name: downstream.name, lite_only: Boolean(downstream.lite_only), min_trust_level: downstream.min_trust_level }, scopes: new URLSearchParams(request.signed_query).get('scope')?.split(' ') ?? [], login_method: event.login_method, eligibility: appEligibility(downstream, event) });
});
app.post('/api/consent', async (c) => {
  const input = await safeInput(c, consentInputSchema);
  const { request, app: downstream } = await getRequest(c.env, input.request, browserToken(c));
  const session = await sessionOf(c, true);
  invariant(request.stage === 'consent' && request.auth_event_id === session!.session.authEventId, 400, 'request_expired', '授权请求已变化，请重新开始');
  const eligibility = appEligibility(downstream, await sessionEvent(c));
  invariant(!input.accept || eligibility.allowed, 403, eligibility.reason ?? 'policy_changed', eligibility.reason === 'trust_level_required' ? `此应用要求等级达到 ${downstream.min_trust_level} 级` : '此应用仅支持 Lite 登录');
  const claimed = await c.env.DB.prepare("UPDATE authorization_request SET status = 'processing' WHERE id = ? AND status = 'pending' RETURNING id").bind(input.request).first();
  invariant(claimed, 400, 'request_expired', '授权请求已过期，请重新开始');
  const response = await createAuth(c.env, downstream.client_id, input.request).handler(new Request(`${c.env.APP_ORIGIN}/api/auth/oauth2/consent`, {
    method: 'POST', headers: jsonHeaders(c),
    body: JSON.stringify({ accept: input.accept, oauth_query: request.signed_query }),
  }));
  if (!input.accept || !response.ok) await c.env.DB.batch([
    authorizationOutcomeStatement(c.env.DB, 'request', "r.id = ? AND r.status IN ('pending','processing')", [input.request], !input.accept ? 'denied' : 'failed', !input.accept ? 'user_denied' : 'authorization_failed'),
    c.env.DB.prepare("UPDATE authorization_request SET status = 'canceled' WHERE id = ? AND status IN ('pending','processing')").bind(input.request),
  ]);
  return forwardProvider(c, response, input.request, true);
});

app.get('/api/auth/oauth2/authorize', beginAuthorization);
app.get('/oauth2/authorize', beginAuthorization);
app.all('/api/auth/*', async (c) => {
  const allowed = new Set(['/api/auth/oauth2/token', '/api/auth/oauth2/userinfo', '/api/auth/oauth2/introspect', '/api/auth/oauth2/revoke', '/api/auth/jwks', '/api/auth/.well-known/openid-configuration', '/api/auth/.well-known/oauth-authorization-server', '/api/auth/sign-out']);
  if (!allowed.has(c.req.path)) return c.json({ error: { code: 'not_found', message: '页面不存在' } }, 404);
  if (protocolPaths.has(c.req.path)) {
    const body = c.req.method === 'POST' ? await c.req.text() : undefined;
    let parameters: Record<string, unknown> = {};
    if (body) {
      try { parameters = c.req.header('Content-Type')?.includes('application/json') ? JSON.parse(body) as Record<string, unknown> : Object.fromEntries(new URLSearchParams(body)); }
      catch { return c.json({ error: 'invalid_request', error_description: 'Invalid request body' }, 400); }
      if (!parameters || typeof parameters !== 'object' || Array.isArray(parameters)) return c.json({ error: 'invalid_request', error_description: 'Invalid request body' }, 400);
    }
    if ('resource' in parameters || new URL(c.req.url).searchParams.has('resource')) return c.json({ error: 'invalid_target', error_description: 'Resource indicators are not supported' }, 400);
    await rateLimit(c.env.DB, `protocol:${c.req.header('CF-Connecting-IP') ?? 'local'}`, 120);
    return forwardProvider(c, await c.get('auth').handler(new Request(c.req.url, { method: c.req.method, headers: internalHeaders(c, true), body })));
  }
  const response = await c.get('auth').handler(c.req.raw);
  if (response.ok && c.req.path.startsWith('/api/auth/.well-known/')) {
    const metadata = await response.json() as Record<string, unknown>;
    // Better Auth describes all built-in capabilities; the public facade exposes a narrower set.
    for (const field of ['end_session_endpoint', 'backchannel_logout_supported', 'backchannel_logout_session_supported',
      'token_endpoint_auth_signing_alg_values_supported', 'introspection_endpoint_auth_signing_alg_values_supported',
      'revocation_endpoint_auth_signing_alg_values_supported', 'dpop_signing_alg_values_supported']) delete metadata[field];
    metadata.token_endpoint_auth_methods_supported = ['client_secret_post', 'none'];
    metadata.introspection_endpoint_auth_methods_supported = ['client_secret_post'];
    metadata.revocation_endpoint_auth_methods_supported = ['client_secret_post', 'none'];
    if ('prompt_values_supported' in metadata) metadata.prompt_values_supported = ['none', 'login', 'consent'];
    return c.json(metadata);
  }
  return forwardProvider(c, response);
});
app.all('/oauth2/:endpoint', async (c) => {
  const endpoint = c.req.param('endpoint');
  if (!['token', 'userinfo', 'introspect', 'revoke'].includes(endpoint)) return c.json({ error: { code: 'not_found', message: '页面不存在' } }, 404);
  const url = new URL(c.req.url); url.pathname = `/api/auth/oauth2/${endpoint}`;
  return app.fetch(new Request(url, c.req.raw), c.env);
});
app.get('/api/user', async (c) => {
  await rateLimit(c.env.DB, `profile:${c.req.header('CF-Connecting-IP') ?? 'local'}`, 120);
  const url = new URL('/api/auth/connect/user', c.env.APP_ORIGIN);
  return forwardProvider(c, await c.get('auth').handler(new Request(url, { headers: internalHeaders(c, true) })));
});
app.get('/.well-known/oauth-authorization-server/api/auth', async (c) => {
  const url = new URL(c.req.url); url.pathname = '/api/auth/.well-known/oauth-authorization-server';
  return app.fetch(new Request(url, c.req.raw), c.env);
});
app.get('/.well-known/:document', async (c) => {
  if (!['openid-configuration', 'oauth-authorization-server'].includes(c.req.param('document'))) return c.json({ error: { code: 'not_found', message: '页面不存在' } }, 404);
  const url = new URL(c.req.url); url.pathname = `/api/auth/.well-known/${c.req.param('document')}`;
  return app.fetch(new Request(url, c.req.raw), c.env);
});

app.notFound((c) => c.json({ error: { code: 'not_found', message: '页面不存在' } }, 404));
app.onError((error, c) => {
  if (error instanceof HttpError) return c.json({ error: { code: error.code, message: error.message } }, error.status as 400);
  if (error instanceof APIError) {
    if (error.body?.error === 'invalid_redirect_uri') return c.json({ error: { code: 'invalid_redirect_uri', message: '请检查回调地址，正式地址使用 HTTPS，本地地址使用 HTTP' } }, 400);
    return c.json({ error: { code: 'request_failed', message: '操作未完成，请重试' } }, error.statusCode as 400);
  }
  return c.json({ error: { code: 'server_error', message: '操作未完成，请稍后再试' } }, 500);
});

export { app, sessionOf, safeInput };
export default { fetch: app.fetch, scheduled: (controller: ScheduledController, env: Env, ctx: ExecutionContext) => { ctx.waitUntil(controller.cron === HISTORY_CRON ? cleanupHistory(env) : cleanup(env)); } };
