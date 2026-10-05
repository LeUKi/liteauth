import { env } from 'cloudflare:workers';
import { afterEach, describe, expect, it, vi } from 'vitest';
import * as oidc from 'openid-client';
import { createAuth } from '../src/auth';
import { createApp } from '../src/apps';
import { app } from '../src/index';
import { makeSignature } from 'better-auth/crypto';
import { randomId } from '../src/crypto';
import { setAppPolicy } from '../src/db/policy';

const rpCallback = 'https://rp.example/callback';
function cookieFrom(response: Response) { return response.headers.getSetCookie().map(cookie => cookie.split(';')[0]).join('; '); }
afterEach(() => vi.unstubAllGlobals());

async function ownerApp(liteOnly: boolean, minimum = 0) {
  const auth = createAuth(env); const context = await auth.$context;
  const user = await context.internalAdapter.createUser({ name: 'Owner', email: '456@linuxdo.liteauth.invalid', emailVerified: false, linuxdoId: 456, username: 'owner' }, { method: 'linuxdo-connect' });
  const event = randomId('ae_');
  await env.DB.prepare('INSERT INTO auth_event (id,user_id,login_method,upstream_client_id,trust_level,profile,created_at) VALUES (?,?,?,?,?,?,?)')
    .bind(event, user.id, 'official_connect', 'platform-test-client', 0, JSON.stringify({ id: 456, username: 'owner', trust_level: 0 }), Date.now()).run();
  const session = await context.internalAdapter.createSession(user.id, false, { authEventId: event }, true);
  const cookie = `${context.authCookies.sessionToken.name}=${encodeURIComponent(`${session!.token}.${await makeSignature(session!.token, env.BETTER_AUTH_SECRET)}`)}`;
  const client = await createApp(env, auth, new Headers({ Cookie: cookie, Origin: env.APP_ORIGIN }), { name: 'Lite RP', redirect_uris: [rpCallback], lite_only: liteOnly, client_type: 'confidential', pkce_required: true });
  if (minimum) await setAppPolicy(env.DB, client.app.client_id, liteOnly, minimum);
  return { client, cookie };
}

describe('browser-bound public authorization facade', () => {
  it.each([
    { prompt: undefined, maxAge: undefined },
    { prompt: 'login', maxAge: undefined },
    { prompt: undefined, maxAge: '0' },
    { prompt: 'login consent', maxAge: '0' },
  ])('runs login, consent and token issuance with prompt=$prompt and max_age=$maxAge', async ({ prompt, maxAge }) => {
    const { client } = await ownerApp(true);
    const verifier = oidc.randomPKCECodeVerifier();
    const query = new URLSearchParams({ client_id: client.app.client_id, redirect_uri: rpCallback, response_type: 'code', state: 'rp-state', code_challenge: await oidc.calculatePKCECodeChallenge(verifier), code_challenge_method: 'S256' });
    const oidcFlow = Boolean(prompt || maxAge);
    if (prompt) query.set('prompt', prompt);
    if (maxAge) query.set('max_age', maxAge);
    if (oidcFlow) { query.set('scope', 'openid profile'); query.set('nonce', 'fresh-nonce'); }
    const authorize = await app.request(`/oauth2/authorize?${query}`, { headers: { Accept: 'text/html' } }, env);
    expect(authorize.status).toBe(302);
    const requestId = new URL(authorize.headers.get('Location')!).searchParams.get('request')!;
    let cookie = cookieFrom(authorize); expect(cookie).toContain('liteauth.browser=');
    const context = await app.request(`/api/login-context?request=${requestId}`, { headers: { Cookie: cookie } }, env);
    expect(await context.json()).toMatchObject({ application: { lite_only: true }, official_available: false });
    const directOfficial = await app.request('/api/login/official', { method: 'POST', headers: { Cookie: cookie, Origin: env.APP_ORIGIN, 'Content-Type': 'application/json' }, body: JSON.stringify({ request: requestId }) }, env);
    expect(directOfficial.status).toBe(403);
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const url = input instanceof Request ? input.url : String(input);
      return url.endsWith('/oauth2/token') ? Response.json({ access_token: 'upstream-fixture-token', token_type: 'Bearer' }) : Response.json({ id: 123, username: 'alice', name: 'Alice', trust_level: 0, active: true, silenced: false });
    }));
    const login = await app.request('/api/login/lite', { method: 'POST', headers: { Cookie: cookie, Origin: env.APP_ORIGIN, 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'alice', client_id: 'alice-self-app', client_secret: 'alice-secret', request: requestId }) }, env);
    expect(login.status).toBe(200);
    const loginBody = await login.json() as { redirect_url: string };
    const upstreamState = new URL(loginBody.redirect_url).searchParams.get('state');
    const callback = await app.request(`/auth/connect/callback?code=upstream-code&state=${upstreamState}`, { headers: { Cookie: cookie } }, env);
    expect(callback.status).toBe(302); expect(callback.headers.get('Location')).toBe(`${env.APP_ORIGIN}/auth/resume?request=${requestId}`);
    cookie += `; ${cookieFrom(callback)}`;
    const resumed = await app.request(`/auth/resume?request=${requestId}`, { headers: { Cookie: cookie } }, env); expect(resumed.status).toBe(302);
    expect(new URL(resumed.headers.get('Location')!).pathname).toBe('/consent');
    const consentId = new URL(resumed.headers.get('Location')!).searchParams.get('request')!; expect(consentId).toBe(requestId);
    const consentContext = await app.request(`/api/consent?request=${consentId}`, { headers: { Cookie: cookie } }, env);
    expect(await consentContext.json()).toMatchObject({ application: { lite_only: true }, login_method: 'lite_self_app', scopes: oidcFlow ? ['openid', 'profile'] : ['profile'] });
    const consent = await app.request('/api/consent', { method: 'POST', headers: { Cookie: cookie, Origin: env.APP_ORIGIN, 'Content-Type': 'application/json' }, body: JSON.stringify({ request: consentId, accept: true }) }, env);
    expect(consent.status).toBe(200); const downstream = await consent.json() as { redirect_url: string };
    const downstreamUrl = new URL(downstream.redirect_url); expect(downstreamUrl.searchParams.get('state')).toBe('rp-state');
    const token = await app.request('/oauth2/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'authorization_code', code: downstreamUrl.searchParams.get('code')!, code_verifier: verifier, client_id: client.app.client_id, client_secret: client.client_secret!, redirect_uri: rpCallback }) }, env);
    expect(token.status).toBe(200); const tokenBody = await token.json() as { access_token: string; id_token?: string };
    if (oidcFlow) {
      expect(tokenBody.id_token).toBeTypeOf('string');
      const payload = tokenBody.id_token!.split('.')[1];
      const claims = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(payload.replaceAll('-', '+').replaceAll('_', '/')), character => character.charCodeAt(0)))) as { auth_time: number; nonce: string; login_method: string };
      const signedRequest = await env.DB.prepare('SELECT created_at FROM authorization_request WHERE id = ?').bind(requestId).first<{ created_at: number }>();
      expect(claims.auth_time).toBeGreaterThanOrEqual(Math.floor(signedRequest!.created_at / 1000));
      expect(claims).toMatchObject({ nonce: 'fresh-nonce', login_method: 'lite_self_app' });
    } else expect(tokenBody.id_token).toBeUndefined();
    const profile = await app.request('/api/user', { headers: { Authorization: `Bearer ${tokenBody.access_token}` } }, env);
    expect(profile.status).toBe(200); expect(await profile.json()).toMatchObject({ id: 123, username: 'alice', login_method: 'lite_self_app', upstream_client_id: 'alice-self-app' });
    expect((await app.request('/api/consent', { method: 'POST', headers: { Cookie: cookie, Origin: env.APP_ORIGIN, 'Content-Type': 'application/json' }, body: JSON.stringify({ request: consentId, accept: true }) }, env)).status).toBe(400);
  });

  it('rejects resume by an existing session before the requested fresh upstream login', async () => {
    const { client, cookie } = await ownerApp(false);
    await env.DB.batch([
      env.DB.prepare('UPDATE session SET created_at = ?').bind(Date.now() - 60_000),
      env.DB.prepare('UPDATE auth_event SET created_at = ?').bind(Date.now() - 60_000),
    ]);
    const query = new URLSearchParams({ client_id: client.app.client_id, redirect_uri: rpCallback, response_type: 'code', scope: 'openid profile', prompt: 'login', max_age: '0', nonce: 'fresh-nonce', code_challenge: await oidc.calculatePKCECodeChallenge(oidc.randomPKCECodeVerifier()), code_challenge_method: 'S256' });
    const authorization = await app.request(`/oauth2/authorize?${query}`, { headers: { Cookie: cookie } }, env);
    expect(authorization.status).toBe(302);
    const location = new URL(authorization.headers.get('Location')!);
    expect(location.pathname).toBe('/login');
    const requestId = location.searchParams.get('request')!;
    const resumed = await app.request(`/auth/resume?request=${requestId}`, { headers: { Cookie: `${cookie}; ${cookieFrom(authorization)}` } }, env);
    expect(resumed.status).toBe(400);
    expect(await env.DB.prepare('SELECT id FROM verification').first()).toBeNull();
    expect(await env.DB.prepare('SELECT id FROM oauth_access_token').first()).toBeNull();
    expect((await app.request('/api/auth/connect/resume', { method: 'POST', headers: { Cookie: cookie, Origin: env.APP_ORIGIN, 'Content-Type': 'application/json' }, body: '{}' }, env)).status).toBe(404);
  });

  it('rejects an opaque authorization request in another browser and preserves cancellation through a toggle back', async () => {
    const { client, cookie } = await ownerApp(false);
    const parameters = new URLSearchParams({ client_id: client.app.client_id, redirect_uri: rpCallback, response_type: 'code', scope: 'profile', code_challenge: await oidc.calculatePKCECodeChallenge(oidc.randomPKCECodeVerifier()), code_challenge_method: 'S256' });
    const authorize = await app.request(`/oauth2/authorize?${parameters}`, { headers: { Cookie: cookie } }, env); expect(authorize.status).toBe(302);
    const id = new URL(authorize.headers.get('Location')!).searchParams.get('request')!;
    const browserCookie = cookieFrom(authorize); const combinedCookie = `${cookie}; ${browserCookie}`;
    expect((await app.request(`/api/consent?request=${id}`, { headers: { Cookie: 'liteauth.browser=other' } }, env)).status).toBe(400);
    await setAppPolicy(env.DB, client.app.client_id, true); await setAppPolicy(env.DB, client.app.client_id, false);
    expect((await app.request(`/api/consent?request=${id}`, { headers: { Cookie: combinedCookie } }, env)).status).toBe(400);
    expect(await env.DB.prepare('SELECT id FROM oauth_access_token').first()).toBeNull();
  });

  it('keeps a verified low-level identity and binding, then authorizes only after fresh qualifying verification', async () => {
    const { client } = await ownerApp(true, 2);
    const verifier = oidc.randomPKCECodeVerifier();
    const query = new URLSearchParams({ client_id: client.app.client_id, redirect_uri: rpCallback, response_type: 'code', scope: 'openid profile', nonce: 'level-nonce', state: 'level-state', code_challenge: await oidc.calculatePKCECodeChallenge(verifier), code_challenge_method: 'S256' });
    const authorize = await app.request(`/oauth2/authorize?${query}`, {}, env);
    const requestId = new URL(authorize.headers.get('Location')!).searchParams.get('request')!;
    let cookie = cookieFrom(authorize);
    let verifiedLevel = 1;
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const url = input instanceof Request ? input.url : String(input);
      return url.endsWith('/oauth2/token') ? Response.json({ access_token: 'upstream-level-token', token_type: 'Bearer' })
        : Response.json({ id: 123, username: 'alice', name: 'Alice', trust_level: verifiedLevel, active: true, silenced: false });
    }));
    const login = await app.request('/api/login/lite', {
      method: 'POST', headers: { Cookie: cookie, Origin: env.APP_ORIGIN, 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'alice', client_id: 'alice-self-app', client_secret: 'alice-secret', request: requestId }),
    }, env);
    const loginBody = await login.json() as { redirect_url: string };
    const callback = await app.request(`/auth/connect/callback?code=low-code&state=${new URL(loginBody.redirect_url).searchParams.get('state')}`, { headers: { Cookie: cookie } }, env);
    expect(callback.headers.get('Location')).toBe(`${env.APP_ORIGIN}/login?request=${requestId}`);
    cookie += `; ${cookieFrom(callback)}`;
    const context = await app.request(`/api/login-context?request=${requestId}`, { headers: { Cookie: cookie } }, env);
    expect(await context.json()).toMatchObject({ application: { min_trust_level: 2 }, eligibility: { allowed: false, reason: 'trust_level_required', trust_level: 1 } });
    expect(await env.DB.prepare('SELECT status,stage FROM authorization_request WHERE id=?').bind(requestId).first()).toMatchObject({ status: 'pending', stage: 'login' });
    expect(await env.DB.prepare("SELECT status FROM upstream_credential WHERE client_id='alice-self-app'").first()).toMatchObject({ status: 'active' });
    expect((await app.request(`/auth/resume?request=${requestId}`, { headers: { Cookie: cookie } }, env)).ok).toBe(false);
    expect(await env.DB.prepare('SELECT id FROM verification').first()).toBeNull();
    expect(await env.DB.prepare('SELECT id FROM oauth_access_token').first()).toBeNull();

    verifiedLevel = 3;
    const fresh = await app.request('/api/login/lite', {
      method: 'POST', headers: { Cookie: cookie, Origin: env.APP_ORIGIN, 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'alice', request: requestId }),
    }, env);
    const freshBody = await fresh.json() as { redirect_url: string };
    const freshCallback = await app.request(`/auth/connect/callback?code=high-code&state=${new URL(freshBody.redirect_url).searchParams.get('state')}`, { headers: { Cookie: cookie } }, env);
    expect(freshCallback.headers.get('Location')).toBe(`${env.APP_ORIGIN}/auth/resume?request=${requestId}`);
    const oldSession = cookie.split('; ').filter(value => !value.startsWith('liteauth.session='));
    cookie = `${oldSession.join('; ')}; ${cookieFrom(freshCallback)}`;
    const resumed = await app.request(`/auth/resume?request=${requestId}`, { headers: { Cookie: cookie } }, env);
    expect(new URL(resumed.headers.get('Location')!).pathname).toBe('/consent');
    const consent = await app.request('/api/consent', {
      method: 'POST', headers: { Cookie: cookie, Origin: env.APP_ORIGIN, 'Content-Type': 'application/json' }, body: JSON.stringify({ request: requestId, accept: true }),
    }, env);
    expect(consent.ok).toBe(true);
    const downstream = await consent.json() as { redirect_url: string };
    const token = await app.request('/oauth2/token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'authorization_code', code: new URL(downstream.redirect_url).searchParams.get('code')!, code_verifier: verifier, client_id: client.app.client_id, client_secret: client.client_secret!, redirect_uri: rpCallback }),
    }, env);
    expect(token.ok).toBe(true);
    const tokens = await token.json() as { access_token: string };
    const info = await app.request('/api/user', { headers: { Authorization: `Bearer ${tokens.access_token}` } }, env);
    expect(await info.json()).toMatchObject({ id: 123, trust_level: 3, login_method: 'lite_self_app' });
    expect((await env.DB.prepare('SELECT trust_level FROM auth_event WHERE user_id=(SELECT id FROM user WHERE linuxdo_id=123) ORDER BY created_at').all()).results).toEqual([{ trust_level: 1 }, { trust_level: 3 }]);
  });

  it('cannot restore a consumed callback canceled by a minimum increase followed by a decrease', async () => {
    const { client } = await ownerApp(false);
    const query = new URLSearchParams({ client_id: client.app.client_id, redirect_uri: rpCallback, response_type: 'code', scope: 'profile', code_challenge: await oidc.calculatePKCECodeChallenge(oidc.randomPKCECodeVerifier()), code_challenge_method: 'S256' });
    const authorize = await app.request(`/oauth2/authorize?${query}`, {}, env);
    const requestId = new URL(authorize.headers.get('Location')!).searchParams.get('request')!;
    const cookie = cookieFrom(authorize);
    const login = await app.request('/api/login/lite', {
      method: 'POST', headers: { Cookie: cookie, Origin: env.APP_ORIGIN, 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'alice', client_id: 'alice-self-app', client_secret: 'alice-secret', request: requestId }),
    }, env);
    const loginBody = await login.json() as { redirect_url: string };
    let release!: () => void;
    let reached!: () => void;
    const waiting = new Promise<void>(resolve => { reached = resolve; });
    const gate = new Promise<void>(resolve => { release = resolve; });
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url.endsWith('/oauth2/token')) { reached(); await gate; return Response.json({ access_token: 'racing-upstream-token', token_type: 'Bearer' }); }
      return Response.json({ id: 123, username: 'alice', name: 'Alice', trust_level: 4, active: true, silenced: false });
    }));
    const callback = app.request(`/auth/connect/callback?code=racing-code&state=${new URL(loginBody.redirect_url).searchParams.get('state')}`, { headers: { Cookie: cookie } }, env);
    await waiting;
    await setAppPolicy(env.DB, client.app.client_id, false, 2);
    await setAppPolicy(env.DB, client.app.client_id, false, 0);
    release();
    const completed = await callback;
    expect(completed.headers.get('Location')).toContain('/login?error=');
    expect(await env.DB.prepare("SELECT client_id FROM upstream_credential WHERE client_id='alice-self-app'").first()).toBeNull();
    expect(await env.DB.prepare('SELECT id FROM auth_event WHERE user_id=(SELECT id FROM user WHERE linuxdo_id=123)').first()).toBeNull();
    expect(await env.DB.prepare('SELECT status FROM authorization_request WHERE id=?').bind(requestId).first()).toMatchObject({ status: 'canceled' });
    expect(await env.DB.prepare('SELECT status,encrypted_payload FROM connect_transaction WHERE request_id=?').bind(requestId).first()).toMatchObject({ status: 'canceled', encrypted_payload: null });
  });
});
