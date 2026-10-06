import { env } from 'cloudflare:workers';
import { makeSignature } from 'better-auth/crypto';
import { describe, expect, it } from 'vitest';
import { app } from '../src/index';
import { createAuth } from '../src/auth';
import { hash } from '../src/crypto';
import { officialLockStatements } from '../src/account-policy';

async function fixture() {
  const context = await createAuth(env).$context;
  const user = await context.internalAdapter.createUser({ name: 'Alice', username: 'alice', linuxdoId: 789,
    email: '789@linuxdo.liteauth.invalid', emailVerified: false, isAdmin: true }, { method: 'linuxdo-connect' });
  const cookies: Record<string, string> = {};
  for (const method of ['lite_self_app', 'official_connect']) {
    const event = `event-${method}`;
    await env.DB.prepare('INSERT INTO auth_event (id,user_id,login_method,upstream_client_id,trust_level,profile,created_at) VALUES (?,?,?,?,?,?,?)')
      .bind(event, user.id, method, `upstream-${method}`, 2, JSON.stringify({ id: 789, username: 'alice', trust_level: 2 }), Date.now()).run();
    const session = await context.internalAdapter.createSession(user.id, false, { authEventId: event }, true);
    cookies[method] = `${context.authCookies.sessionToken.name}=${encodeURIComponent(`${session!.token}.${await makeSignature(session!.token, env.BETTER_AUTH_SECRET)}`)}`;
  }
  await env.DB.prepare(`INSERT INTO upstream_credential (client_id,owner_user_id,kind,ciphertext,version,status,created_at,updated_at)
    VALUES ('alice-app',?,'self','retained-ciphertext',1,'active',?,?)`).bind(user.id, Date.now(), Date.now()).run();
  return { user, cookies };
}

describe('account channel policy at the public API boundary', () => {
  it('rejects old Lite management authority while retaining a server-only login hint and existing binding', async () => {
    const { user, cookies } = await fixture();
    const headers = { Cookie: cookies.lite_self_app, Origin: env.APP_ORIGIN, 'Content-Type': 'application/json' };
    expect((await app.request('/api/session', { headers }, env)).status).toBe(200);
    const firstVerified = Date.now();
    await env.DB.batch(officialLockStatements(env.DB, user.id, firstVerified));
    const session = await app.request('/api/session', { headers }, env);
    expect(await session.json()).toEqual({ user: null, login_method: null });
    const context = await app.request('/api/login-context', { headers }, env);
    expect(await context.json()).toMatchObject({ official_available: true, lite_available: false,
      eligibility: { allowed: false, reason: 'official_login_required' } });
    for (const path of ['/api/apps', '/api/credentials', '/api/admin/users']) {
      const response = await app.request(path, { headers }, env);
      expect(response.status).toBe(401);
      expect(await response.json()).toMatchObject({ error: { code: 'official_login_required' } });
    }
    for (const [path, input] of [
      ['/api/login/lite', { username: 'alice', client_id: 'new-app', client_secret: 'candidate-secret' }],
      ['/api/credentials/verify', { client_id: 'new-app', client_secret: 'candidate-secret' }],
    ] as const) {
      const response = await app.request(path, { method: 'POST', headers, body: JSON.stringify(input) }, env);
      expect([401, 403]).toContain(response.status);
      expect(await response.json()).toMatchObject({ error: { code: 'official_login_required' } });
    }
    const officialHeaders = { ...headers, Cookie: cookies.official_connect };
    const accepted = await app.request('/api/session', { headers: officialHeaders }, env);
    expect(await accepted.json()).toMatchObject({ user: { id: user.id, official_verified_at: new Date(firstVerified).toISOString() }, login_method: 'official_connect' });
    expect(await (await app.request('/api/credentials', { headers: officialHeaders }, env)).json()).toMatchObject({ credential: { client_id: 'alice-app' } });
    const verify = await app.request('/api/credentials/verify', { method: 'POST', headers: officialHeaders,
      body: JSON.stringify({ client_id: 'new-app', client_secret: 'candidate-secret' }) }, env);
    expect(verify.status).toBe(403);
    expect(await verify.json()).toMatchObject({ error: { code: 'official_login_required' } });
    const detail = await app.request(`/api/admin/users/${user.id}`, { headers: officialHeaders }, env);
    expect(await detail.json()).toMatchObject({ user: { official_verified_at: new Date(firstVerified).toISOString() } });
    expect((await app.request('/api/logout', { method: 'POST', headers, body: '{}' }, env)).ok).toBe(true);
    expect(await (await app.request('/api/login-context', {}, env)).json()).toMatchObject({ lite_available: true });
  });

  it('reports locked-account ineligibility for Lite-only applications regardless of old cookie channel', async () => {
    const { user, cookies } = await fixture();
    await env.DB.batch(officialLockStatements(env.DB, user.id, Date.now()));
    await env.DB.batch([
      env.DB.prepare(`INSERT INTO oauth_client (id,client_id,name,redirect_uris,disabled) VALUES ('rp','rp','RP','["https://rp.example/callback"]',0)`),
      env.DB.prepare("INSERT INTO app_settings (client_id,lite_only,min_trust_level) VALUES ('rp',1,0)"),
      env.DB.prepare(`INSERT INTO authorization_request (id,client_id,signed_query,browser_hash,stage,status,created_at,expires_at)
        VALUES ('request','rp','',?,'login','pending',?,?)`).bind(await hash('browser'), Date.now(), Date.now() + 60_000),
    ]);
    for (const cookie of Object.values(cookies)) {
      const response = await app.request('/api/login-context?request=request', { headers: { Cookie: `${cookie}; liteauth.browser=browser` } }, env);
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({ official_available: false, lite_available: false,
        eligibility: { allowed: false, reason: 'official_only_account' } });
    }
    expect(await env.DB.prepare("SELECT status FROM upstream_credential WHERE client_id='alice-app'").first()).toEqual({ status: 'active' });
  });

  it('starts native authorization with rejected Lite cookies and redirects locked official accounts away from Lite-only consent', async () => {
    const { user, cookies } = await fixture();
    await env.DB.batch(officialLockStatements(env.DB, user.id, Date.now()));
    await env.DB.batch([
      env.DB.prepare(`INSERT INTO oauth_client (id,client_id,name,redirect_uris,token_endpoint_auth_method,require_pkce,disabled)
        VALUES ('rp','rp','RP','["https://rp.example/callback"]','none',1,0)`),
      env.DB.prepare("INSERT INTO app_settings (client_id,lite_only,min_trust_level) VALUES ('rp',1,0)"),
    ]);
    const query = new URLSearchParams({ client_id: 'rp', redirect_uri: 'https://rp.example/callback',
      response_type: 'code', scope: 'profile', state: 'state', code_challenge: 'a'.repeat(43), code_challenge_method: 'S256' });
    for (const cookie of Object.values(cookies)) {
      const response = await app.request(`/oauth2/authorize?${query}`, { headers: { Cookie: cookie } }, env);
      expect(response.status).toBe(302);
      const redirect = new URL(response.headers.get('Location')!);
      expect(redirect.pathname).toBe('/login');
      const browserCookie = response.headers.getSetCookie().map(value => value.split(';')[0]).join('; ');
      const context = await app.request(`/api/login-context?request=${redirect.searchParams.get('request')}`, {
        headers: { Cookie: `${cookie}; ${browserCookie}` },
      }, env);
      expect(context.status).toBe(200);
      expect(await context.json()).toMatchObject({ official_available: false, lite_available: false,
        eligibility: { allowed: false, reason: 'official_only_account' } });
    }
    expect(await env.DB.prepare('SELECT id FROM verification').first()).toBeNull();
    expect(await env.DB.prepare('SELECT id FROM oauth_access_token').first()).toBeNull();
  });
});
