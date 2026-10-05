import { env } from 'cloudflare:workers';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { app } from '../src/index';
import { open, seal } from '../src/secrets';
import { disableUser } from '../src/admin';
import { createAuth } from '../src/auth';

const alice = { id: 123, username: 'alice', name: 'Alice', avatar_url: null, trust_level: 0, active: true, silenced: false };
const callbackCookie = (response: Response) => response.headers.getSetCookie().map(value => value.split(';')[0]).join('; ');
async function insertUser(id: string, linuxdoId: number, username: string, options: { admin?: boolean } = {}) {
  const now = Date.now();
  await env.DB.prepare(`INSERT INTO user
    (id,name,email,email_verified,created_at,updated_at,linuxdo_id,username,is_admin,credential_epoch)
    VALUES (?,?,?,0,?,?,?,?,?,0)`)
    .bind(id, username, `${id}@example.invalid`, now, now, linuxdoId, username, Number(options.admin ?? false)).run();
}
function mockConnect(profile = alice, valid = true) {
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    const url = input instanceof Request ? input.url : String(input);
    if (url === 'https://connect.linux.do/oauth2/token') return valid ? Response.json({ access_token: 'fixture-upstream-token', token_type: 'Bearer', expires_in: 3600 }) : Response.json({ error: 'invalid_client' }, { status: 400 });
    if (url === 'https://connect.linux.do/api/user') return Response.json({ ...profile, api_key: 'must-not-be-stored', email: 'not-to-be-exposed' });
    throw new Error('Unexpected test fetch');
  }));
}
afterEach(() => vi.unstubAllGlobals());

async function begin(method: 'official' | 'lite', input: Record<string, unknown>, cookie?: string, runtime = env) {
  if (!cookie) {
    const context = await app.request('/api/login-context', {}, runtime);
    cookie = callbackCookie(context);
  }
  const response = await app.request(`/api/login/${method}`, { method: 'POST', headers: { Cookie: cookie, Origin: runtime.APP_ORIGIN, 'Content-Type': 'application/json' }, body: JSON.stringify(input) }, runtime);
  const body = await response.clone().json().catch(() => ({})) as { redirect_url?: string };
  return { response, cookie, url: body.redirect_url ? new URL(body.redirect_url) : undefined };
}
async function complete(login: Awaited<ReturnType<typeof begin>>, extraCookie = '', runtime = env) {
  return app.request(`/auth/connect/callback?code=fixture-code&state=${login.url!.searchParams.get('state')}`, { headers: { Cookie: `${login.cookie}; ${extraCookie}` } }, runtime);
}

describe('upstream login, encrypted binding and callback lifecycle', () => {
  it('uses actual Host-prefixed secure cookies on HTTPS and ignores the legacy session name', async () => {
    const runtime = { ...env, APP_ORIGIN: 'https://auth.example.com' };
    const context = await createAuth(runtime).$context;
    for (const cookie of [...Object.values(context.authCookies), context.createAuthCookie('provider_probe')]) {
      expect(cookie.name).toMatch(/^__Host-liteauth\./);
      expect(cookie.attributes).toMatchObject({ secure: true, httpOnly: true, sameSite: 'lax', path: '/' });
      expect(cookie.attributes.domain).toBeUndefined();
    }
    mockConnect();
    const login = await begin('official', {}, undefined, runtime);
    expect(login.response.status).toBe(200);
    expect(login.cookie).toContain('__Host-liteauth.browser=');
    const callback = await complete(login, '', runtime);
    expect(callback.status).toBe(302);
    const sessionHeader = callback.headers.getSetCookie().find(value => value.startsWith('__Host-liteauth.session='));
    expect(sessionHeader).toBeDefined();
    expect(sessionHeader).toMatch(/; Secure/i);
    expect(sessionHeader).toMatch(/; HttpOnly/i);
    expect(sessionHeader).toMatch(/; Path=\//i);
    expect(sessionHeader).toMatch(/; SameSite=Lax/i);
    expect(sessionHeader).not.toMatch(/; Domain=/i);
    const cookie = sessionHeader!.split(';')[0];
    const session = await app.request('/api/session', { headers: { Cookie: cookie } }, runtime);
    expect(await session.json()).toMatchObject({ user: { linuxdo_id: 123 } });
    const injected = await app.request('/api/session', { headers: { Cookie: cookie.replace('__Host-', '__Secure-__Host-') } }, runtime);
    expect(await injected.json()).toMatchObject({ user: null });
  });

  it('completes an official login, sets a real session cookie and exposes only verified stable identity', async () => {
    mockConnect(); const login = await begin('official', {}); expect(login.response.status).toBe(200);
    const callback = await complete(login); expect(callback.status).toBe(302); expect(callback.headers.get('Location')).toBe(`${env.APP_ORIGIN}/apps`);
    const cookie = `${login.cookie}; ${callbackCookie(callback)}`;
    const response = await app.request('/api/session', { headers: { Cookie: cookie } }, env);
    expect(await response.json()).toMatchObject({ user: { linuxdo_id: 123, username: 'alice', is_admin: false }, login_method: 'official_connect' });
    const transaction = await env.DB.prepare('SELECT encrypted_payload, status FROM connect_transaction').first<{ encrypted_payload: string | null; status: string }>();
    expect(transaction).toMatchObject({ encrypted_payload: null, status: 'completed' });
    const stored = await env.DB.prepare('SELECT profile,trust_level FROM auth_event').first<{ profile: string; trust_level: number }>();
    expect(stored!.trust_level).toBe(alice.trust_level);
    expect(stored!.profile).not.toContain('must-not-be-stored'); expect(stored!.profile).not.toContain('fixture-upstream-token');
    expect((await complete(login)).headers.get('Location')).toContain('authorization_failed');
  });

  it('sets admin only for the stable ID returned by an authenticated callback', async () => {
    mockConnect({ ...alice, username: 'maintainer' });
    const ordinary = await complete(await begin('official', {}));
    expect(await (await app.request('/api/session', { headers: { Cookie: callbackCookie(ordinary) } }, env)).json()).toMatchObject({ user: { is_admin: false } });
    mockConnect({ ...alice, id: 900001, username: 'maintainer' });
    const verified = await complete(await begin('official', {}));
    expect(await (await app.request('/api/session', { headers: { Cookie: callbackCookie(verified) } }, env)).json()).toMatchObject({ user: { linuxdo_id: 900001, is_admin: true } });
  });

  it.each(['', ' 123', '123 ', '1.23e2', '+123', '0123', '0x7b', 'invalid'])('does not bootstrap an administrator from invalid configuration %j', async (configured) => {
    const runtime = { ...env, ADMIN_LINUXDO_ID: configured };
    mockConnect();
    const login = await begin('official', {}, undefined, runtime);
    const callback = await complete(login, '', runtime);
    expect(callback.headers.get('Location')).toBe(`${env.APP_ORIGIN}/apps`);
    const session = await app.request('/api/session', { headers: { Cookie: callbackCookie(callback) } }, runtime);
    expect(await session.json()).toMatchObject({ user: { linuxdo_id: 123, is_admin: false } });
  });

  it('does not bootstrap an administrator when the setting is absent', async () => {
    const runtime = { ...env };
    Reflect.deleteProperty(runtime, 'ADMIN_LINUXDO_ID');
    mockConnect();
    const callback = await complete(await begin('official', {}, undefined, runtime), '', runtime);
    const session = await app.request('/api/session', { headers: { Cookie: callbackCookie(callback) } }, runtime);
    expect(await session.json()).toMatchObject({ user: { linuxdo_id: 123, is_admin: false } });
  });

  it('binds usable self-app credentials encrypted, and reuses the same account across channels', async () => {
    mockConnect(); const official = await complete(await begin('official', {}));
    const before = await (await app.request('/api/session', { headers: { Cookie: callbackCookie(official) } }, env)).json() as { user: { id: string } };
    const login = await begin('lite', { username: 'alice', client_id: 'alice-connect', client_secret: 'alice-secret' });
    const completed = await complete(login); expect(completed.headers.get('Location')).toBe(`${env.APP_ORIGIN}/apps`);
    const after = await (await app.request('/api/session', { headers: { Cookie: callbackCookie(completed) } }, env)).json() as { user: { id: string }; login_method: string };
    expect(after.user.id).toBe(before.user.id); expect(after.login_method).toBe('lite_self_app');
    const credential = await env.DB.prepare("SELECT ciphertext, version FROM upstream_credential WHERE client_id = 'alice-connect'").first<{ ciphertext: string; version: number }>();
    expect(credential!.ciphertext).not.toContain('alice-secret'); expect(await open(env, credential!.ciphertext, `upstream:alice-connect:v${credential!.version}`)).toBe('alice-secret');
    const reused = await begin('lite', { username: 'alice' }); expect(reused.response.status).toBe(200); expect(reused.url!.searchParams.get('client_id')).toBe('alice-connect');
  });

  it('keeps the same LiteAuth account when Linux.do username changes and a new self app is submitted', async () => {
    mockConnect();
    const first = await complete(await begin('lite', { username: 'alice', client_id: 'alice-connect', client_secret: 'old-secret' }));
    const before = await (await app.request('/api/session', { headers: { Cookie: callbackCookie(first) } }, env)).json() as { user: { id: string; username: string } };
    mockConnect({ ...alice, username: 'alice-renamed', name: 'Alice Renamed' });
    const renamed = await complete(await begin('lite', { username: 'alice-renamed', client_id: 'alice-connect-renamed', client_secret: 'new-secret' }));
    expect(renamed.headers.get('Location')).toBe(`${env.APP_ORIGIN}/apps`);
    const after = await (await app.request('/api/session', { headers: { Cookie: callbackCookie(renamed) } }, env)).json() as { user: { id: string; username: string; name: string } };
    expect(after.user).toMatchObject({ id: before.user.id, username: 'alice-renamed', name: 'Alice Renamed' });
    const credentials = await env.DB.prepare('SELECT client_id,status,owner_user_id FROM upstream_credential WHERE owner_user_id = ? ORDER BY updated_at, client_id')
      .bind(before.user.id).all<{ client_id: string; status: string; owner_user_id: string }>();
    expect(credentials.results.map((row) => ({ client_id: row.client_id, status: row.status }))).toEqual([
      { client_id: 'alice-connect', status: 'revoked' },
      { client_id: 'alice-connect-renamed', status: 'active' },
    ]);
  });

  it('uses an already-bound Connect client ID to lock the stable owner after a username change', async () => {
    mockConnect();
    const first = await complete(await begin('lite', { username: 'alice', client_id: 'alice-connect', client_secret: 'old-secret' }));
    const before = await (await app.request('/api/session', { headers: { Cookie: callbackCookie(first) } }, env)).json() as { user: { id: string } };
    mockConnect({ ...alice, username: 'alice-renamed' });
    const renamed = await complete(await begin('lite', { username: 'alice-renamed', client_id: 'alice-connect', client_secret: 'new-secret' }));
    expect(renamed.headers.get('Location')).toBe(`${env.APP_ORIGIN}/apps`);
    const after = await (await app.request('/api/session', { headers: { Cookie: callbackCookie(renamed) } }, env)).json() as { user: { id: string; username: string } };
    expect(after.user).toMatchObject({ id: before.user.id, username: 'alice-renamed' });
    const credential = await env.DB.prepare("SELECT ciphertext, version FROM upstream_credential WHERE client_id = 'alice-connect'").first<{ ciphertext: string; version: number }>();
    expect(await open(env, credential!.ciphertext, `upstream:alice-connect:v${credential!.version}`)).toBe('new-secret');
  });

  it('updates credentials from a logged-in session by stable ID after the upstream username changed', async () => {
    mockConnect();
    const initialLogin = await begin('lite', { username: 'alice', client_id: 'alice-connect', client_secret: 'old-secret' });
    const initial = await complete(initialLogin);
    const cookie = `${initialLogin.cookie}; ${callbackCookie(initial)}`;
    mockConnect({ ...alice, username: 'alice-renamed' });
    const update = await app.request('/api/credentials/verify', { method: 'POST', headers: { Cookie: cookie, Origin: env.APP_ORIGIN, 'Content-Type': 'application/json' }, body: JSON.stringify({ client_id: 'alice-connect-new', client_secret: 'new-secret' }) }, env);
    expect(update.status).toBe(200);
    const updateBody = await update.json() as { redirect_url: string };
    const state = new URL(updateBody.redirect_url).searchParams.get('state');
    const completed = await app.request(`/auth/connect/callback?code=fixture-code&state=${state}`, { headers: { Cookie: cookie } }, env);
    expect(completed.headers.get('Location')).toBe(`${env.APP_ORIGIN}/credentials`);
    const session = await (await app.request('/api/session', { headers: { Cookie: `${cookie}; ${callbackCookie(completed)}` } }, env)).json() as { user: { id: string; username: string } };
    expect(session.user.username).toBe('alice-renamed');
    const active = await env.DB.prepare("SELECT client_id FROM upstream_credential WHERE owner_user_id = ? AND status = 'active'").bind(session.user.id).first<{ client_id: string }>();
    expect(active?.client_id).toBe('alice-connect-new');
  });

  it('reuses a hosted credential found by the old local username when the callback returns the renamed profile', async () => {
    mockConnect();
    const initial = await complete(await begin('lite', { username: 'alice', client_id: 'alice-connect', client_secret: 'old-secret' }));
    const before = await (await app.request('/api/session', { headers: { Cookie: callbackCookie(initial) } }, env)).json() as { user: { id: string } };
    mockConnect({ ...alice, username: 'alice-renamed' });
    const hosted = await complete(await begin('lite', { username: 'alice' }));
    expect(hosted.headers.get('Location')).toBe(`${env.APP_ORIGIN}/apps`);
    const after = await (await app.request('/api/session', { headers: { Cookie: callbackCookie(hosted) } }, env)).json() as { user: { id: string; username: string } };
    expect(after.user).toMatchObject({ id: before.user.id, username: 'alice-renamed' });
  });

  it('keeps a manually submitted renamed profile on the original stable user despite a local username collision', async () => {
    mockConnect({ ...alice, username: 'alice-old' });
    const first = await complete(await begin('lite', { username: 'alice-old', client_id: 'alice-connect', client_secret: 'old-secret' }));
    const original = await (await app.request('/api/session', { headers: { Cookie: callbackCookie(first) } }, env)).json() as { user: { id: string } };
    await insertUser('other-user', 456, 'alice-renamed');
    mockConnect({ ...alice, username: 'alice-renamed' });
    const renamed = await complete(await begin('lite', { username: 'alice-renamed', client_id: 'alice-connect-renamed', client_secret: 'new-secret' }));
    expect(renamed.headers.get('Location')).toBe(`${env.APP_ORIGIN}/apps`);
    const users = await env.DB.prepare("SELECT id,linuxdo_id,username FROM user WHERE username = 'alice-renamed' ORDER BY id").all<{ id: string; linuxdo_id: number; username: string }>();
    expect(users.results).toEqual(expect.arrayContaining([
      { id: original.user.id, linuxdo_id: 123, username: 'alice-renamed' },
      { id: 'other-user', linuxdo_id: 456, username: 'alice-renamed' },
    ]));
    const active = await env.DB.prepare("SELECT owner_user_id FROM upstream_credential WHERE client_id = 'alice-connect-renamed'").first<{ owner_user_id: string }>();
    expect(active?.owner_user_id).toBe(original.user.id);
  });

  it('separates the target owner from the actually verified identity when a bound client callback is wrong', async () => {
    mockConnect();
    const first = await complete(await begin('lite', { username: 'alice', client_id: 'alice-connect', client_secret: 'old-secret' }));
    const owner = await (await app.request('/api/session', { headers: { Cookie: callbackCookie(first) } }, env)).json() as { user: { id: string } };
    await insertUser('actual-user', 456, 'mallory');
    mockConnect({ id: 456, username: 'mallory', name: 'Mallory', avatar_url: null, trust_level: 0, active: true, silenced: false });
    const mismatch = await complete(await begin('lite', { username: 'alice-renamed', client_id: 'alice-connect', client_secret: 'wrong-owner-secret' }));
    expect(mismatch.headers.get('Location')).toContain('identity_mismatch');
    const record = await env.DB.prepare(`SELECT actor_id,actor_linuxdo_id,subject_user_id,subject_linuxdo_id,identity_confirmed,result,reason
      FROM audit WHERE action = 'connect.verification' AND result = 'failed'`).first<{
      actor_id: string | null; actor_linuxdo_id: number | null; subject_user_id: string | null; subject_linuxdo_id: number | null;
      identity_confirmed: number; result: string; reason: string;
    }>();
    expect(record).toMatchObject({
      actor_id: 'actual-user',
      actor_linuxdo_id: 456,
      subject_user_id: owner.user.id,
      subject_linuxdo_id: 123,
      identity_confirmed: 1,
      result: 'failed',
      reason: 'identity_mismatch',
    });
  });

  it('does not choose a hosted credential when the username hint is ambiguous', async () => {
    const now = Date.now();
    const secretOne = await seal(env, 'secret-one', 'upstream:client-one:v1');
    const secretTwo = await seal(env, 'secret-two', 'upstream:client-two:v1');
    await env.DB.batch([
      env.DB.prepare("INSERT INTO user (id,name,email,email_verified,created_at,updated_at,linuxdo_id,username,credential_epoch) VALUES ('u1','Alice','u1@example.invalid',0,?,?,?,?,0)").bind(now, now, 123, 'alice'),
      env.DB.prepare("INSERT INTO user (id,name,email,email_verified,created_at,updated_at,linuxdo_id,username,credential_epoch) VALUES ('u2','Other Alice','u2@example.invalid',0,?,?,?,?,0)").bind(now, now, 456, 'alice'),
      env.DB.prepare("INSERT INTO upstream_credential (client_id,owner_user_id,kind,ciphertext,version,status,created_at,updated_at) VALUES ('client-one','u1','self',?,1,'active',?,?)").bind(secretOne, now, now),
      env.DB.prepare("INSERT INTO upstream_credential (client_id,owner_user_id,kind,ciphertext,version,status,created_at,updated_at) VALUES ('client-two','u2','self',?,1,'active',?,?)").bind(secretTwo, now, now),
    ]);
    const response = await begin('lite', { username: 'alice' });
    expect(response.response.status).toBe(404);
    expect(await response.response.json()).toMatchObject({ error: { code: 'credentials_required' } });
  });

  it('rejects callback identity mismatch and reserves the platform app against user submission', async () => {
    mockConnect({ ...alice, username: 'mallory' });
    const login = await begin('lite', { username: 'alice', client_id: 'alice-connect', client_secret: 'alice-secret' });
    const response = await complete(login); expect(response.headers.get('Location')).toContain('identity_mismatch');
    expect(await env.DB.prepare("SELECT client_id FROM upstream_credential WHERE client_id = 'alice-connect'").first()).toBeNull();
    const reserved = await begin('lite', { username: 'alice', client_id: env.CONNECT_CLIENT_ID, client_secret: 'other-secret' });
    expect(reserved.response.status).toBe(409);
  });

  it('preserves old credentials on failed replacement and blocks callbacks after deletion', async () => {
    mockConnect(); const initial = await begin('lite', { username: 'alice', client_id: 'alice-connect', client_secret: 'old-secret' });
    const completed = await complete(initial); const cookie = `${initial.cookie}; ${callbackCookie(completed)}`;
    const update = await app.request('/api/credentials/verify', { method: 'POST', headers: { Cookie: cookie, Origin: env.APP_ORIGIN, 'Content-Type': 'application/json' }, body: JSON.stringify({ client_id: 'alice-connect', client_secret: 'new-secret' }) }, env);
    const updateBody = await update.json() as { redirect_url: string };
    const state = new URL(updateBody.redirect_url).searchParams.get('state');
    mockConnect(alice, false);
    const failed = await app.request(`/auth/connect/callback?code=fixture-code&state=${state}`, { headers: { Cookie: cookie } }, env); expect(failed.headers.get('Location')).toContain('connect_login_failed');
    const old = await env.DB.prepare("SELECT ciphertext, version FROM upstream_credential WHERE client_id = 'alice-connect'").first<{ ciphertext: string; version: number }>();
    expect(await open(env, old!.ciphertext, `upstream:alice-connect:v${old!.version}`)).toBe('old-secret');
    mockConnect(); const pending = await begin('lite', { username: 'alice' }, cookie);
    const deletion = await app.request('/api/credentials', { method: 'DELETE', headers: { Cookie: cookie, Origin: env.APP_ORIGIN } }, env); expect(deletion.status).toBe(200);
    expect((await complete(pending)).headers.get('Location')).toContain('authorization_failed');
    const history = await env.DB.prepare("SELECT ciphertext, status, owner_user_id FROM upstream_credential WHERE client_id = 'alice-connect'").first<{ ciphertext: string | null; status: string; owner_user_id: string }>();
    expect(history).toMatchObject({ ciphertext: null, status: 'revoked' }); expect(history?.owner_user_id).toBeTruthy();
  });

  it('rejects wrong-browser callbacks and host-independent CSRF requests', async () => {
    mockConnect(); const login = await begin('official', {});
    const wrong = await app.request(`/auth/connect/callback?code=fixture-code&state=${login.url!.searchParams.get('state')}`, { headers: { Cookie: 'liteauth.browser=wrong-browser' } }, env);
    expect(wrong.headers.get('Location')).toContain('authorization_failed');
    const crossSite = await app.request('/api/login/official', { method: 'POST', headers: { Origin: 'https://attacker.example', 'Content-Type': 'application/json' }, body: '{}' }, env); expect(crossSite.status).toBe(403);
    expect((await complete(login)).headers.get('Location')).toBe(`${env.APP_ORIGIN}/apps`);
  });

  it('does not let a pre-registration candidate restore a credential after the account revokes bindings', async () => {
    mockConnect(); const candidate = await begin('lite', { username: 'alice', client_id: 'alice-connect', client_secret: 'old-candidate' });
    const official = await complete(await begin('official', {}, candidate.cookie));
    const cookie = `${candidate.cookie}; ${callbackCookie(official)}`;
    const deletion = await app.request('/api/credentials', { method: 'DELETE', headers: { Cookie: cookie, Origin: env.APP_ORIGIN } }, env); expect(deletion.status).toBe(200);
    expect((await complete(candidate)).headers.get('Location')).toContain('credential_changed');
    expect(await env.DB.prepare("SELECT client_id FROM upstream_credential WHERE client_id = 'alice-connect'").first()).toBeNull();
  });

  it('rejects a renamed unknown candidate when credentials changed after the transaction started', async () => {
    mockConnect();
    const initial = await begin('lite', { username: 'alice', client_id: 'alice-connect', client_secret: 'old-secret' });
    const completed = await complete(initial);
    const session = await (await app.request('/api/session', { headers: { Cookie: callbackCookie(completed) } }, env)).json() as { user: { id: string } };
    mockConnect({ ...alice, username: 'alice-renamed' });
    const candidate = await begin('lite', { username: 'alice-renamed', client_id: 'alice-connect-renamed', client_secret: 'new-secret' });
    await app.request('/api/credentials', { method: 'DELETE', headers: { Cookie: `${initial.cookie}; ${callbackCookie(completed)}`, Origin: env.APP_ORIGIN } }, env);
    expect((await complete(candidate)).headers.get('Location')).toContain('credential_changed');
    expect(await env.DB.prepare("SELECT status FROM upstream_credential WHERE client_id = 'alice-connect-renamed'").first()).toBeNull();
    const user = await env.DB.prepare('SELECT username FROM user WHERE id = ?').bind(session.user.id).first<{ username: string }>();
    expect(user?.username).toBe('alice');
  });

  it('does not let an unknown renamed candidate restore credentials after a later legitimate replacement', async () => {
    mockConnect();
    const initialLogin = await begin('lite', { username: 'alice', client_id: 'alice-connect', client_secret: 'old-secret' });
    const initial = await complete(initialLogin);
    const cookie = `${initialLogin.cookie}; ${callbackCookie(initial)}`;
    mockConnect({ ...alice, username: 'alice-renamed' });
    const stale = await begin('lite', { username: 'alice-renamed', client_id: 'stale-client', client_secret: 'stale-secret' });
    const update = await app.request('/api/credentials/verify', { method: 'POST', headers: { Cookie: cookie, Origin: env.APP_ORIGIN, 'Content-Type': 'application/json' }, body: JSON.stringify({ client_id: 'legit-client', client_secret: 'legit-secret' }) }, env);
    const state = new URL(((await update.json()) as { redirect_url: string }).redirect_url).searchParams.get('state');
    const updated = await app.request(`/auth/connect/callback?code=fixture-code&state=${state}`, { headers: { Cookie: cookie } }, env);
    expect(updated.headers.get('Location')).toBe(`${env.APP_ORIGIN}/credentials`);
    expect((await complete(stale)).headers.get('Location')).toContain('credential_changed');
    const active = await env.DB.prepare("SELECT client_id FROM upstream_credential WHERE status = 'active' AND kind = 'self'").first<{ client_id: string }>();
    expect(active?.client_id).toBe('legit-client');
    expect(await env.DB.prepare("SELECT client_id FROM upstream_credential WHERE client_id = 'stale-client'").first()).toBeNull();
  });

  it('does not let an unknown renamed candidate restore credentials after admin disable and enable', async () => {
    mockConnect();
    const initial = await complete(await begin('lite', { username: 'alice', client_id: 'alice-connect', client_secret: 'old-secret' }));
    const session = await (await app.request('/api/session', { headers: { Cookie: callbackCookie(initial) } }, env)).json() as { user: { id: string } };
    await insertUser('admin-user', 900001, 'admin', { admin: true });
    mockConnect({ ...alice, username: 'alice-renamed' });
    const stale = await begin('lite', { username: 'alice-renamed', client_id: 'stale-client', client_secret: 'stale-secret' });
    await disableUser(env, 'admin-user', session.user.id, true);
    await disableUser(env, 'admin-user', session.user.id, false);
    expect((await complete(stale)).headers.get('Location')).toContain('credential_changed');
    expect(await env.DB.prepare("SELECT client_id FROM upstream_credential WHERE client_id = 'stale-client'").first()).toBeNull();
  });

  it('allows only one of two unknown renamed candidates to bind, and ignores unrelated user epoch changes', async () => {
    mockConnect();
    const initial = await complete(await begin('lite', { username: 'alice', client_id: 'alice-connect', client_secret: 'old-secret' }));
    const owner = await (await app.request('/api/session', { headers: { Cookie: callbackCookie(initial) } }, env)).json() as { user: { id: string } };
    await insertUser('other-user', 456, 'other');
    mockConnect({ ...alice, username: 'alice-renamed' });
    const first = await begin('lite', { username: 'alice-renamed', client_id: 'first-client', client_secret: 'first-secret' });
    const second = await begin('lite', { username: 'alice-renamed', client_id: 'second-client', client_secret: 'second-secret' });
    await env.DB.prepare('UPDATE user SET credential_epoch = credential_epoch + 1 WHERE id = ?').bind('other-user').run();
    expect((await complete(first)).headers.get('Location')).toBe(`${env.APP_ORIGIN}/apps`);
    expect((await complete(second)).headers.get('Location')).toContain('credential_changed');
    const credentials = await env.DB.prepare('SELECT client_id,status FROM upstream_credential WHERE owner_user_id = ? ORDER BY client_id')
      .bind(owner.user.id).all<{ client_id: string; status: string }>();
    expect(credentials.results).toEqual(expect.arrayContaining([
      { client_id: 'alice-connect', status: 'revoked' },
      { client_id: 'first-client', status: 'active' },
    ]));
    expect(credentials.results.some((row) => row.client_id === 'second-client')).toBe(false);
  });

  it('advances the credential clock for legacy epoch writes and rolls back failed guarded batches cleanly', async () => {
    await insertUser('legacy-user', 789, 'legacy');
    const before = await env.DB.prepare('SELECT revision FROM credential_clock WHERE id = 1').first<{ revision: number }>();
    await env.DB.prepare('UPDATE user SET credential_epoch = credential_epoch + 1 WHERE id = ?').bind('legacy-user').run();
    const advanced = await env.DB.prepare('SELECT credential_epoch,credential_revision FROM user WHERE id = ?').bind('legacy-user')
      .first<{ credential_epoch: number; credential_revision: number }>();
    const clock = await env.DB.prepare('SELECT revision FROM credential_clock WHERE id = 1').first<{ revision: number }>();
    expect(clock!.revision).toBeGreaterThan(before!.revision);
    expect(advanced).toMatchObject({ credential_epoch: 1, credential_revision: clock!.revision });
    await expect(env.DB.batch([
      env.DB.prepare('UPDATE user SET credential_epoch = credential_epoch + 1 WHERE id = ?').bind('legacy-user'),
      env.DB.prepare("INSERT INTO mutation_guard (id,ok) VALUES ('rollback-guard',0)"),
    ])).rejects.toThrow();
    expect(await env.DB.prepare('SELECT credential_epoch,credential_revision FROM user WHERE id = ?').bind('legacy-user').first()).toEqual(advanced);
    expect(await env.DB.prepare('SELECT revision FROM credential_clock WHERE id = 1').first()).toEqual(clock);
  });
});
