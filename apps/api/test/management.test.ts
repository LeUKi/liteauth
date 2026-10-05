import { env } from 'cloudflare:test';
import { makeSignature } from 'better-auth/crypto';
import { describe, expect, it } from 'vitest';
import { redirectUriSchema, type App, type AppInput, type AppResponse, type LoginMethod } from '@liteauth/contracts';
import { createAuth, type LiteAuth } from '../src/auth';
import { createApp, deleteApp, getApp, listApps, readAppSecret, rotateAppSecret, updateApp } from '../src/apps';
import { disableApp, disableUser, listAudit, listUsers } from '../src/admin';
import { hash, randomId } from '../src/crypto';
import { app } from '../src/index';

const appInput = (overrides: Partial<AppInput> = {}): AppInput => ({
  name: 'Test application', redirect_uris: ['https://client.example/callback'],
  client_type: 'confidential', pkce_required: true, lite_only: false, ...overrides,
});

type Login = Awaited<ReturnType<typeof login>>;

async function login(username: string, linuxdoId: number, options: { method?: LoginMethod; admin?: boolean } = {}) {
  const auth = createAuth(env);
  const context = await auth.$context;
  const user = await context.internalAdapter.createUser({
    name: username, email: `${linuxdoId}@identity.invalid`, emailVerified: false,
    username, linuxdoId, isAdmin: options.admin ?? false, disabled: false, credentialEpoch: 0,
  }, { method: 'oauth', oauth: { providerId: 'linuxdo-connect' } });
  const eventId = randomId('ev_');
  const method = options.method ?? 'official_connect';
  const profile = { id: linuxdoId, username, name: username, avatar_url: null, trust_level: 1, active: true, silenced: false };
  await env.DB.prepare(`INSERT INTO auth_event (id, user_id, login_method, upstream_client_id, profile, trust_level, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)`).bind(eventId, user.id, method, method === 'official_connect' ? env.CONNECT_CLIENT_ID : `self-${linuxdoId}`, JSON.stringify(profile), profile.trust_level, Date.now()).run();
  const session = await context.internalAdapter.createSession(user.id, false, { authEventId: eventId }, true);
  const headers = new Headers({ Origin: env.APP_ORIGIN });
  headers.set('Cookie', `${context.authCookies.sessionToken.name}=${session.token}.${await makeSignature(session.token, context.secret)}`);
  return { auth, userId: user.id, eventId, sessionId: session.id, headers, profile, method };
}

async function createApplication(owner: Login, overrides: Partial<AppInput> = {}) {
  return createApp(env, owner.auth, owner.headers, appInput(overrides));
}

async function redirectUrl(response: Response) {
  const location = response.headers.get('Location');
  if (location) return new URL(location, env.APP_ORIGIN);
  const body = await response.json() as { redirect?: boolean; url?: string };
  expect(response.status).toBe(200);
  expect(body.redirect).toBe(true);
  expect(body.url).toBeTypeOf('string');
  return new URL(body.url!, env.APP_ORIGIN);
}

async function challenge(verifier: string) {
  return (await hash(verifier)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

async function authorize(auth: LiteAuth, client: App, headers: Headers, pkce?: { verifier: string; method: string }) {
  const query = new URLSearchParams({
    response_type: 'code', client_id: client.client_id, redirect_uri: client.redirect_uris[0],
    scope: 'openid profile', state: randomId('state_'), nonce: randomId('nonce_'),
  });
  if (pkce) {
    query.set('code_challenge', pkce.method === 'S256' ? await challenge(pkce.verifier) : pkce.verifier);
    query.set('code_challenge_method', pkce.method);
  }
  return auth.handler(new Request(`${env.APP_ORIGIN}/api/auth/oauth2/authorize?${query}`, { headers }));
}

// Codes and tokens are issued by the configured provider, with its real D1 policy adapter.
async function authorizationCode(owner: Login, client: App) {
  const verifier = randomId() + randomId();
  const auth = createAuth(env, client.client_id);
  let target = await redirectUrl(await authorize(auth, client, owner.headers, { verifier, method: 'S256' }));
  if (target.pathname === '/consent') {
    const headers = new Headers(owner.headers);
    headers.set('Content-Type', 'application/json');
    headers.set('Accept', 'application/json');
    target = await redirectUrl(await auth.handler(new Request(`${env.APP_ORIGIN}/api/auth/oauth2/consent`, {
      method: 'POST', headers, body: JSON.stringify({ accept: true, oauth_query: target.searchParams.toString() }),
    })));
  }
  expect(target.origin + target.pathname).toBe(client.redirect_uris[0]);
  expect(target.searchParams.has('error')).toBe(false);
  const code = target.searchParams.get('code');
  expect(code).toBeTypeOf('string');
  const row = await env.DB.prepare(`SELECT code_id FROM grant_ledger
    WHERE code_id = ? AND client_id = ? AND auth_event_id = ? AND state = 'pending'`)
    .bind(await challenge(code!), client.client_id, owner.eventId).first<{ code_id: string }>();
  expect(row).not.toBeNull();
  return { code: code!, codeId: row!.code_id, verifier };
}

async function exchangeCode(owner: Login, client: AppResponse, code: { code: string; verifier: string }, secret = client.client_secret) {
  const body = new URLSearchParams({
    grant_type: 'authorization_code', client_id: client.app.client_id, code: code.code,
    redirect_uri: client.app.redirect_uris[0], code_verifier: code.verifier,
  });
  if (secret) body.set('client_secret', secret);
  return owner.auth.handler(new Request(`${env.APP_ORIGIN}/api/auth/oauth2/token`, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body,
  }));
}

async function issuedToken(owner: Login, client: AppResponse) {
  const code = await authorizationCode(owner, client.app);
  const response = await exchangeCode(owner, client, code);
  const body = await response.json() as { access_token?: string; token_type?: string };
  expect(response.status).toBe(200);
  expect(body.token_type).toBe('Bearer');
  expect(body.access_token).toBeTypeOf('string');
  const row = await env.DB.prepare('SELECT token_id FROM grant_ledger WHERE code_id = ? AND state = ?')
    .bind(code.codeId, 'issued').first<{ token_id: string }>();
  expect(row).not.toBeNull();
  return { accessToken: body.access_token!, codeId: code.codeId, tokenId: row!.token_id };
}

async function introspect(owner: Login, client: AppResponse, token: string, secret = client.client_secret) {
  const body = new URLSearchParams({ client_id: client.app.client_id, token, token_type_hint: 'access_token' });
  if (secret) body.set('client_secret', secret);
  const response = await owner.auth.handler(new Request(`${env.APP_ORIGIN}/api/auth/oauth2/introspect`, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body,
  }));
  return { status: response.status, body: await response.json() as Record<string, unknown> };
}

async function userInfo(owner: Login, token: string) {
  const response = await owner.auth.handler(new Request(`${env.APP_ORIGIN}/api/auth/oauth2/userinfo`, {
    headers: { Authorization: `Bearer ${token}` },
  }));
  return { status: response.status, body: await response.json() as Record<string, unknown> };
}

async function pendingFlow(owner: Login, client: App, status: 'pending' | 'processing' = 'pending') {
  const id = randomId('req_');
  const transactionId = randomId('tx_');
  const now = Date.now();
  await env.DB.batch([
    env.DB.prepare(`INSERT INTO authorization_request
      (id, client_id, signed_query, browser_hash, auth_event_id, stage, status, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?, 'consent', ?, ?, ?)`)
      .bind(id, client.client_id, 'signed-fixture', 'browser-fixture', owner.eventId, status, now, now + 600_000),
    env.DB.prepare(`INSERT INTO connect_transaction
      (id, state_hash, browser_hash, request_id, method, client_id, encrypted_payload, expected_user_id, status, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)`)
      .bind(transactionId, randomId('state_'), 'browser-fixture', id, owner.method, `upstream-${owner.userId}`, 'encrypted-fixture', owner.userId, now, now + 600_000),
  ]);
  return { id, transactionId };
}

function pausedSecretUpdate() {
  let release!: () => void;
  let signal!: () => void;
  const blocked = new Promise<void>((resolve) => { release = resolve; });
  const entered = new Promise<void>((resolve) => { signal = resolve; });
  const wrap = (statement: D1PreparedStatement): D1PreparedStatement => new Proxy(statement, {
    get(target, property) {
      if (property === 'bind') return (...values: Parameters<D1PreparedStatement['bind']>) => wrap(target.bind(...values));
      const member = Reflect.get(target, property);
      if (['all', 'first', 'run', 'raw'].includes(String(property))) return async (...args: unknown[]) => {
        signal();
        await blocked;
        return member.apply(target, args);
      };
      return typeof member === 'function' ? member.bind(target) : member;
    },
  });
  const db = new Proxy(env.DB, {
    get(target, property) {
      if (property === 'prepare') return (query: string) => {
        const statement = target.prepare(query);
        return /update\s+["`]?oauth_client["`]?\s/i.test(query) && /client_secret/i.test(query) ? wrap(statement) : statement;
      };
      const member = Reflect.get(target, property);
      return typeof member === 'function' ? member.bind(target) : member;
    },
  });
  return { env: { ...env, DB: db }, entered, release };
}

describe('application ownership and provider credentials', () => {
  it('isolates listing, reads, updates, deletion and secret rotation between owners', async () => {
    const alice = await login('alice', 101);
    const bob = await login('bob', 102);
    const first = await createApplication(alice);
    const second = await createApplication(bob, { name: 'Bob application' });

    expect((await listApps(env, alice.userId)).apps.map((app) => app.id)).toEqual([first.app.id]);
    expect((await listApps(env, bob.userId)).apps.map((app) => app.id)).toEqual([second.app.id]);
    await expect(getApp(env, first.app.id, bob.userId)).rejects.toMatchObject({ status: 404, code: 'app_not_found' });
    await expect(updateApp(env, first.app.id, bob.userId, false, appInput({ name: 'Stolen' }))).rejects.toMatchObject({ status: 404, code: 'app_not_found' });
    await expect(deleteApp(env, first.app.id, bob.userId, false)).rejects.toMatchObject({ status: 404, code: 'app_not_found' });
    await expect(rotateAppSecret(env, bob.auth, bob.headers, first.app.id, bob.userId, false)).rejects.toMatchObject({ status: 404, code: 'app_not_found' });
    expect((await getApp(env, first.app.id, alice.userId)).app).toEqual(first.app);
  });

  it('creates hashed secrets through Better Auth and authenticates the original secret only', async () => {
    const owner = await login('owner', 103);
    const client = await createApplication(owner);
    expect(client.client_secret).toBeTypeOf('string');
    expect(client.app.redirect_uris).toEqual(appInput().redirect_uris);
    const stored = await env.DB.prepare('SELECT user_id, client_secret FROM oauth_client WHERE id = ?')
      .bind(client.app.id).first<{ user_id: string; client_secret: string }>();
    expect(stored?.user_id).toBe(owner.userId);
    expect(stored?.client_secret).toBeTruthy();
    expect(stored?.client_secret).not.toBe(client.client_secret);
    expect(await introspect(owner, client, 'nonexistent-token')).toEqual({ status: 200, body: { active: false } });
    expect(await introspect(owner, client, 'nonexistent-token', 'incorrect-secret')).toMatchObject({ status: 400, body: { error: 'invalid_client' } });
    expect(await introspect(owner, client, 'nonexistent-token', stored!.client_secret)).toMatchObject({ status: 400, body: { error: 'invalid_client' } });
    expect(await getApp(env, client.app.id, owner.userId)).not.toHaveProperty('client_secret');
    expect(JSON.stringify(await listApps(env, owner.userId))).not.toContain(client.client_secret);
    expect(JSON.stringify(await listApps(env, owner.userId))).not.toContain(stored!.client_secret);
  });

  it('rotates through the provider, hashes the new secret and rejects the previous one', async () => {
    const owner = await login('owner', 104);
    const client = await createApplication(owner);
    const rotated = await rotateAppSecret(env, owner.auth, owner.headers, client.app.id, owner.userId, false);
    expect(rotated.client_secret).not.toBe(client.client_secret);
    expect(await introspect(owner, client, 'nonexistent-token', rotated.client_secret)).toEqual({ status: 200, body: { active: false } });
    expect(await introspect(owner, client, 'nonexistent-token')).toMatchObject({ status: 400, body: { error: 'invalid_client' } });
    const stored = await env.DB.prepare('SELECT client_secret FROM oauth_client WHERE id = ?').bind(client.app.id).first<{ client_secret: string }>();
    expect(stored?.client_secret).not.toBe(rotated.client_secret);
    expect(await readAppSecret(env, client.app.id, owner.userId)).toEqual({ status: 'available', client_secret: rotated.client_secret });
    expect((await env.DB.prepare("SELECT action FROM audit WHERE target_id = ? AND action = 'app.secret_rotated'").bind(client.app.id).all()).results).toHaveLength(1);
  });

  it('lets administrators inspect applications but requires their owner to rotate secrets', async () => {
    const owner = await login('owner', 105);
    const admin = await login('admin', 900001, { admin: true });
    const client = await createApplication(owner);
    expect((await getApp(env, client.app.id, admin.userId, true)).app.id).toBe(client.app.id);
    expect((await listApps(env, admin.userId, true)).apps.map((app) => app.id)).toEqual([client.app.id]);
    await expect(rotateAppSecret(env, admin.auth, admin.headers, client.app.id, admin.userId, true)).rejects.toMatchObject({ status: 403, code: 'owner_required' });
    expect(await introspect(owner, client, 'nonexistent-token')).toEqual({ status: 200, body: { active: false } });
  });

  it('repeatedly reveals the same encrypted secret only to its owner', async () => {
    const owner = await login('owner', 120);
    const stranger = await login('stranger', 121);
    const admin = await login('admin', 900001, { admin: true });
    const client = await createApplication(owner);
    const expected = { status: 'available', client_secret: client.client_secret };
    expect(await readAppSecret(env, client.app.id, owner.userId)).toEqual(expected);
    expect(await readAppSecret(env, client.app.id, owner.userId)).toEqual(expected);
    await expect(readAppSecret(env, client.app.id, stranger.userId)).rejects.toMatchObject({ status: 404, code: 'app_not_found' });
    await expect(readAppSecret(env, client.app.id, admin.userId, true)).rejects.toMatchObject({ status: 403, code: 'owner_required' });
    const stored = await env.DB.prepare('SELECT client_secret, secret_ciphertext FROM oauth_client WHERE id = ?')
      .bind(client.app.id).first<{ client_secret: string; secret_ciphertext: string }>();
    expect(stored!.secret_ciphertext).toBeTruthy();
    expect(stored!.secret_ciphertext).not.toContain(client.client_secret);
    const audit = (await env.DB.prepare("SELECT * FROM audit WHERE target_id = ? AND action = 'app.secret_viewed'")
      .bind(client.app.id).all()).results;
    expect(audit).toHaveLength(2);
    expect(JSON.stringify(audit)).not.toContain(client.client_secret);
    expect(JSON.stringify(audit)).not.toContain(stored!.client_secret);
    expect(JSON.stringify(audit)).not.toContain(stored!.secret_ciphertext);
    const response = await app.request(`/api/apps/${client.app.id}/secret`, { headers: owner.headers }, env);
    expect(response.status).toBe(200);
    expect(response.headers.get('Cache-Control')).toBe('no-store');
    expect(await response.json()).toEqual(expected);
    const denied = await app.request(`/api/apps/${client.app.id}/secret`, { headers: admin.headers }, env);
    expect(denied.status).toBe(403);
    expect(await denied.json()).not.toHaveProperty('client_secret');
  });

  it('keeps legacy hashed secrets active until their owner explicitly rotates', async () => {
    const owner = await login('legacy-owner', 122);
    const client = await createApplication(owner);
    await env.DB.prepare('UPDATE oauth_client SET secret_ciphertext = NULL WHERE id = ?').bind(client.app.id).run();
    const before = await env.DB.prepare('SELECT client_secret FROM oauth_client WHERE id = ?').bind(client.app.id).first();
    expect(await readAppSecret(env, client.app.id, owner.userId)).toEqual({ status: 'legacy_unavailable', client_secret: null });
    expect(await env.DB.prepare('SELECT client_secret FROM oauth_client WHERE id = ?').bind(client.app.id).first()).toEqual(before);
    expect(await introspect(owner, client, 'nonexistent-token')).toEqual({ status: 200, body: { active: false } });
    const rotated = await rotateAppSecret(env, owner.auth, owner.headers, client.app.id, owner.userId, false);
    expect(await readAppSecret(env, client.app.id, owner.userId)).toEqual({ status: 'available', client_secret: rotated.client_secret });
    expect(await introspect(owner, client, 'nonexistent-token')).toMatchObject({ status: 400, body: { error: 'invalid_client' } });
  });

  it('has no secret to display for public clients', async () => {
    const owner = await login('public-owner', 123);
    const client = await createApplication(owner, { client_type: 'public' });
    expect(await readAppSecret(env, client.app.id, owner.userId)).toEqual({ status: 'not_applicable', client_secret: null });
    expect(await env.DB.prepare('SELECT client_secret, secret_ciphertext FROM oauth_client WHERE id = ?').bind(client.app.id).first())
      .toEqual({ client_secret: null, secret_ciphertext: null });
  });

  it('rejects a display copy moved between clients without affecting native secret authentication', async () => {
    const owner = await login('owner', 124);
    const first = await createApplication(owner);
    const second = await createApplication(owner, { name: 'Second app' });
    const firstCiphertext = await env.DB.prepare('SELECT secret_ciphertext FROM oauth_client WHERE id = ?')
      .bind(first.app.id).first<{ secret_ciphertext: string }>();
    await env.DB.prepare('UPDATE oauth_client SET secret_ciphertext = ? WHERE id = ?').bind(firstCiphertext!.secret_ciphertext, second.app.id).run();
    await expect(readAppSecret(env, second.app.id, owner.userId)).rejects.toMatchObject({ status: 500, code: 'secret_unavailable' });
    expect(await introspect(owner, second, 'nonexistent-token')).toEqual({ status: 200, body: { active: false } });
  });

  it('defaults application level to zero and preserves the level when updates omit it', async () => {
    const owner = await login('owner', 125);
    const client = await createApplication(owner);
    expect(client.app.min_trust_level).toBe(0);
    const limited = await updateApp(env, client.app.id, owner.userId, false, appInput({ min_trust_level: 4 }));
    expect(limited.app.min_trust_level).toBe(4);
    const updated = await updateApp(env, client.app.id, owner.userId, false, appInput({ name: 'Renamed' }));
    expect(updated.app.min_trust_level).toBe(4);
    for (const level of [-1, 5, 1.5]) {
      await expect(updateApp(env, client.app.id, owner.userId, false, appInput({ min_trust_level: level }))).rejects.toMatchObject({ name: 'ZodError' });
    }
  });

  it('rejects a stale rotation when another rotation commits first', async () => {
    const owner = await login('owner', 126);
    const client = await createApplication(owner);
    const paused = pausedSecretUpdate();
    const stale = rotateAppSecret(paused.env, createAuth(paused.env), owner.headers, client.app.id, owner.userId, false)
      .then((result) => ({ result }), (error: unknown) => ({ error }));
    await paused.entered;
    let fresh!: { client_secret: string };
    try { fresh = await rotateAppSecret(env, owner.auth, owner.headers, client.app.id, owner.userId, false); }
    finally { paused.release(); }
    expect(await stale).toHaveProperty('error');
    expect(await readAppSecret(env, client.app.id, owner.userId)).toEqual({ status: 'available', client_secret: fresh.client_secret });
    expect(await introspect(owner, client, 'nonexistent-token', fresh.client_secret)).toEqual({ status: 200, body: { active: false } });
    expect(await introspect(owner, client, 'nonexistent-token')).toMatchObject({ status: 400, body: { error: 'invalid_client' } });
  });

  it('does not resurrect either secret representation when deletion commits before rotation', async () => {
    const owner = await login('owner', 127);
    const client = await createApplication(owner);
    const paused = pausedSecretUpdate();
    const rotating = rotateAppSecret(paused.env, createAuth(paused.env), owner.headers, client.app.id, owner.userId, false)
      .then((result) => ({ result }), (error: unknown) => ({ error }));
    await paused.entered;
    try { await deleteApp(env, client.app.id, owner.userId, false); }
    finally { paused.release(); }
    expect(await rotating).toHaveProperty('error');
    expect(await env.DB.prepare('SELECT disabled, client_secret, secret_ciphertext FROM oauth_client WHERE id = ?').bind(client.app.id).first())
      .toEqual({ disabled: 1, client_secret: null, secret_ciphertext: null });
    await expect(readAppSecret(env, client.app.id, owner.userId)).rejects.toMatchObject({ status: 404, code: 'app_not_found' });
  });

  it('clears the newest secret when rotation commits before deletion', async () => {
    const owner = await login('owner', 128);
    const client = await createApplication(owner);
    const rotated = await rotateAppSecret(env, owner.auth, owner.headers, client.app.id, owner.userId, false);
    expect(await readAppSecret(env, client.app.id, owner.userId)).toEqual({ status: 'available', client_secret: rotated.client_secret });
    await deleteApp(env, client.app.id, owner.userId, false);
    expect(await env.DB.prepare('SELECT disabled, client_secret, secret_ciphertext FROM oauth_client WHERE id = ?').bind(client.app.id).first())
      .toEqual({ disabled: 1, client_secret: null, secret_ciphertext: null });
  });

  it('keeps the previous native hash and encrypted copy when sealing a new secret fails', async () => {
    const owner = await login('owner', 129);
    const client = await createApplication(owner);
    const before = await env.DB.prepare('SELECT client_secret, secret_ciphertext FROM oauth_client WHERE id = ?').bind(client.app.id).first();
    const brokenEnv = { ...env, CREDENTIAL_ENCRYPTION_KEY: 'invalid!' };
    const brokenAuth = createAuth(brokenEnv);
    await expect(rotateAppSecret(brokenEnv, brokenAuth, owner.headers, client.app.id, owner.userId, false)).rejects.toThrow();
    expect(await env.DB.prepare('SELECT client_secret, secret_ciphertext FROM oauth_client WHERE id = ?').bind(client.app.id).first()).toEqual(before);
    expect(await readAppSecret(env, client.app.id, owner.userId)).toEqual({ status: 'available', client_secret: client.client_secret });
    expect(await introspect(owner, client, 'nonexistent-token')).toEqual({ status: 200, body: { active: false } });
    await expect(createApp(brokenEnv, brokenAuth, owner.headers, appInput({ name: 'Unsealed' }))).rejects.toThrow();
    expect((await listApps(env, owner.userId)).apps).toHaveLength(1);
    expect((await env.DB.prepare('SELECT id FROM oauth_client').all()).results).toHaveLength(1);
  });
});

describe('public clients and PKCE', () => {
  it('accepts standard callbacks and rejects non-exact HTTP loopback aliases and HTTPS loopback', () => {
    for (const uri of ['https://client.example/callback', 'http://localhost:9444/callback', 'http://127.0.0.1:9444/callback', 'http://[::1]:9444/callback', 'http://LOCALHOST:80/callback']) {
      expect(redirectUriSchema.safeParse(uri).success, uri).toBe(true);
    }
    for (const uri of ['http://client.example/callback', 'http://2130706433:9444/callback', 'http://0x7f000001:9444/callback', 'http://127.1:9444/callback', 'http://%6cocalhost:9444/callback', 'http://localhost.:9444/callback', 'http://[0:0:0:0:0:0:0:1]:9444/callback', 'https://localhost/callback', 'https://localhost./callback', 'https://127.0.0.1/callback', 'https://127.0.0.2/callback', 'https://[::1]/callback', 'https://client.example/callback#', 'https://user:pass@client.example/callback']) {
      expect(redirectUriSchema.safeParse(uri).success, uri).toBe(false);
    }
  });

  it.each(['http://127.0.0.1:9444/callback', 'http://localhost:9444/callback', 'http://[::1]:9444/callback'])('creates a public loopback client through Hono and completes S256 authorization: %s', async (redirectUri) => {
    const owner = await login('owner', 106);
    const input = appInput({ name: '联调验证', redirect_uris: [redirectUri], client_type: 'public', pkce_required: true, lite_only: false });
    const headers = new Headers(owner.headers);
    headers.set('Content-Type', 'application/json');
    const response = await app.request('/api/apps', { method: 'POST', headers, body: JSON.stringify(input) }, env);
    expect(response.status).toBe(201);
    const client = await response.json() as AppResponse;
    expect(client.app).toMatchObject({ name: input.name, redirect_uris: [redirectUri], client_type: 'public', pkce_required: true, lite_only: false });
    expect(client.client_secret).toBeUndefined();
    expect(await env.DB.prepare('SELECT application_type FROM oauth_client WHERE id = ?').bind(client.app.id).first()).toEqual({ application_type: 'native' });
    const token = await issuedToken(owner, client);
    expect((await userInfo(owner, token.accessToken)).status).toBe(200);
  });

  it('keeps loopback metadata aligned when a confidential client updates its callbacks', async () => {
    const owner = await login('owner', 106);
    const client = await createApplication(owner);
    const input = appInput({ redirect_uris: ['http://127.0.0.1:9444/callback'] });
    const updated = await updateApp(env, client.app.id, owner.userId, false, input);
    expect(await env.DB.prepare('SELECT application_type FROM oauth_client WHERE id = ?').bind(client.app.id).first()).toEqual({ application_type: 'native' });
    const token = await issuedToken(owner, { ...updated, client_secret: client.client_secret });
    expect((await userInfo(owner, token.accessToken)).status).toBe(200);
    await updateApp(env, client.app.id, owner.userId, false, appInput());
    expect(await env.DB.prepare('SELECT application_type FROM oauth_client WHERE id = ?').bind(client.app.id).first()).toEqual({ application_type: 'web' });
  });

  it('supports exact local HTTP and remote HTTPS callbacks in the same public registration', async () => {
    const owner = await login('owner', 106);
    const redirectUris = ['http://127.0.0.1:9444/callback', 'https://client.example/callback'];
    const client = await createApplication(owner, { client_type: 'public', redirect_uris: redirectUris });
    for (const redirectUri of redirectUris) {
      const selected = { ...client, app: { ...client.app, redirect_uris: [redirectUri] } };
      const token = await issuedToken(owner, selected);
      expect((await userInfo(owner, token.accessToken)).status).toBe(200);
    }
  });


  it('rejects public clients without PKCE on both creation and update', async () => {
    const owner = await login('owner', 106);
    await expect(createApplication(owner, { client_type: 'public', pkce_required: false })).rejects.toMatchObject({ name: 'ZodError' });
    expect((await listApps(env, owner.userId)).apps).toHaveLength(0);
    const client = await createApplication(owner, { client_type: 'public' });
    expect(client).not.toHaveProperty('client_secret');
    const stored = await env.DB.prepare('SELECT client_secret, require_pkce, token_endpoint_auth_method FROM oauth_client WHERE id = ?')
      .bind(client.app.id).first<{ client_secret: string | null; require_pkce: number; token_endpoint_auth_method: string }>();
    expect(stored).toEqual({ client_secret: null, require_pkce: 1, token_endpoint_auth_method: 'none' });
    await expect(updateApp(env, client.app.id, owner.userId, false, appInput({ client_type: 'public', pkce_required: false }))).rejects.toMatchObject({ name: 'ZodError' });
    expect((await getApp(env, client.app.id, owner.userId)).app.pkce_required).toBe(true);
    await expect(rotateAppSecret(env, owner.auth, owner.headers, client.app.id, owner.userId, false)).rejects.toMatchObject({ status: 400, code: 'rotation_unavailable' });
  });

  it('enforces S256 in the actual authorization endpoint and issues public tokens without a secret', async () => {
    const owner = await login('owner', 107);
    const client = await createApplication(owner, { client_type: 'public' });
    for (const pkce of [undefined, { verifier: 'a'.repeat(64), method: 'plain' }]) {
      const target = await redirectUrl(await authorize(owner.auth, client.app, owner.headers, pkce));
      expect(target.origin + target.pathname).toBe(client.app.redirect_uris[0]);
      expect(target.searchParams.get('error')).toBe('invalid_request');
      expect(target.searchParams.has('code')).toBe(false);
    }
    expect((await env.DB.prepare('SELECT code_id FROM grant_ledger').all()).results).toHaveLength(0);
    const token = await issuedToken(owner, client);
    expect((await userInfo(owner, token.accessToken)).status).toBe(200);
  });

  it('rejects a wrong verifier, while a fresh S256 grant can still be exchanged', async () => {
    const owner = await login('owner', 108);
    const client = await createApplication(owner, { client_type: 'public' });
    const code = await authorizationCode(owner, client.app);
    const rejected = await exchangeCode(owner, client, { ...code, verifier: 'wrong'.repeat(13) });
    expect(rejected.status).toBeGreaterThanOrEqual(400);
    expect(rejected.status).toBeLessThan(500);
    expect(await rejected.json()).not.toHaveProperty('access_token');
    expect((await env.DB.prepare('SELECT id FROM oauth_access_token').all()).results).toHaveLength(0);
    const token = await issuedToken(owner, client);
    expect((await userInfo(owner, token.accessToken)).body).toMatchObject({ login_method: 'official_connect', liteauth_user_id: owner.userId });
  });

  it('keeps client type immutable and allows an explicit confidential PKCE exemption', async () => {
    const owner = await login('owner', 109);
    const client = await createApplication(owner, { pkce_required: false });
    expect(client.app.pkce_required).toBe(false);
    await expect(updateApp(env, client.app.id, owner.userId, false, appInput({ client_type: 'public' }))).rejects.toMatchObject({ status: 400, code: 'client_type_immutable' });
    const target = await redirectUrl(await authorize(owner.auth, client.app, owner.headers));
    expect(target.pathname).toBe('/consent');
    expect(target.searchParams.has('error')).toBe(false);
  });
});

describe('administrator permissions and durable revocation', () => {
  it('blocks non-administrators and protects every administrator account from disabling', async () => {
    const user = await login('user', 110);
    const admin = await login('admin', 900001, { admin: true });
    const otherAdmin = await login('other-admin', 111, { admin: true });
    const client = await createApplication(user);
    await expect(listUsers(env, user.userId)).rejects.toMatchObject({ status: 403, code: 'admin_required' });
    await expect(listAudit(env, user.userId)).rejects.toMatchObject({ status: 403, code: 'admin_required' });
    await expect(disableUser(env, user.userId, admin.userId, true)).rejects.toMatchObject({ status: 403, code: 'admin_required' });
    await expect(disableApp(env, user.userId, client.app.id, true)).rejects.toMatchObject({ status: 403, code: 'admin_required' });
    for (const target of [admin, otherAdmin]) {
      await expect(disableUser(env, admin.userId, target.userId, true)).rejects.toMatchObject({ status: 400, code: 'admin_protected' });
      expect(await env.DB.prepare('SELECT disabled, credential_epoch FROM user WHERE id = ?').bind(target.userId).first()).toEqual({ disabled: 0, credential_epoch: 0 });
      expect(await target.auth.api.getSession({ headers: target.headers })).not.toBeNull();
    }
    expect((await getApp(env, client.app.id, user.userId)).app.disabled).toBe(false);
  });

  it('denies administration by a disabled administrator', async () => {
    const admin = await login('admin', 900001, { admin: true });
    const user = await login('user', 112);
    await env.DB.prepare('UPDATE user SET disabled = 1 WHERE id = ?').bind(admin.userId).run();
    await expect(listUsers(env, admin.userId)).rejects.toMatchObject({ status: 403, code: 'admin_required' });
    await expect(disableUser(env, admin.userId, user.userId, true)).rejects.toMatchObject({ status: 403, code: 'admin_required' });
    expect(await env.DB.prepare('SELECT disabled FROM user WHERE id = ?').bind(user.userId).first()).toEqual({ disabled: 0 });
  });

  it('keeps app grants, tokens and in-flight authorizations revoked after disable then enable', async () => {
    const owner = await login('owner', 113);
    const admin = await login('admin', 900001, { admin: true });
    const client = await createApplication(owner);
    const token = await issuedToken(owner, client);
    const pending = await authorizationCode(owner, client.app);
    const flow = await pendingFlow(owner, client.app, 'processing');
    expect((await introspect(owner, client, token.accessToken)).body.active).toBe(true);

    await disableApp(env, admin.userId, client.app.id, true);
    expect((await getApp(env, client.app.id, owner.userId)).app.disabled).toBe(true);
    await disableApp(env, admin.userId, client.app.id, false);
    expect((await getApp(env, client.app.id, owner.userId)).app.disabled).toBe(false);
    expect((await env.DB.prepare('SELECT id FROM verification WHERE identifier = ?').bind(pending.codeId).all()).results).toHaveLength(0);
    expect(await introspect(owner, client, token.accessToken)).toEqual({ status: 200, body: { active: false } });
    expect((await exchangeCode(owner, client, pending)).status).toBe(400);
    expect(await env.DB.prepare('SELECT state FROM grant_ledger WHERE code_id = ?').bind(pending.codeId).first()).toEqual({ state: 'canceled' });
    expect(await env.DB.prepare('SELECT status FROM authorization_request WHERE id = ?').bind(flow.id).first()).toEqual({ status: 'canceled' });
    expect(await env.DB.prepare('SELECT status, encrypted_payload FROM connect_transaction WHERE id = ?').bind(flow.transactionId).first()).toEqual({ status: 'canceled', encrypted_payload: null });
    expect((await env.DB.prepare('SELECT id FROM oauth_consent WHERE client_id = ?').bind(client.app.client_id).all()).results).toHaveLength(0);
    const fresh = await issuedToken(owner, client);
    expect((await introspect(owner, client, fresh.accessToken)).body.active).toBe(true);
  });

  it('keeps user events, grants, tokens and sessions revoked after disable then enable', async () => {
    const owner = await login('owner', 114, { method: 'lite_self_app' });
    const admin = await login('admin', 900001, { admin: true });
    const client = await createApplication(owner);
    const token = await issuedToken(owner, client);
    const pending = await authorizationCode(owner, client.app);
    const flow = await pendingFlow(owner, client.app, 'processing');
    await disableUser(env, admin.userId, owner.userId, true);
    await disableUser(env, admin.userId, owner.userId, false);

    expect(await env.DB.prepare('SELECT disabled, credential_epoch FROM user WHERE id = ?').bind(owner.userId).first()).toEqual({ disabled: 0, credential_epoch: 1 });
    expect((await env.DB.prepare('SELECT revoked_at FROM auth_event WHERE id = ?').bind(owner.eventId).first<{ revoked_at: number }>())?.revoked_at).toBeGreaterThan(0);
    expect(await owner.auth.api.getSession({ headers: owner.headers })).toBeNull();
    expect(await introspect(owner, client, token.accessToken)).toEqual({ status: 200, body: { active: false } });
    expect((await userInfo(owner, token.accessToken)).status).toBe(401);
    expect((await exchangeCode(owner, client, pending)).status).toBe(400);
    expect(await env.DB.prepare('SELECT state FROM grant_ledger WHERE code_id = ?').bind(pending.codeId).first()).toEqual({ state: 'canceled' });
    expect(await env.DB.prepare('SELECT status FROM authorization_request WHERE id = ?').bind(flow.id).first()).toEqual({ status: 'canceled' });
    expect(await env.DB.prepare('SELECT status, encrypted_payload FROM connect_transaction WHERE id = ?').bind(flow.transactionId).first()).toEqual({ status: 'canceled', encrypted_payload: null });
  });

  it('soft-deletes applications permanently, clears their secret and rejects re-enabling', async () => {
    const owner = await login('owner', 115);
    const admin = await login('admin', 900001, { admin: true });
    const client = await createApplication(owner);
    const token = await issuedToken(owner, client);
    const pending = await authorizationCode(owner, client.app);
    await deleteApp(env, client.app.id, owner.userId, false);
    expect((await env.DB.prepare('SELECT id FROM verification WHERE identifier = ?').bind(pending.codeId).all()).results).toHaveLength(0);
    await expect(disableApp(env, admin.userId, client.app.id, false)).rejects.toMatchObject({ status: 404, code: 'app_not_found' });
    await expect(updateApp(env, client.app.id, owner.userId, false, appInput())).rejects.toMatchObject({ status: 404, code: 'app_not_found' });
    await expect(rotateAppSecret(env, owner.auth, owner.headers, client.app.id, owner.userId, false)).rejects.toMatchObject({ status: 404, code: 'app_not_found' });
    expect((await listApps(env, admin.userId, true)).apps).toHaveLength(0);
    expect(await env.DB.prepare('SELECT disabled, client_secret, secret_ciphertext FROM oauth_client WHERE id = ?').bind(client.app.id).first())
      .toEqual({ disabled: 1, client_secret: null, secret_ciphertext: null });
    await expect(readAppSecret(env, client.app.id, owner.userId)).rejects.toMatchObject({ status: 404, code: 'app_not_found' });
    expect((await env.DB.prepare('SELECT deleted_at FROM app_settings WHERE client_id = ?').bind(client.app.client_id).first<{ deleted_at: number }>())?.deleted_at).toBeGreaterThan(0);
    expect((await userInfo(owner, token.accessToken)).status).toBe(401);
    expect(await env.DB.prepare('SELECT state FROM grant_ledger WHERE code_id = ?').bind(pending.codeId).first()).toEqual({ state: 'canceled' });
  });

  it('keeps deletion permanent when it races an administrator re-enable', async () => {
    const owner = await login('owner', 118);
    const admin = await login('admin', 900001, { admin: true });
    const client = await createApplication(owner);
    await disableApp(env, admin.userId, client.app.id, true);
    let release!: () => void;
    let signal!: () => void;
    const blocked = new Promise<void>((resolve) => { release = resolve; });
    const entered = new Promise<void>((resolve) => { signal = resolve; });
    const pausedDb = new Proxy(env.DB, {
      get(target, property) {
        if (property === 'batch') return async (statements: D1PreparedStatement[]) => {
          signal();
          await blocked;
          return target.batch(statements);
        };
        const member = Reflect.get(target, property);
        return typeof member === 'function' ? member.bind(target) : member;
      },
    });
    // Pause after the administrator's ownership/read checks, before its durable mutation.
    const enabling = disableApp({ ...env, DB: pausedDb }, admin.userId, client.app.id, false);
    await entered;
    try {
      await deleteApp(env, client.app.id, owner.userId, false);
    } finally {
      release();
    }
    await enabling;
    expect(await env.DB.prepare('SELECT disabled, client_secret FROM oauth_client WHERE id = ?').bind(client.app.id).first()).toEqual({ disabled: 1, client_secret: null });
    await expect(getApp(env, client.app.id, owner.userId)).rejects.toMatchObject({ status: 404, code: 'app_not_found' });
  });
});

describe('Lite-only policy and immutable issued-token provenance', () => {
  it('preserves official tokens already issued, cancels pending official grants and preserves Lite grants', async () => {
    const official = await login('official-user', 116);
    const lite = await login('lite-user', 117, { method: 'lite_self_app' });
    const client = await createApplication(official);
    const issued = await issuedToken(official, client);
    const officialCode = await authorizationCode(official, client.app);
    const liteCode = await authorizationCode(lite, client.app);
    const officialFlow = await pendingFlow(official, client.app, 'processing');
    const liteFlow = await pendingFlow(lite, client.app);
    const before = await env.DB.prepare('SELECT expires_at, reference_id, revoked FROM oauth_access_token WHERE id = ?')
      .bind(issued.tokenId).first();

    await updateApp(env, client.app.id, official.userId, false, appInput({ lite_only: true }));
    expect(await introspect(official, client, issued.accessToken)).toMatchObject({ status: 200, body: { active: true } });
    expect(await userInfo(official, issued.accessToken)).toMatchObject({ status: 200, body: {
      login_method: 'official_connect', auth_source: 'linuxdo', upstream_client_id: env.CONNECT_CLIENT_ID, liteauth_user_id: official.userId,
    } });
    expect(await env.DB.prepare('SELECT expires_at, reference_id, revoked FROM oauth_access_token WHERE id = ?').bind(issued.tokenId).first()).toEqual(before);
    expect(await env.DB.prepare('SELECT state FROM grant_ledger WHERE code_id = ?').bind(officialCode.codeId).first()).toEqual({ state: 'canceled' });
    expect(await env.DB.prepare('SELECT status FROM authorization_request WHERE id = ?').bind(officialFlow.id).first()).toEqual({ status: 'canceled' });
    expect(await env.DB.prepare('SELECT status, encrypted_payload FROM connect_transaction WHERE id = ?').bind(officialFlow.transactionId).first()).toEqual({ status: 'canceled', encrypted_payload: null });
    expect(await env.DB.prepare('SELECT status FROM authorization_request WHERE id = ?').bind(liteFlow.id).first()).toEqual({ status: 'pending' });
    expect((await exchangeCode(lite, client, liteCode)).status).toBe(200);

    await updateApp(env, client.app.id, official.userId, false, appInput({ lite_only: false }));
    const rejected = await exchangeCode(official, client, officialCode);
    expect(rejected.status).toBe(400);
    expect(await rejected.json()).toMatchObject({ error: 'invalid_grant' });
    expect(await env.DB.prepare('SELECT state FROM grant_ledger WHERE code_id = ?').bind(officialCode.codeId).first()).toEqual({ state: 'canceled' });
    expect((await introspect(official, client, issued.accessToken)).body.active).toBe(true);
    expect((await userInfo(official, issued.accessToken)).body.login_method).toBe('official_connect');
  });
});
