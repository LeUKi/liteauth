import { env } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';
import { makeSignature } from 'better-auth/crypto';
import * as oidc from 'openid-client';
import { createAuth, eventClaims, userInfoSnapshotClaims } from '../src/auth';
import { createApp } from '../src/apps';
import { setAppPolicy } from '../src/db/policy';
import { randomId } from '../src/crypto';
import { app } from '../src/index';
import type { LoginMethod } from '@liteauth/contracts';
import { officialLockStatements } from '../src/account-policy';

const redirectUri = 'https://rp.example/callback';
async function fixture(method: LoginMethod = 'official_connect', clientType: 'confidential' | 'public' = 'confidential', trustLevel = 0) {
  const auth = createAuth(env);
  const context = await auth.$context;
  const user = await context.internalAdapter.createUser({ name: 'Alice', email: '123@linuxdo.liteauth.invalid', emailVerified: false, linuxdoId: 123, username: 'alice' }, { method: 'linuxdo-connect' });
  const eventId = randomId('ae_');
  await env.DB.prepare('INSERT INTO auth_event (id, user_id, login_method, upstream_client_id, trust_level, profile, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .bind(eventId, user.id, method, method === 'official_connect' ? 'platform-client' : 'alice-client', trustLevel, JSON.stringify({ id: 123, username: 'alice', name: 'Alice', avatar_url: null, trust_level: trustLevel, active: true, silenced: false }), Date.now()).run();
  const session = await context.internalAdapter.createSession(user.id, false, { authEventId: eventId }, true);
  if (!session) throw new Error('Session fixture failed');
  const cookie = `${context.authCookies.sessionToken.name}=${encodeURIComponent(`${session.token}.${await makeSignature(session.token, env.BETTER_AUTH_SECRET)}`)}`;
  const headers = new Headers({ Cookie: cookie, Origin: env.APP_ORIGIN, Accept: 'application/json' });
  const client = await createApp(env, auth, headers, { name: 'Test RP', redirect_uris: [redirectUri], lite_only: false, client_type: clientType, pkce_required: true });
  return { auth, context, user, eventId, session, cookie, headers, client };
}

async function authorization(f: Awaited<ReturnType<typeof fixture>>, scopes = 'openid profile', extra: Record<string, string> = {}) {
  const verifier = oidc.randomPKCECodeVerifier();
  const parameters = new URLSearchParams({ client_id: f.client.app.client_id, redirect_uri: redirectUri, response_type: 'code', scope: scopes, state: 'rp-state', nonce: 'rp-nonce', code_challenge: await oidc.calculatePKCECodeChallenge(verifier), code_challenge_method: 'S256', ...extra });
  const response = await f.auth.handler(new Request(`${env.APP_ORIGIN}/api/auth/oauth2/authorize?${parameters}`, { headers: f.headers }));
  expect(response.status).toBe(200);
  const redirect = await response.json() as { redirect: boolean; url: string };
  expect(redirect.redirect).toBe(true);
  const consentUrl = new URL(redirect.url, env.APP_ORIGIN);
  if (consentUrl.pathname === '/callback') {
    expect(consentUrl.searchParams.get('state')).toBe('rp-state');
    const code = consentUrl.searchParams.get('code'); expect(code).toBeTruthy();
    return { code: code!, verifier, callback: consentUrl };
  }
  expect(consentUrl.pathname).toBe('/consent');
  const consent = await f.auth.handler(new Request(`${env.APP_ORIGIN}/api/auth/oauth2/consent`, { method: 'POST', headers: { ...Object.fromEntries(f.headers), 'Content-Type': 'application/json' }, body: JSON.stringify({ accept: true, oauth_query: consentUrl.searchParams.toString() }) }));
  expect(consent.status).toBe(200);
  const result = await consent.json() as { redirect: boolean; url: string };
  const callback = new URL(result.url);
  expect(callback.searchParams.get('state')).toBe('rp-state');
  const code = callback.searchParams.get('code'); expect(code).toBeTruthy();
  return { code: code!, verifier, callback };
}

function redeem(f: Awaited<ReturnType<typeof fixture>>, authorization: { code: string; verifier: string }, resource?: string) {
  const body = new URLSearchParams({ grant_type: 'authorization_code', client_id: f.client.app.client_id, client_secret: f.client.client_secret!, code: authorization.code, code_verifier: authorization.verifier, redirect_uri: redirectUri });
  if (resource) body.set('resource', resource);
  return f.auth.handler(new Request(`${env.APP_ORIGIN}/api/auth/oauth2/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body }));
}
async function userinfo(f: Awaited<ReturnType<typeof fixture>>, token: string) {
  return f.auth.handler(new Request(`${env.APP_ORIGIN}/api/auth/oauth2/userinfo`, { headers: { Authorization: `Bearer ${token}` } }));
}

describe('real Better Auth / Drizzle / D1 authorization flow', () => {
  it.each([['official_connect', 'confidential'], ['lite_self_app', 'public']] as const)('interoperates with openid-client discovery, code exchange and UserInfo for %s / %s', async (method, clientType) => {
    const f = await fixture(method, clientType);
    const config = await oidc.discovery(new URL(`${env.APP_ORIGIN}/api/auth`), f.client.app.client_id,
      { token_endpoint_auth_method: clientType === 'public' ? 'none' : 'client_secret_post', id_token_signed_response_alg: 'RS256' },
      clientType === 'public' ? oidc.None() : oidc.ClientSecretPost(f.client.client_secret!),
      { execute: [oidc.allowInsecureRequests], [oidc.customFetch]: async (input, init) => app.fetch(new Request(input, init), env) });
    const code = await authorization(f);
    const tokens = await oidc.authorizationCodeGrant(config, code.callback, { expectedState: 'rp-state', expectedNonce: 'rp-nonce', pkceCodeVerifier: code.verifier, idTokenExpected: true });
    const claims = tokens.claims()!;
    expect(claims.sub).toBe(f.user.id);
    const profile = await oidc.fetchUserInfo(config, tokens.access_token, claims.sub);
    expect(profile).toMatchObject({ sub: f.user.id, id: 123, login_method: method, liteauth_user_id: f.user.id });
    await expect(oidc.fetchUserInfo(config, tokens.access_token, `${claims.sub}-different-user`)).rejects.toMatchObject({ code: 'OAUTH_JSON_ATTRIBUTE_COMPARISON_FAILED' });
  });

  it('returns standard UserInfo profile fields from the immutable authentication event', async () => {
    const f = await fixture();
    await env.DB.batch([
      env.DB.prepare('UPDATE auth_event SET profile = ? WHERE id = ?').bind(JSON.stringify({ id: 123, username: 'alice', name: 'Event Snapshot', avatar_url: 'https://linux.do/event.png', trust_level: 0, active: true, silenced: false }), f.eventId),
      env.DB.prepare('UPDATE user SET name = ?, image = ? WHERE id = ?').bind('Current Profile', 'https://linux.do/current.png', f.user.id),
    ]);
    const tokenResponse = await redeem(f, await authorization(f));
    const tokens = await tokenResponse.json() as { access_token: string };
    const info = await userinfo(f, tokens.access_token);
    expect(info.status).toBe(200);
    expect(await info.json()).toMatchObject({
      sub: f.user.id,
      name: 'Event Snapshot',
      picture: 'https://linux.do/event.png',
      username: 'alice',
      avatar_url: 'https://linux.do/event.png',
    });
  });

  it('isolates concurrent UserInfo responses across two authentication snapshots', async () => {
    const f = await fixture();
    const firstResponse = await redeem(f, await authorization(f));
    expect(firstResponse.status).toBe(200);
    const first = await firstResponse.json() as { access_token: string };
    const secondEvent = randomId('ae_');
    await env.DB.batch([
      env.DB.prepare('INSERT INTO auth_event (id, user_id, login_method, upstream_client_id, trust_level, profile, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
        .bind(secondEvent, f.user.id, 'lite_self_app', 'second-client', 2, JSON.stringify({ id: 123, username: 'alice_new', name: 'Later Snapshot', avatar_url: 'https://cdn.example/later.png', trust_level: 2, active: true, silenced: false }), Date.now()),
      env.DB.prepare('UPDATE session SET auth_event_id = ? WHERE id = ?').bind(secondEvent, f.session.id),
      env.DB.prepare('UPDATE user SET name = ?, image = ? WHERE id = ?').bind('Mutable Profile', 'https://cdn.example/current.png', f.user.id),
    ]);
    const secondResponse = await redeem(f, await authorization(f));
    expect(secondResponse.status).toBe(200);
    const second = await secondResponse.json() as { access_token: string };
    const cases = [
      { token: first.access_token, expected: { name: 'Alice', username: 'alice', login_method: 'official_connect' }, picture: undefined },
      { token: second.access_token, expected: { name: 'Later Snapshot', username: 'alice_new', login_method: 'lite_self_app' }, picture: 'https://cdn.example/later.png' },
    ];
    const responses = await Promise.all(cases.flatMap(entry => ['/api/auth/oauth2/userinfo', '/oauth2/userinfo'].map(async path => {
      const response = await app.request(path, { headers: { Authorization: `Bearer ${entry.token}` } }, env);
      return { entry, status: response.status, body: await response.json() as Record<string, unknown> };
    })));
    for (const { entry, status, body } of responses) {
      expect(status).toBe(200);
      expect(body).toMatchObject({ sub: f.user.id, ...entry.expected });
      expect(body.picture).toBe(entry.picture);
      expect(body.__liteauth_userinfo_snapshot).toBeUndefined();
    }
  });

  it('omits missing standard UserInfo picture fields and honors openid-only scope', async () => {
    const f = await fixture();
    await env.DB.prepare('UPDATE user SET name = ?, image = ? WHERE id = ?').bind('Current Profile', 'https://linux.do/current.png', f.user.id).run();
    const tokenResponse = await redeem(f, await authorization(f));
    const tokens = await tokenResponse.json() as { access_token: string };
    const profile = await (await userinfo(f, tokens.access_token)).json() as Record<string, unknown>;
    expect(profile).toMatchObject({ sub: f.user.id, name: 'Alice', avatar_url: null });
    expect(profile.picture).toBeUndefined();
    expect(profile.given_name).toBeUndefined();
    expect(profile.family_name).toBeUndefined();
    expect(profile.__liteauth_userinfo_snapshot).toBeUndefined();

    const openidOnlyClaims = await userInfoSnapshotClaims(env, f.eventId, f.user.id, ['openid']);
    expect(openidOnlyClaims).toMatchObject({
      id: 123,
      username: 'alice',
      avatar_url: null,
      login_method: 'official_connect',
      auth_source: 'linuxdo',
      upstream_client_id: 'platform-client',
      liteauth_user_id: f.user.id,
    });
    expect(openidOnlyClaims.name).toBeUndefined();
    expect(openidOnlyClaims.picture).toBeUndefined();
  });

  it('rejects oversized management and OAuth bodies before parsing them', async () => {
    const limit = 64 * 1024;
    const prefix = '{"username":"';
    const suffix = '"}';
    const exact = `${prefix}${'a'.repeat(limit - prefix.length - suffix.length)}${suffix}`;
    const allowed = await app.request('/api/login/lite', { method: 'POST', headers: { Origin: env.APP_ORIGIN, 'Content-Type': 'application/json' }, body: exact }, env);
    expect(allowed.status).not.toBe(413);

    const tooLargeJson = `${exact} `;
    const management = await app.request('/api/login/lite', { method: 'POST', headers: { Origin: env.APP_ORIGIN, 'Content-Type': 'application/json' }, body: tooLargeJson }, env);
    expect(management.status).toBe(413);
    expect(await management.json()).toEqual({ error: { code: 'payload_too_large', message: '请求内容过大' } });

    const protocol = await app.request('/oauth2/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: `grant_type=authorization_code&${'x'.repeat(limit)}` }, env);
    expect(protocol.status).toBe(413);
    expect(await protocol.json()).toEqual({ error: 'invalid_request', error_description: 'Payload too large' });

    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('x'.repeat(limit + 1)));
        controller.close();
      },
    });
    const streamed = await app.fetch(new Request(`${env.APP_ORIGIN}/oauth2/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: stream,
      duplex: 'half',
    } as RequestInit), env);
    expect(streamed.status).toBe(413);
  });

  it('retains provider replay revocation when a concurrent losing exchange runs after the winning token was issued', async () => {
    const f = await fixture('lite_self_app', 'public');
    let releaseIssued!: () => void;
    const issued = new Promise<void>((resolve) => { releaseIssued = resolve; });
    let tokenRequests = 0;
    const config = await oidc.discovery(new URL(`${env.APP_ORIGIN}/api/auth`), f.client.app.client_id,
      { token_endpoint_auth_method: 'none', id_token_signed_response_alg: 'RS256' }, oidc.None(),
      { execute: [oidc.allowInsecureRequests], [oidc.customFetch]: async (input, init) => {
        if (new URL(input).pathname === '/api/auth/oauth2/token') {
          const call = ++tokenRequests;
          if (call === 2) await issued;
          const response = await app.fetch(new Request(input, init), env);
          if (call === 1) releaseIssued();
          return response;
        }
        return app.fetch(new Request(input, init), env);
      } });
    const code = await authorization(f);
    const checks = { expectedState: 'rp-state', expectedNonce: 'rp-nonce', pkceCodeVerifier: code.verifier, idTokenExpected: true };
    const results = await Promise.allSettled([
      oidc.authorizationCodeGrant(config, new URL(code.callback), checks),
      oidc.authorizationCodeGrant(config, new URL(code.callback), checks),
    ]);
    const successes = results.filter((result) => result.status === 'fulfilled');
    const failures = results.filter((result) => result.status === 'rejected');
    expect(successes).toHaveLength(1); expect(failures).toHaveLength(1);
    expect(failures[0].reason).toBeInstanceOf(oidc.ResponseBodyError);
    expect(failures[0].reason.error).toBe('invalid_grant');
    expect((await env.DB.prepare('SELECT count(*) AS count FROM oauth_access_token').first<{ count: number }>())?.count).toBe(0);
    const tokens = successes[0].value;
    const profile = await app.request('/api/auth/oauth2/userinfo', { headers: { Authorization: `Bearer ${tokens.access_token}` } }, env);
    expect(profile.status).toBe(401);
    await expect(oidc.fetchUserInfo(config, tokens.access_token, tokens.claims()!.sub)).rejects.toThrow();
  });

  it('rejects malformed request-bound code records before persistence while retaining unrelated verification support', async () => {
    const data = { identifier: 'malformed-code', value: 'not-json', expiresAt: new Date(Date.now() + 120_000), createdAt: new Date(), updatedAt: new Date() };
    const bound = await createAuth(env, 'test-client', 'test-request').$context;
    await expect(bound.adapter.create({ model: 'verification', data })).rejects.toMatchObject({ body: { error: 'invalid_grant' } });
    expect((await env.DB.prepare('SELECT count(*) AS count FROM verification').first<{ count: number }>())?.count).toBe(0);
    expect((await env.DB.prepare('SELECT count(*) AS count FROM grant_ledger').first<{ count: number }>())?.count).toBe(0);
    const unrelated = await createAuth(env).$context;
    await unrelated.adapter.create({ model: 'verification', data: { ...data, identifier: 'unrelated-verification' } });
    expect(await env.DB.prepare('SELECT identifier, value FROM verification').first()).toMatchObject({ identifier: 'unrelated-verification', value: 'not-json' });
    expect((await env.DB.prepare('SELECT count(*) AS count FROM grant_ledger').first<{ count: number }>())?.count).toBe(0);
  });

  it('issues opaque tokens, verifies signed OIDC tokens, and retains issued Lite provenance after official upgrade', async () => {
    const f = await fixture('lite_self_app');
    const code = await authorization(f);
    const expiry = await env.DB.prepare('SELECT created_at, expires_at FROM verification').first<{ created_at: number; expires_at: number }>();
    expect(expiry!.expires_at - expiry!.created_at).toBeLessThanOrEqual(121_000);
    const response = await redeem(f, code); expect(response.status).toBe(200);
    const tokens = await response.json() as { access_token: string; id_token: string; refresh_token?: string };
    const officialEvent = randomId('ae_');
    await env.DB.prepare('INSERT INTO auth_event (id, user_id, login_method, upstream_client_id, trust_level, profile, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .bind(officialEvent, f.user.id, 'official_connect', 'platform-client', 4, JSON.stringify({ id: 123, username: 'alice', name: 'Alice', trust_level: 4 }), Date.now()).run();
    await env.DB.batch(officialLockStatements(env.DB, f.user.id, Date.now()));
    await f.context.internalAdapter.createSession(f.user.id, false, { authEventId: officialEvent }, true);
    expect(tokens.access_token.split('.')).toHaveLength(1); expect(tokens.refresh_token).toBeUndefined();
    const stored = await env.DB.prepare('SELECT reference_id FROM oauth_access_token').first<{ reference_id: string }>();
    expect(stored?.reference_id).toBe(f.eventId);
    const info = await userinfo(f, tokens.access_token); expect(info.status).toBe(200);
    expect(await info.json()).toMatchObject({ sub: f.user.id, id: 123, username: 'alice', login_method: 'lite_self_app', upstream_client_id: 'alice-client', liteauth_user_id: f.user.id });
    const decode = (value: string) => Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), character => character.charCodeAt(0));
    const [protectedHeader, payload, signature] = tokens.id_token.split('.');
    const header = JSON.parse(new TextDecoder().decode(decode(protectedHeader))) as { kid: string; alg: string };
    const claims = JSON.parse(new TextDecoder().decode(decode(payload))) as Record<string, unknown>;
    const jwksResponse = await f.auth.handler(new Request(`${env.APP_ORIGIN}/api/auth/jwks`));
    const jwks = await jwksResponse.json() as { keys: (JsonWebKey & { kid: string })[] };
    const jwk = jwks.keys.find(key => key.kid === header.kid)!;
    const publicKey = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
    expect(await crypto.subtle.verify('RSASSA-PKCS1-v1_5', publicKey, decode(signature), new TextEncoder().encode(`${protectedHeader}.${payload}`))).toBe(true);
    expect(claims).toMatchObject({ iss: `${env.APP_ORIGIN}/api/auth`, aud: f.client.app.client_id, nonce: 'rp-nonce', sub: f.user.id, login_method: 'lite_self_app', id: 123 });
    expect(claims.email).toBeUndefined();
  });

  it('serves UserInfo standard profile fields from the immutable authentication event', async () => {
    const f = await fixture();
    await env.DB.prepare('UPDATE auth_event SET profile=? WHERE id=?')
      .bind(JSON.stringify({ id: 123, username: 'alice', name: 'Alice Snapshot', avatar_url: 'https://cdn.example/alice.png', trust_level: 0, active: true, silenced: false }), f.eventId).run();
    const response = await redeem(f, await authorization(f, 'openid profile')); expect(response.status).toBe(200);
    const tokens = await response.json() as { access_token: string };
    await env.DB.prepare("UPDATE user SET name='Alice Changed', image='https://cdn.example/changed.png' WHERE id=?").bind(f.user.id).run();
    const info = await userinfo(f, tokens.access_token); expect(info.status).toBe(200);
    expect(await info.json()).toMatchObject({
      sub: f.user.id,
      name: 'Alice Snapshot',
      picture: 'https://cdn.example/alice.png',
      given_name: 'Alice',
      family_name: 'Snapshot',
      avatar_url: 'https://cdn.example/alice.png',
      login_method: 'official_connect',
    });
  });

  it('omits missing profile fields and keeps LiteAuth claims for openid-only UserInfo', async () => {
    const f = await fixture();
    const issued = await redeem(f, await authorization(f, 'openid')); expect(issued.status).toBe(200);
    const tokens = await issued.json() as { access_token: string };
    await env.DB.prepare("UPDATE user SET name='Mutable Name', image='https://cdn.example/current.png' WHERE id=?").bind(f.user.id).run();
    const info = await userinfo(f, tokens.access_token); expect(info.status).toBe(200);
    const body = await info.json() as Record<string, unknown>;
    expect(body).toMatchObject({ sub: f.user.id, id: 123, username: 'alice', login_method: 'official_connect' });
    expect(body.name).toBeUndefined();
    expect(body.picture).toBeUndefined();
    expect(body.given_name).toBeUndefined();
    expect(body.family_name).toBeUndefined();
  });


  it('serves requested UserInfo profile claims from the immutable event through all public endpoints', async () => {
    const f = await fixture();
    await env.DB.prepare('UPDATE auth_event SET profile=? WHERE id=?')
      .bind(JSON.stringify({ id: 123, username: 'alice', name: 'Requested Snapshot', avatar_url: null, trust_level: 0, active: true, silenced: false }), f.eventId).run();
    const claims = JSON.stringify({ userinfo: { name: null, picture: null } });
    const issued = await redeem(f, await authorization(f, 'openid', { claims })); expect(issued.status).toBe(200);
    const tokens = await issued.json() as { access_token: string };
    await env.DB.prepare("UPDATE user SET name='Mutable Name', image='https://cdn.example/current.png' WHERE id=?").bind(f.user.id).run();
    const headers = { Authorization: `Bearer ${tokens.access_token}` };
    const direct = await userinfo(f, tokens.access_token); expect(direct.status).toBe(200);
    const api = await app.request('/api/auth/oauth2/userinfo', { headers }, env); expect(api.status).toBe(200);
    const alias = await app.request('/oauth2/userinfo', { headers }, env); expect(alias.status).toBe(200);
    const bodies = await Promise.all([direct, api, alias].map(async response => response.json() as Promise<Record<string, unknown>>));
    expect(bodies[1]).toEqual(bodies[0]);
    expect(bodies[2]).toEqual(bodies[0]);
    expect(bodies[0]).toMatchObject({ sub: f.user.id, name: 'Requested Snapshot', id: 123, username: 'alice', login_method: 'official_connect' });
    expect(bodies[0].picture).toBeUndefined();
    expect(bodies[0].__liteauth_userinfo_snapshot).toBeUndefined();
  });

  it('allows one concurrent redemption and rejects authorization-code replay', async () => {
    const f = await fixture(); const code = await authorization(f);
    const responses = await Promise.all([redeem(f, code), redeem(f, code)]);
    expect(responses.filter(response => response.ok)).toHaveLength(1);
    // The losing request may revoke the winner's token if it runs after issuance, as required for code replay.
    expect((await env.DB.prepare('SELECT count(*) AS count FROM oauth_access_token').first<{ count: number }>())?.count).toBeLessThanOrEqual(1);
    expect((await env.DB.prepare("SELECT count(*) AS count FROM grant_ledger WHERE state = 'issued'").first<{ count: number }>())?.count).toBe(1);
    expect((await redeem(f, code)).ok).toBe(false);
    expect((await env.DB.prepare('SELECT count(*) AS count FROM oauth_access_token').first<{ count: number }>())?.count).toBe(0);
  });

  it('cancels unredeemed official codes permanently while keeping already issued official tokens valid', async () => {
    const f = await fixture(); const issued = await redeem(f, await authorization(f));
    const tokens = await issued.json() as { access_token: string };
    const secondVerifier = oidc.randomPKCECodeVerifier();
    const parameters = new URLSearchParams({ client_id: f.client.app.client_id, redirect_uri: redirectUri, response_type: 'code', scope: 'profile', code_challenge: await oidc.calculatePKCECodeChallenge(secondVerifier), code_challenge_method: 'S256' });
    const authorize = await f.auth.handler(new Request(`${env.APP_ORIGIN}/api/auth/oauth2/authorize?${parameters}`, { headers: f.headers }));
    const second = await authorize.json() as { url: string };
    const code = { code: new URL(second.url).searchParams.get('code')!, verifier: secondVerifier };
    await setAppPolicy(env.DB, f.client.app.client_id, true);
    expect((await redeem(f, code)).ok).toBe(false);
    const old = await userinfo(f, tokens.access_token); expect(old.status).toBe(200); expect(await old.json()).toMatchObject({ login_method: 'official_connect' });
    await setAppPolicy(env.DB, f.client.app.client_id, false);
    expect((await redeem(f, code)).ok).toBe(false);
  });

  it('does not resurrect an official code consumed before issuance when the policy is toggled on then off', async () => {
    const f = await fixture(); await authorization(f);
    const stored = await env.DB.prepare('SELECT identifier FROM verification').first<{ identifier: string }>();
    const code = await f.context.internalAdapter.consumeVerificationValue(stored!.identifier);
    expect(code).toBeTruthy();
    await setAppPolicy(env.DB, f.client.app.client_id, true); await setAppPolicy(env.DB, f.client.app.client_id, false);
    await expect(f.context.adapter.transaction(adapter => adapter.create({ model: 'oauthAccessToken', data: { token: 'test-token', clientId: f.client.app.client_id, sessionId: f.session.id, userId: f.user.id, referenceId: f.eventId, authorizationCodeId: stored!.identifier, scopes: ['profile'], createdAt: new Date(), expiresAt: new Date(Date.now() + 3600_000) } }))).rejects.toMatchObject({ body: { error: 'invalid_grant' } });
    expect((await env.DB.prepare('SELECT count(*) AS count FROM oauth_access_token').first<{ count: number }>())?.count).toBe(0);
  });

  it('allows Lite authorization for a Lite-only app', async () => {
    const f = await fixture('lite_self_app'); await setAppPolicy(env.DB, f.client.app.client_id, true);
    const tokenResponse = await redeem(f, await authorization(f)); expect(tokenResponse.ok).toBe(true);
    const tokens = await tokenResponse.json() as { access_token: string };
    expect(await (await userinfo(f, tokens.access_token)).json()).toMatchObject({ login_method: 'lite_self_app', upstream_client_id: 'alice-client' });
  });

  it('serves the Connect-compatible profile endpoint for plain OAuth without weakening OIDC UserInfo', async () => {
    const f = await fixture(); const response = await redeem(f, await authorization(f, 'profile')); expect(response.ok).toBe(true);
    const tokens = await response.json() as { access_token: string; id_token?: string }; expect(tokens.id_token).toBeUndefined();
    const info = await app.request('/api/user', { headers: { Authorization: `Bearer ${tokens.access_token}` } }, env);
    expect(info.status).toBe(200); expect(await info.json()).toMatchObject({ id: 123, username: 'alice', login_method: 'official_connect', upstream_client_id: 'platform-client' });
    expect((await userinfo(f, tokens.access_token)).ok).toBe(false);
    expect((await app.request('/api/user', {}, env)).status).toBe(401);
  });

  it('blocks direct official authorization and forbidden grant/resource/DCR routes through the Hono facade', async () => {
    const f = await fixture(); await setAppPolicy(env.DB, f.client.app.client_id, true);
    const params = new URLSearchParams({ client_id: f.client.app.client_id, redirect_uri: redirectUri, response_type: 'code', scope: 'profile', code_challenge: await oidc.calculatePKCECodeChallenge(oidc.randomPKCECodeVerifier()), code_challenge_method: 'S256' });
    const response = await app.request(`/oauth2/authorize?${params}`, { headers: { Cookie: f.cookie, Accept: 'text/html' } }, env);
    expect(response.status).toBe(302); const location = response.headers.get('Location')!; expect(new URL(location).pathname).toBe('/login');
    expect(new URL(location).searchParams.get('request')).toBeTruthy();
    expect((await app.request('/api/auth/oauth2/register', { method: 'POST' }, env)).status).toBe(403);
    const machine = await app.request('/oauth2/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'client_credentials', client_id: f.client.app.client_id, client_secret: f.client.client_secret! }) }, env);
    expect(machine.ok).toBe(false);
    const resource = await app.request('/oauth2/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'authorization_code', resource: 'https://evil.example' }) }, env);
    expect(resource.status).toBe(400); expect(await resource.json()).toMatchObject({ error: 'invalid_target' });
  });

  it('rejects oversized request bodies before JSON, form or provider parsing', async () => {
    const oversizedJson = JSON.stringify({ username: 'alice', padding: 'x'.repeat(64 * 1024) });
    const login = await app.request('/api/login/lite', {
      method: 'POST',
      headers: { Origin: env.APP_ORIGIN, 'Content-Type': 'application/json' },
      body: oversizedJson,
    }, env);
    expect(login.status).toBe(413);
    expect(await login.json()).toMatchObject({ error: { code: 'payload_too_large' } });

    const oversizedForm = new URLSearchParams({ grant_type: 'authorization_code', code: 'x'.repeat(64 * 1024) }).toString();
    const token = await app.request('/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: oversizedForm,
    }, env);
    expect(token.status).toBe(413);
    expect(await token.json()).toMatchObject({ error: 'invalid_request', error_description: 'Payload too large' });

    const declaredLarge = await app.request('/api/login/lite', {
      method: 'POST',
      headers: { Origin: env.APP_ORIGIN, 'Content-Type': 'application/json', 'Content-Length': String(64 * 1024 + 1) },
      body: '{}',
    }, env);
    expect(declaredLarge.status).toBe(413);
    expect(await declaredLarge.json()).toMatchObject({ error: { code: 'payload_too_large' } });

    const declaredLargeProtocol = await app.request('/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': String(64 * 1024 + 1) },
      body: 'grant_type=authorization_code',
    }, env);
    expect(declaredLargeProtocol.status).toBe(413);
    expect(await declaredLargeProtocol.json()).toMatchObject({ error: 'invalid_request', error_description: 'Payload too large' });

    const chunk = new TextEncoder().encode('x'.repeat(33 * 1024));
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(chunk);
        controller.enqueue(chunk);
        controller.close();
      },
    });
    const streamed = await app.fetch(new Request(`${env.APP_ORIGIN}/api/login/lite`, {
      method: 'POST',
      headers: { Origin: env.APP_ORIGIN, 'Content-Type': 'application/json' },
      body: stream,
      duplex: 'half',
    } as RequestInit & { duplex: 'half' }), env);
    expect(streamed.status).toBe(413);

    const small = await app.request('/api/login/lite', {
      method: 'POST',
      headers: { Origin: env.APP_ORIGIN, 'Content-Type': 'application/json' },
      body: '{}',
    }, env);
    expect(small.status).not.toBe(413);
  });

  it('keeps token issuance and policy changes ordered atomically under concurrent D1 operations', async () => {
    const f = await fixture(); const code = await authorization(f);
    const [response] = await Promise.all([redeem(f, code), setAppPolicy(env.DB, f.client.app.client_id, true)]);
    const ledger = await env.DB.prepare('SELECT state FROM grant_ledger').first<{ state: string }>();
    const tokens = await env.DB.prepare('SELECT count(*) AS count FROM oauth_access_token').first<{ count: number }>();
    expect(ledger?.state).toBe(response.ok ? 'issued' : 'canceled'); expect(tokens?.count).toBe(response.ok ? 1 : 0);
  });
});

describe('minimum verified level admission', () => {
  const levelCases = [0, 1, 2, 3, 4].flatMap(level => [['official_connect', level], ['lite_self_app', level]] as [LoginMethod, number][]);
  it.each(levelCases)('admits a %s immutable level %i snapshot at that minimum', async (method, level) => {
    const f = await fixture(method, 'confidential', level);
    await setAppPolicy(env.DB, f.client.app.client_id, false, level);
    const response = await redeem(f, await authorization(f));
    expect(response.status).toBe(200);
    const tokens = await response.json() as { access_token: string };
    expect(await (await userinfo(f, tokens.access_token)).json()).toMatchObject({ trust_level: level });
  });

  it.each(['official_connect', 'lite_self_app'] as const)('blocks an insufficient %s session in both the facade and native consent handler', async (method) => {
    const f = await fixture(method, 'confidential', 1);
    await setAppPolicy(env.DB, f.client.app.client_id, false, 2);
    const verifier = oidc.randomPKCECodeVerifier();
    const query = new URLSearchParams({ client_id: f.client.app.client_id, redirect_uri: redirectUri, response_type: 'code', scope: 'profile', code_challenge: await oidc.calculatePKCECodeChallenge(verifier), code_challenge_method: 'S256' });
    const facade = await app.request(`/oauth2/authorize?${query}`, { headers: { Cookie: f.cookie } }, env);
    expect(facade.status).toBe(302);
    expect(new URL(facade.headers.get('Location')!).pathname).toBe('/login');
    const native = await f.auth.handler(new Request(`${env.APP_ORIGIN}/api/auth/oauth2/authorize?${query}`, { headers: f.headers }));
    const nativeBody = await native.json() as { url: string };
    const consent = await f.auth.handler(new Request(`${env.APP_ORIGIN}/api/auth/oauth2/consent`, {
      method: 'POST', headers: { ...Object.fromEntries(f.headers), 'Content-Type': 'application/json' },
      body: JSON.stringify({ accept: true, oauth_query: new URL(nativeBody.url, env.APP_ORIGIN).searchParams.toString() }),
    }));
    expect(consent.ok).toBe(false);
    expect(await env.DB.prepare('SELECT id FROM verification').first()).toBeNull();
    expect(await env.DB.prepare('SELECT id FROM oauth_access_token').first()).toBeNull();
  });

  it('does not substitute mutable profile JSON or another session for the authoritative level snapshot', async () => {
    const f = await fixture('lite_self_app', 'confidential', 1);
    await env.DB.prepare('UPDATE auth_event SET profile=? WHERE id=?').bind(JSON.stringify({ id: 123, username: 'alice', trust_level: 4 }), f.eventId).run();
    await env.DB.prepare('INSERT INTO auth_event (id,user_id,login_method,upstream_client_id,trust_level,profile,created_at) VALUES (?,?,?,?,?,?,?)')
      .bind('upgraded-later', f.user.id, 'lite_self_app', 'alice-client', 4, JSON.stringify({ id: 123, username: 'alice', trust_level: 4 }), Date.now()).run();
    await f.context.internalAdapter.createSession(f.user.id, false, { authEventId: 'upgraded-later' }, true);
    expect(await eventClaims(env, f.eventId, f.user.id)).toMatchObject({ trust_level: 1 });
    await setAppPolicy(env.DB, f.client.app.client_id, false, 2);
    const query = new URLSearchParams({ client_id: f.client.app.client_id, redirect_uri: redirectUri, response_type: 'code', scope: 'profile', code_challenge: await oidc.calculatePKCECodeChallenge(oidc.randomPKCECodeVerifier()), code_challenge_method: 'S256' });
    const facade = await app.request(`/oauth2/authorize?${query}`, { headers: { Cookie: f.cookie } }, env);
    expect(new URL(facade.headers.get('Location')!).pathname).toBe('/login');
    expect(await env.DB.prepare('SELECT id FROM verification').first()).toBeNull();
  });

  it('requires reverification when a historical event has no validated numeric level', async () => {
    const f = await fixture('official_connect', 'confidential', 0);
    await env.DB.prepare('UPDATE auth_event SET trust_level=NULL WHERE id=?').bind(f.eventId).run();
    const query = new URLSearchParams({ client_id: f.client.app.client_id, redirect_uri: redirectUri, response_type: 'code', scope: 'profile', code_challenge: await oidc.calculatePKCECodeChallenge(oidc.randomPKCECodeVerifier()), code_challenge_method: 'S256' });
    const facade = await app.request(`/oauth2/authorize?${query}`, { headers: { Cookie: f.cookie } }, env);
    expect(new URL(facade.headers.get('Location')!).pathname).toBe('/login');
    expect(await eventClaims(env, f.eventId, f.user.id)).toMatchObject({ trust_level: null });
    expect(await env.DB.prepare('SELECT id FROM verification').first()).toBeNull();
  });

  it('combines a qualifying level with the required authentication method', async () => {
    const f = await fixture('official_connect', 'confidential', 4);
    await setAppPolicy(env.DB, f.client.app.client_id, true, 4);
    const query = new URLSearchParams({ client_id: f.client.app.client_id, redirect_uri: redirectUri, response_type: 'code', scope: 'profile', code_challenge: await oidc.calculatePKCECodeChallenge(oidc.randomPKCECodeVerifier()), code_challenge_method: 'S256' });
    const facade = await app.request(`/oauth2/authorize?${query}`, { headers: { Cookie: f.cookie } }, env);
    expect(new URL(facade.headers.get('Location')!).pathname).toBe('/login');
    expect(await env.DB.prepare('SELECT id FROM verification').first()).toBeNull();
  });

  it('keeps issued claims valid while a raised and then lowered minimum cannot resurrect a pending code', async () => {
    const f = await fixture('lite_self_app', 'confidential', 1);
    const issued = await redeem(f, await authorization(f));
    const tokens = await issued.json() as { access_token: string };
    const verifier = oidc.randomPKCECodeVerifier();
    const query = new URLSearchParams({ client_id: f.client.app.client_id, redirect_uri: redirectUri, response_type: 'code', scope: 'profile', code_challenge: await oidc.calculatePKCECodeChallenge(verifier), code_challenge_method: 'S256' });
    const second = await f.auth.handler(new Request(`${env.APP_ORIGIN}/api/auth/oauth2/authorize?${query}`, { headers: f.headers }));
    const secondBody = await second.json() as { url: string };
    const pending = { code: new URL(secondBody.url).searchParams.get('code')!, verifier };
    await setAppPolicy(env.DB, f.client.app.client_id, false, 2);
    const oldInfo = await userinfo(f, tokens.access_token);
    expect(oldInfo.status).toBe(200);
    expect(await oldInfo.json()).toMatchObject({ trust_level: 1, login_method: 'lite_self_app' });
    await setAppPolicy(env.DB, f.client.app.client_id, false, 0);
    expect((await redeem(f, pending)).ok).toBe(false);
  });

  it('permanently rejects a consumed code whose final issuance loses to a minimum increase', async () => {
    const f = await fixture('official_connect', 'confidential', 1);
    await authorization(f);
    const stored = await env.DB.prepare('SELECT identifier FROM verification').first<{ identifier: string }>();
    expect(await f.context.internalAdapter.consumeVerificationValue(stored!.identifier)).toBeTruthy();
    await setAppPolicy(env.DB, f.client.app.client_id, false, 2);
    await setAppPolicy(env.DB, f.client.app.client_id, false, 0);
    await expect(f.context.adapter.create({ model: 'oauthAccessToken', data: {
      token: 'late-minimum-token', clientId: f.client.app.client_id, sessionId: f.session.id, userId: f.user.id,
      referenceId: f.eventId, authorizationCodeId: stored!.identifier, scopes: ['profile'], createdAt: new Date(), expiresAt: new Date(Date.now() + 3600_000),
    } })).rejects.toMatchObject({ body: { error: 'invalid_grant' } });
    expect(await env.DB.prepare('SELECT id FROM oauth_access_token').first()).toBeNull();
  });

  it('orders token issuance against a minimum increase in one D1 commit', async () => {
    const f = await fixture('lite_self_app', 'confidential', 1);
    const code = await authorization(f);
    const [response] = await Promise.all([redeem(f, code), setAppPolicy(env.DB, f.client.app.client_id, false, 2)]);
    const ledger = await env.DB.prepare('SELECT state FROM grant_ledger').first<{ state: string }>();
    expect(ledger?.state).toBe(response.ok ? 'issued' : 'canceled');
    expect((await env.DB.prepare('SELECT count(*) AS count FROM oauth_access_token').first<{ count: number }>())?.count).toBe(response.ok ? 1 : 0);
  });
});

describe('official account lock with native OAuth handling', () => {
  it('keeps previously issued Lite OAuth/OIDC claims valid while redirecting the stale Lite management cookie', async () => {
    const f = await fixture('lite_self_app');
    const issued = await redeem(f, await authorization(f));
    expect(issued.status).toBe(200);
    const tokens = await issued.json() as { access_token: string; id_token: string };
    const claimsBefore = JSON.parse(atob(tokens.id_token.split('.')[1].replaceAll('-', '+').replaceAll('_', '/'))) as Record<string, unknown>;
    await env.DB.batch(officialLockStatements(env.DB, f.user.id, Date.now()));
    await env.DB.prepare("UPDATE user SET username='renamed',name='New name',last_login_method='official_connect' WHERE id=?").bind(f.user.id).run();
    const info = await userinfo(f, tokens.access_token);
    expect(info.status).toBe(200);
    expect(await info.json()).toMatchObject({ sub: f.user.id, username: 'alice', login_method: 'lite_self_app', trust_level: 0 });
    const compatible = await app.request('/api/user', { headers: { Authorization: `Bearer ${tokens.access_token}` } }, env);
    expect(compatible.status).toBe(200);
    expect(await compatible.json()).toMatchObject({ id: 123, username: 'alice', login_method: 'lite_self_app' });
    const claimsAfter = JSON.parse(atob(tokens.id_token.split('.')[1].replaceAll('-', '+').replaceAll('_', '/'))) as Record<string, unknown>;
    expect(claimsAfter).toEqual(claimsBefore); expect(claimsAfter.login_method).toBe('lite_self_app');
    expect((await env.DB.prepare('SELECT revoked_at FROM auth_event WHERE id=?').bind(f.eventId).first<{ revoked_at: number | null }>())!.revoked_at).toBeNull();
    expect(await env.DB.prepare('SELECT id FROM session WHERE id=?').bind(f.session.id).first()).toBeTruthy();
    const management = await app.request('/api/session', { headers: f.headers }, env);
    expect(await management.json()).toMatchObject({ user: null });
    const query = new URLSearchParams({ client_id: f.client.app.client_id, redirect_uri: redirectUri, response_type: 'code', scope: 'openid profile', code_challenge: await oidc.calculatePKCECodeChallenge(oidc.randomPKCECodeVerifier()), code_challenge_method: 'S256' });
    const native = await f.auth.handler(new Request(`${env.APP_ORIGIN}/api/auth/oauth2/authorize?${query}`, { headers: f.headers }));
    expect(native.status).toBe(200);
    const prompt = await native.json() as { url: string };
    expect(new URL(prompt.url, env.APP_ORIGIN).pathname).toBe('/login');
    const snapshot = await eventClaims(env, f.eventId, f.user.id);
    expect(snapshot.login_method).toBe('lite_self_app');
  });

  it('blocks old consent confirmation and code persistence after the account lock', async () => {
    const f = await fixture('lite_self_app');
    const query = new URLSearchParams({ client_id: f.client.app.client_id, redirect_uri: redirectUri, response_type: 'code', scope: 'profile', code_challenge: await oidc.calculatePKCECodeChallenge(oidc.randomPKCECodeVerifier()), code_challenge_method: 'S256' });
    const response = await f.auth.handler(new Request(`${env.APP_ORIGIN}/api/auth/oauth2/authorize?${query}`, { headers: f.headers }));
    const prompt = await response.json() as { url: string };
    expect(new URL(prompt.url, env.APP_ORIGIN).pathname).toBe('/consent');
    await env.DB.batch(officialLockStatements(env.DB, f.user.id, Date.now()));
    const consent = await f.auth.handler(new Request(`${env.APP_ORIGIN}/api/auth/oauth2/consent`, {
      method: 'POST', headers: { ...Object.fromEntries(f.headers), 'Content-Type': 'application/json' },
      body: JSON.stringify({ accept: true, oauth_query: new URL(prompt.url, env.APP_ORIGIN).searchParams.toString() }),
    }));
    expect(consent.status).toBe(403);
    expect(await consent.json()).toMatchObject({ error: 'official_login_required' });
    expect(await env.DB.prepare('SELECT id FROM verification').first()).toBeNull();
    expect(await env.DB.prepare('SELECT id FROM oauth_access_token').first()).toBeNull();
  });

  it('permanently cancels an already-consumed pending code while preserving prior token issuance', async () => {
    const f = await fixture('lite_self_app');
    const prior = await redeem(f, await authorization(f)); expect(prior.status).toBe(200);
    const priorTokens = await prior.json() as { access_token: string };
    await authorization(f);
    const pending = await env.DB.prepare("SELECT code_id FROM grant_ledger WHERE state='pending'").first<{ code_id: string }>();
    expect(await f.context.internalAdapter.consumeVerificationValue(pending!.code_id)).toBeTruthy();
    await env.DB.batch(officialLockStatements(env.DB, f.user.id, Date.now()));
    await expect(f.context.adapter.create({ model: 'oauthAccessToken', data: {
      token: 'late-lite-token', clientId: f.client.app.client_id, sessionId: f.session.id, userId: f.user.id,
      referenceId: f.eventId, authorizationCodeId: pending!.code_id, scopes: ['profile'], createdAt: new Date(), expiresAt: new Date(Date.now() + 3600_000),
    } })).rejects.toMatchObject({ body: { error: 'invalid_grant' } });
    expect(await env.DB.prepare('SELECT state FROM grant_ledger WHERE code_id=?').bind(pending!.code_id).first()).toEqual({ state: 'canceled' });
    expect((await env.DB.prepare('SELECT count(*) AS count FROM oauth_access_token').first<{ count: number }>())!.count).toBe(1);
    expect((await userinfo(f, priorTokens.access_token)).status).toBe(200);
  });
});
