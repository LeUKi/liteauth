import { env } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';
import { beginConnect, revokeCredentials } from '../src/connect';
import { createAuth } from '../src/auth';
import { disableUser } from '../src/admin';
import { setAppPolicy } from '../src/db/policy';
import { getRequest } from '../src/requests';
import { hash } from '../src/crypto';
import { officialLockStatements } from '../src/account-policy';

const browser = 'policy-race-browser';
const client = 'policy-race-client';

async function fixture(requestId = 'request-before-toggle') {
  await env.DB.prepare(`INSERT INTO oauth_client (id, client_id, name, disabled, redirect_uris, created_at)
    VALUES ('client-row', ?, 'Policy test', 0, '["https://rp.example/callback"]', ?)`)
    .bind(client, Date.now()).run();
  await env.DB.prepare('INSERT INTO app_settings (client_id, lite_only) VALUES (?, 0)').bind(client).run();
  await request(requestId);
}

async function request(id: string) {
  await env.DB.prepare(`INSERT INTO authorization_request
    (id,client_id,signed_query,browser_hash,auth_event_id,stage,status,created_at,expires_at)
    VALUES (?, ?, 'fixture', ?, NULL, 'login', 'pending', ?, ?)`)
    .bind(id, client, await hash(browser), Date.now(), Date.now() + 600_000).run();
}

describe('anonymous official authorization policy ordering', () => {
  it('permanently cancels the request whose anonymous official login has started', async () => {
    await fixture();
    await beginConnect(env, browser, 'official_connect', { request: 'request-before-toggle' });
    await setAppPolicy(env.DB, client, true);
    await setAppPolicy(env.DB, client, false);
    await expect(getRequest(env, 'request-before-toggle', browser)).rejects.toMatchObject({ code: 'request_expired' });
    await expect(beginConnect(env, browser, 'official_connect', { request: 'request-before-toggle' })).rejects.toMatchObject({ code: 'request_expired' });
    expect(await env.DB.prepare('SELECT status, encrypted_payload FROM connect_transaction').first()).toMatchObject({ status: 'canceled', encrypted_payload: null });
    expect((await env.DB.prepare("SELECT result,reason FROM audit WHERE action='authorization.canceled'").all()).results).toEqual([{ result: 'canceled', reason: 'policy_changed' }]);
    await request('new-request-after-toggle');
    await expect(beginConnect(env, browser, 'official_connect', { request: 'new-request-after-toggle' })).resolves.toHaveProperty('redirect_url');
  });

  it('rechecks current policy at the transaction insert after an earlier allowed lookup', async () => {
    await fixture();
    let release!: () => void;
    let reached!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const waiting = new Promise<void>((resolve) => { reached = resolve; });
    const db = new Proxy(env.DB, {
      get(target, key) {
        if (key === 'prepare') return (sql: string) => {
          const statement = target.prepare(sql);
          if (!sql.startsWith('INSERT INTO connect_transaction')) return statement;
          return { bind: (...values: unknown[]) => {
            const bound = statement.bind(...values);
            return { run: async () => { reached(); await gate; return bound.run(); } };
          } };
        };
        const value = Reflect.get(target, key);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
    const pending = beginConnect({ ...env, DB: db }, browser, 'official_connect', { request: 'request-before-toggle' });
    const rejected = expect(pending).rejects.toMatchObject({ code: 'request_expired' });
    await waiting;
    await setAppPolicy(env.DB, client, true);
    release();
    await rejected;
    expect((await env.DB.prepare('SELECT id FROM connect_transaction').all()).results).toHaveLength(0);
  });
});

async function accountFixture() {
  await fixture();
  const context = await createAuth(env).$context;
  const user = await context.internalAdapter.createUser({ name: 'Alice', email: 'alice@example.invalid', emailVerified: false, linuxdoId: 123, username: 'alice' }, { method: 'linuxdo-connect' });
  const eventId = 'race-lite-event';
  await env.DB.prepare(`INSERT INTO auth_event (id,user_id,login_method,upstream_client_id,trust_level,profile,created_at)
    VALUES (?,?,'lite_self_app','self-client',0,?,?)`).bind(eventId, user.id, JSON.stringify({ id: 123, username: 'alice', trust_level: 0 }), Date.now()).run();
  const session = await context.internalAdapter.createSession(user.id, false, { authEventId: eventId }, true);
  await env.DB.prepare('UPDATE authorization_request SET auth_event_id=?').bind(eventId).run();
  const codeData = { identifier: 'race-code', value: JSON.stringify({ type: 'authorization_code', referenceId: eventId, userId: user.id, query: { client_id: client } }), createdAt: new Date(), updatedAt: new Date(), expiresAt: new Date(Date.now() + 120_000) };
  const tokenData = { token: 'race-token', clientId: client, sessionId: session!.id, userId: user.id, referenceId: eventId, authorizationCodeId: codeData.identifier, scopes: ['profile'], createdAt: new Date(), expiresAt: new Date(Date.now() + 3600_000) };
  return { context, user, eventId, session, codeData, tokenData };
}

function heldDatabase(sqlPrefix: string) {
  const gated = new WeakSet<D1PreparedStatement>();
  let release!: () => void; let reached!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const waiting = new Promise<void>(resolve => { reached = resolve; });
  const db = new Proxy(env.DB, { get(target, key) {
    if (key === 'prepare') return (sql: string) => {
      const statement = target.prepare(sql);
      if (!sql.startsWith(sqlPrefix)) return statement;
      return new Proxy(statement, { get(prepared, property) {
        if (property === 'bind') return (...values: unknown[]) => {
          const bound = prepared.bind(...values);
          const wrapped = new Proxy(bound, { get(boundTarget, boundProperty) {
            if (boundProperty === 'run') return async () => { reached(); await gate; return boundTarget.run(); };
            const value = Reflect.get(boundTarget, boundProperty); return typeof value === 'function' ? value.bind(boundTarget) : value;
          } });
          gated.add(wrapped); return wrapped;
        };
        const value = Reflect.get(prepared, property); return typeof value === 'function' ? value.bind(prepared) : value;
      } });
    };
    if (key === 'batch') return async (statements: D1PreparedStatement[]) => {
      if (statements.some(statement => gated.has(statement))) { reached(); await gate; }
      return target.batch(statements);
    };
    const value = Reflect.get(target, key); return typeof value === 'function' ? value.bind(target) : value;
  } });
  return { db, waiting, release };
}

describe('permanent account lock commit ordering', () => {
  it('rechecks the lock when a Lite transaction is inserted after an allowed owner lookup', async () => {
    const f = await accountFixture();
    await env.DB.prepare(`INSERT INTO upstream_credential (client_id,owner_user_id,kind,status,created_at,updated_at)
      VALUES ('bound-race-client',?,'self','active',?,?)`).bind(f.user.id, Date.now(), Date.now()).run();
    const held = heldDatabase('INSERT INTO connect_transaction');
    const starting = beginConnect({ ...env, DB: held.db }, browser, 'lite_self_app', { username: 'alice', client_id: 'bound-race-client', client_secret: 'secret' });
    const rejected = expect(starting).rejects.toMatchObject({ code: 'official_login_required' });
    await held.waiting; await env.DB.batch(officialLockStatements(env.DB, f.user.id, Date.now())); held.release(); await rejected;
    expect(await env.DB.prepare('SELECT id FROM connect_transaction').first()).toBeNull();
  });

  it('rejects a Lite management session insert that loses to the account lock', async () => {
    const f = await accountFixture();
    const held = heldDatabase('INSERT INTO session');
    const context = await createAuth({ ...env, DB: held.db }).$context;
    const creating = context.internalAdapter.createSession(f.user.id, false, { authEventId: f.eventId }, true);
    const rejected = expect(creating).rejects.toMatchObject({ body: { error: 'official_login_required' } });
    await held.waiting; await env.DB.batch(officialLockStatements(env.DB, f.user.id, Date.now())); held.release(); await rejected;
    expect((await env.DB.prepare('SELECT count(*) AS count FROM session').first<{ count: number }>())!.count).toBe(1);
  });

  it('blocks authorization-code persistence that loses to the account lock', async () => {
    const f = await accountFixture();
    const held = heldDatabase('INSERT INTO verification');
    const context = await createAuth({ ...env, DB: held.db }, client, 'request-before-toggle').$context;
    const creating = context.adapter.create({ model: 'verification', data: f.codeData });
    const rejected = expect(creating).rejects.toMatchObject({ body: { error: 'invalid_grant' } });
    await held.waiting; await env.DB.batch(officialLockStatements(env.DB, f.user.id, Date.now())); held.release(); await rejected;
    expect(await env.DB.prepare('SELECT id FROM verification').first()).toBeNull();
    expect(await env.DB.prepare('SELECT code_id FROM grant_ledger').first()).toBeNull();
  });

  it('blocks final token persistence that loses to the account lock after code consumption', async () => {
    const f = await accountFixture();
    await f.context.adapter.create({ model: 'verification', data: f.codeData });
    await f.context.internalAdapter.consumeVerificationValue(f.codeData.identifier);
    const held = heldDatabase('INSERT INTO oauth_access_token');
    const context = await createAuth({ ...env, DB: held.db }).$context;
    const creating = context.adapter.create({ model: 'oauthAccessToken', data: f.tokenData });
    const rejected = expect(creating).rejects.toMatchObject({ body: { error: 'invalid_grant' } });
    await held.waiting; await env.DB.batch(officialLockStatements(env.DB, f.user.id, Date.now())); held.release(); await rejected;
    expect(await env.DB.prepare('SELECT id FROM oauth_access_token').first()).toBeNull();
    expect(await env.DB.prepare('SELECT state FROM grant_ledger').first()).toEqual({ state: 'canceled' });
  });

  it('retains a token that commits before the official lock and cancels only the next pending code', async () => {
    const f = await accountFixture();
    await f.context.adapter.create({ model: 'verification', data: f.codeData });
    await f.context.adapter.create({ model: 'oauthAccessToken', data: f.tokenData });
    await f.context.adapter.create({ model: 'verification', data: { ...f.codeData, identifier: 'next-code' } });
    await env.DB.batch(officialLockStatements(env.DB, f.user.id, Date.now()));
    expect(await env.DB.prepare("SELECT revoked,reference_id FROM oauth_access_token WHERE token='race-token'").first()).toEqual({ revoked: null, reference_id: f.eventId });
    expect((await env.DB.prepare('SELECT code_id,state FROM grant_ledger ORDER BY code_id').all()).results).toEqual([
      { code_id: 'next-code', state: 'canceled' }, { code_id: 'race-code', state: 'issued' },
    ]);
  });
});

describe('explicit user revocation permanently cancels pending requests', () => {
  it.each(['credential', 'account'])('%s revocation cancels a Lite transaction pinned by an existing client binding', async (operation) => {
    await fixture();
    const context = await createAuth(env).$context;
    const user = await context.internalAdapter.createUser({ name: 'Alice', email: 'alice@example.invalid', emailVerified: false, linuxdoId: 123, username: 'alice' }, { method: 'linuxdo-connect' });
    await env.DB.prepare(`INSERT INTO upstream_credential (client_id,owner_user_id,kind,status,created_at,updated_at)
      VALUES ('alice-client',?,'self','active',?,?)`).bind(user.id, Date.now(), Date.now()).run();
    const input = { username: 'alice', client_id: 'alice-client', client_secret: 'fixture-secret', request: 'request-before-toggle' };
    await beginConnect(env, browser, 'lite_self_app', input);
    expect(await env.DB.prepare('SELECT expected_user_id FROM connect_transaction').first()).toEqual({ expected_user_id: user.id });
    if (operation === 'credential') await revokeCredentials(env, user.id);
    else {
      const admin = await context.internalAdapter.createUser({ name: 'Admin', email: 'admin@example.invalid', emailVerified: false, linuxdoId: 900001, username: 'admin', isAdmin: true }, { method: 'linuxdo-connect' });
      await disableUser(env, admin.id, user.id, true);
      await disableUser(env, admin.id, user.id, false);
    }
    await expect(getRequest(env, input.request, browser)).rejects.toMatchObject({ code: 'request_expired' });
    await expect(beginConnect(env, browser, 'lite_self_app', input)).rejects.toMatchObject({ code: 'request_expired' });
    await request('fresh-after-revocation');
    await expect(beginConnect(env, browser, 'lite_self_app', { ...input, request: 'fresh-after-revocation' })).resolves.toHaveProperty('redirect_url');
  });

  it('credential removal cancels a pending consent bound to a Lite authentication event', async () => {
    await fixture();
    const context = await createAuth(env).$context;
    const user = await context.internalAdapter.createUser({ name: 'Alice', email: 'alice@example.invalid', emailVerified: false, linuxdoId: 123, username: 'alice' }, { method: 'linuxdo-connect' });
    await env.DB.prepare("INSERT INTO auth_event (id,user_id,login_method,upstream_client_id,profile,created_at) VALUES ('lite-event',?,'lite_self_app','alice-client','{}',?)").bind(user.id, Date.now()).run();
    await env.DB.prepare("UPDATE authorization_request SET stage='consent', auth_event_id='lite-event'").run();
    await revokeCredentials(env, user.id);
    await expect(getRequest(env, 'request-before-toggle', browser)).rejects.toMatchObject({ code: 'request_expired' });
  });
});

describe('minimum level policy ordering', () => {
  it.each(['official_connect', 'lite_self_app'] as const)('cancels an in-flight identity of %s permanently when the minimum increases', async (method) => {
    await fixture();
    await beginConnect(env, browser, method, method === 'lite_self_app'
      ? { request: 'request-before-toggle', username: 'alice', client_id: 'alice-self-app', client_secret: 'fixture-secret' }
      : { request: 'request-before-toggle' });
    await setAppPolicy(env.DB, client, false, 1);
    await setAppPolicy(env.DB, client, false, 0);
    await expect(getRequest(env, 'request-before-toggle', browser)).rejects.toMatchObject({ code: 'request_expired' });
    expect(await env.DB.prepare('SELECT status, encrypted_payload FROM connect_transaction').first()).toMatchObject({ status: 'canceled', encrypted_payload: null });
    await request('fresh-after-minimum-reset');
    await expect(beginConnect(env, browser, method, method === 'lite_self_app'
      ? { request: 'fresh-after-minimum-reset', username: 'alice', client_id: 'alice-self-app', client_secret: 'fixture-secret' }
      : { request: 'fresh-after-minimum-reset' })).resolves.toHaveProperty('redirect_url');
  });

  it('cancels low and unknown pending identities while retaining qualifying consent and issued grants', async () => {
    await fixture('anonymous');
    const context = await createAuth(env).$context;
    const user = await context.internalAdapter.createUser({ name: 'Alice', email: 'alice@example.invalid', emailVerified: false, linuxdoId: 123, username: 'alice' }, { method: 'linuxdo-connect' });
    for (const [id, level] of [['low', 1], ['high', 3], ['unknown', null]] as const) {
      await env.DB.prepare('INSERT INTO auth_event (id,user_id,login_method,upstream_client_id,trust_level,profile,created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
        .bind(id, user.id, 'lite_self_app', 'alice-client', level, '{}', Date.now()).run();
      await request(id);
      await env.DB.prepare("UPDATE authorization_request SET auth_event_id=?,stage='consent' WHERE id=?").bind(id, id).run();
      await env.DB.prepare("INSERT INTO grant_ledger (code_id,client_id,auth_event_id,state,created_at,expires_at) VALUES (?,?,?,'pending',?,?)")
        .bind(id, client, id, Date.now(), Date.now() + 120_000).run();
    }
    await env.DB.prepare("INSERT INTO grant_ledger (code_id,client_id,auth_event_id,state,created_at,expires_at) VALUES ('already-issued',?,'low','issued',?,?)")
      .bind(client, Date.now(), Date.now() + 120_000).run();
    await setAppPolicy(env.DB, client, false, 2);
    expect((await env.DB.prepare('SELECT id,status FROM authorization_request ORDER BY id').all()).results).toEqual([
      { id: 'anonymous', status: 'canceled' }, { id: 'high', status: 'pending' }, { id: 'low', status: 'canceled' }, { id: 'unknown', status: 'canceled' },
    ]);
    expect((await env.DB.prepare('SELECT code_id,state FROM grant_ledger ORDER BY code_id').all()).results).toEqual([
      { code_id: 'already-issued', state: 'issued' }, { code_id: 'high', state: 'pending' }, { code_id: 'low', state: 'canceled' }, { code_id: 'unknown', state: 'canceled' },
    ]);
    await setAppPolicy(env.DB, client, true);
    expect(await env.DB.prepare('SELECT lite_only,min_trust_level FROM app_settings WHERE client_id=?').bind(client).first()).toMatchObject({ lite_only: 1, min_trust_level: 2 });
    await setAppPolicy(env.DB, client, false, 0);
    expect(await env.DB.prepare("SELECT status FROM authorization_request WHERE id='low'").first()).toMatchObject({ status: 'canceled' });
    expect(await env.DB.prepare("SELECT state FROM grant_ledger WHERE code_id='low'").first()).toMatchObject({ state: 'canceled' });
    expect((await env.DB.prepare("SELECT actor_username,actor_linuxdo_id,trust_level FROM audit WHERE request_id='low' AND action='authorization.canceled'").all()).results).toEqual([{ actor_username: 'alice', actor_linuxdo_id: 123, trust_level: 1 }]);
  });

  it.each([-1, 5, 1.5, Number.NaN])('rejects invalid minimum %s without changing policy', async (minimum) => {
    await fixture();
    await expect(setAppPolicy(env.DB, client, true, minimum)).rejects.toMatchObject({ code: 'invalid_trust_level' });
    expect(await env.DB.prepare('SELECT lite_only,min_trust_level FROM app_settings').first()).toMatchObject({ lite_only: 0, min_trust_level: 0 });
  });
});
