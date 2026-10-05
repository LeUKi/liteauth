import { env } from 'cloudflare:test';
import { makeSignature } from 'better-auth/crypto';
import { describe, expect, it } from 'vitest';
import type { ConnectRecordsPage, AdminUsersPage } from '@liteauth/contracts';
import { getAdminUser, listConnectRecords, listUserApps, listUsers, parseAdminConnectFilters, parseAdminUserFilters } from '../src/admin';
import { LOG_RETENTION_MS } from '../src/audit';
import { app } from '../src/index';

async function fixtures() {
  const now = Date.now();
  for (const [id, username, nativeId, admin] of [
    ['admin', 'admin', 900001, 1], ['user-a', 'Alpha', 1001, 0], ['user-b', 'Beta', 1002, 0],
  ] as const) {
    await env.DB.batch([
      env.DB.prepare(`INSERT INTO user (id,name,email,email_verified,created_at,updated_at,linuxdo_id,username,is_admin)
        VALUES (?,?,?,0,?,?,?,?,?)`).bind(id, username, `${id}@identity.invalid`, now, now, nativeId, username, admin),
      env.DB.prepare(`INSERT INTO auth_event (id,user_id,login_method,upstream_client_id,profile,trust_level,created_at)
        VALUES (?,?,?,?,?,?,?)`).bind(`event-${id}`, id, 'lite_self_app', `upstream-${id}`,
        JSON.stringify({ id: nativeId, username, name: username, trust_level: 2 }), 2, now),
      env.DB.prepare(`INSERT INTO session (id,token,user_id,expires_at,created_at,updated_at,auth_event_id)
        VALUES (?,?,?,?,?,?,?)`).bind(`session-${id}`, `token-${id}`, id, now + 3600_000, now, now, `event-${id}`),
    ]);
  }
  await env.DB.prepare(`UPDATE user SET last_authenticated_at=?,last_login_method='lite_self_app',last_trust_level=2 WHERE id='user-a'`)
    .bind(now).run();
  await env.DB.batch([
    env.DB.prepare(`INSERT INTO upstream_credential (client_id,owner_user_id,kind,ciphertext,status,created_at,updated_at)
      VALUES ('active-a','user-a','self','private-connect-secret','active',?,?)`).bind(now, now),
    env.DB.prepare(`INSERT INTO upstream_credential (client_id,owner_user_id,kind,ciphertext,status,created_at,updated_at)
      VALUES ('old-a','user-a','self',NULL,'revoked',?,?)`).bind(now - 1000, now - 1000),
    env.DB.prepare(`INSERT INTO upstream_credential (client_id,owner_user_id,kind,status,created_at,updated_at)
      VALUES ('platform-reserved',NULL,'platform','active',?,?)`).bind(now, now),
  ]);
  return now;
}

async function cookie(userId: string) {
  const token = `token-${userId}`;
  return `liteauth.session=${encodeURIComponent(`${token}.${await makeSignature(token, env.BETTER_AUTH_SECRET)}`)}`;
}

async function ownedApp(id: string, ownerId = 'user-a', options: { createdAt?: number; deleted?: boolean; public?: boolean; disabled?: boolean } = {}) {
  await env.DB.batch([
    env.DB.prepare(`INSERT INTO oauth_client
      (id,client_id,user_id,name,redirect_uris,token_endpoint_auth_method,require_pkce,disabled,created_at,client_secret,secret_ciphertext)
      VALUES (?,?,?,?,?,?,1,?,?,?,?)`).bind(id, `client-${id}`, ownerId, `App ${id}`, '["https://rp.example/callback"]',
      options.public ? 'none' : 'client_secret_post', Number(options.disabled ?? false), options.createdAt ?? Date.now(),
      options.public ? null : 'private-native-hash', options.public ? null : 'private-downstream-ciphertext'),
    env.DB.prepare('INSERT INTO app_settings (client_id,min_trust_level,deleted_at) VALUES (?,3,?)')
      .bind(`client-${id}`, options.deleted ? Date.now() : null),
  ]);
}

async function verification(id: string, options: {
  actor?: string | null; subject?: string | null; actorUsername?: string | null; subjectUsername?: string | null;
  upstream?: string; createdAt?: number; result?: 'success' | 'failed' | 'canceled'; identityConfirmed?: boolean;
  action?: string; eventKey?: string | null;
} = {}) {
  const actor = options.actor === undefined ? 'user-a' : options.actor;
  const subject = options.subject === undefined ? 'user-a' : options.subject;
  await env.DB.prepare(`INSERT INTO audit
    (id,action,actor_id,actor_type,actor_linuxdo_id,actor_username,actor_name,target_id,target_type,created_at,
     subject_user_id,subject_linuxdo_id,subject_username,upstream_client_id,connect_transaction_id,
     identity_confirmed,verification_purpose,result,reason,login_method,trust_level,event_key)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .bind(id, options.action ?? 'connect.verification', actor, actor ? 'user' : 'unknown', actor === 'user-a' ? 1001 : actor === 'user-b' ? 1002 : null,
      options.actorUsername === undefined ? actor === 'user-a' ? 'Alpha' : actor === 'user-b' ? 'Beta' : null : options.actorUsername,
      actor ? `Display ${actor}` : null, subject, 'user', options.createdAt ?? Date.now(), subject,
      subject === 'user-a' ? 1001 : subject === 'user-b' ? 1002 : null, options.subjectUsername ?? null,
      options.upstream ?? 'active-a', `tx-${id}`, Number(options.identityConfirmed ?? Boolean(actor)), 'credential_validation',
      options.result ?? 'success', options.result === 'failed' ? 'identity_mismatch' : null,
      actor ? 'lite_self_app' : null, actor ? 2 : null, options.eventKey === undefined ? `connect:${id}` : options.eventKey).run();
}

describe('administrator account queries', () => {
  it('requires an enabled administrator on every query before inspecting target users or filters', async () => {
    await fixtures();
    for (const actor of ['user-a', 'missing']) {
      for (const query of [
        () => listUsers(env, actor, { limit: 0 }), () => getAdminUser(env, actor, 'user-b'),
        () => listUserApps(env, actor, 'user-b'), () => listConnectRecords(env, actor, 'user-b'),
      ]) await expect(query()).rejects.toMatchObject({ status: 403, code: 'admin_required' });
    }
    await env.DB.prepare("UPDATE user SET disabled=1 WHERE id='admin'").run();
    for (const query of [
      () => listUsers(env, 'admin'), () => getAdminUser(env, 'admin', 'user-a'),
      () => listUserApps(env, 'admin', 'user-a'), () => listConnectRecords(env, 'admin', 'user-a'),
    ]) await expect(query()).rejects.toMatchObject({ status: 403, code: 'admin_required' });
  });

  it('searches current names, stable IDs and owned Connect IDs without treating wildcards as a query', async () => {
    await fixtures();
    for (const q of ['alpha', '@Alpha', '1001', 'user-a', 'active-a', 'old-a']) {
      const page = await listUsers(env, 'admin', { q });
      expect(page.users.map((user) => user.id), q).toEqual(['user-a']);
      expect(page.users[0].connect_client_id).toBe('active-a');
    }
    for (const q of ['%', '_', "' OR 1=1 --", 'platform-reserved']) {
      expect((await listUsers(env, 'admin', { q })).users, q).toHaveLength(0);
    }
    await env.DB.prepare("UPDATE user SET disabled=1 WHERE id='user-b'").run();
    expect((await listUsers(env, 'admin', { disabled: true })).users.map((user) => user.id)).toEqual(['user-b']);
    expect((await listUsers(env, 'admin', { disabled: false })).users.every((user) => !user.disabled)).toBe(true);
    expect(parseAdminUserFilters({ disabled: 'false', limit: '25' })).toMatchObject({ disabled: false, limit: 25 });
  });

  it('paginates tied creation times without duplicates and rejects invalid controls', async () => {
    await fixtures();
    const first = await listUsers(env, 'admin', { limit: 1 });
    expect(first.users[0].id).toBe('user-b');
    expect(first.next_cursor).toBeTruthy();
    const second = await listUsers(env, 'admin', { limit: 1, cursor: first.next_cursor! });
    expect(second.users[0].id).toBe('user-a');
    const third = await listUsers(env, 'admin', { limit: 1, cursor: second.next_cursor! });
    expect(third.users[0].id).toBe('admin');
    expect(third.next_cursor).toBeNull();
    for (const input of [{ limit: 0 }, { limit: 101 }, { q: 'x'.repeat(129) }]) {
      await expect(listUsers(env, 'admin', input)).rejects.toMatchObject({ status: 400, code: 'invalid_filters' });
    }
    await expect(listUsers(env, 'admin', { cursor: 'invalid' })).rejects.toMatchObject({ status: 400, code: 'invalid_cursor' });
    await expect(listUsers(env, 'admin', { cursor: btoa(JSON.stringify(['not-time', 'user-a'])) })).rejects.toMatchObject({ status: 400, code: 'invalid_cursor' });
    expect(() => parseAdminUserFilters({ disabled: 'unexpected' })).toThrow();
  });

  it('returns durable latest authentication and credential metadata without recovering missing history or secrets', async () => {
    const now = await fixtures();
    await env.DB.prepare("DELETE FROM auth_event WHERE user_id='user-a'").run();
    const detail = await getAdminUser(env, 'admin', 'user-a');
    expect(detail.user).toMatchObject({ id: 'user-a', last_login_method: 'lite_self_app', last_trust_level: 2,
      last_authenticated_at: new Date(now).toISOString(), connect_client_id: 'active-a' });
    expect(detail.credentials.map((credential) => [credential.client_id, credential.status])).toEqual([['active-a', 'active'], ['old-a', 'revoked']]);
    expect(JSON.stringify(detail)).not.toContain('private-connect-secret');
    expect(detail.user).not.toHaveProperty('email');
    expect((await getAdminUser(env, 'admin', 'user-b')).user).toMatchObject({ connect_client_id: null, last_login_method: null,
      last_trust_level: null, last_authenticated_at: null });
    await expect(getAdminUser(env, 'admin', 'missing')).rejects.toMatchObject({ status: 404, code: 'user_not_found' });
  });

  it('lists only the selected user applications with stable paging and no secret fields', async () => {
    const now = await fixtures();
    await ownedApp('a1', 'user-a', { createdAt: now });
    await ownedApp('a2', 'user-a', { createdAt: now, public: true, disabled: true });
    await ownedApp('deleted', 'user-a', { deleted: true });
    await ownedApp('other', 'user-b');
    const first = await listUserApps(env, 'admin', 'user-a', { limit: 1 });
    expect(first.apps[0]).toMatchObject({ id: 'a2', client_type: 'public', disabled: true, min_trust_level: 3 });
    const next = await listUserApps(env, 'admin', 'user-a', { cursor: first.next_cursor!, limit: 1 });
    expect(next.apps[0]).toMatchObject({ id: 'a1', client_type: 'confidential' });
    expect(next.next_cursor).toBeNull();
    expect((await listUserApps(env, 'admin', 'user-b')).apps.map((application) => application.id)).toEqual(['other']);
    expect(JSON.stringify([first, next])).not.toContain('private-native-hash');
    expect(JSON.stringify([first, next])).not.toContain('private-downstream-ciphertext');
    expect(first.apps[0]).not.toHaveProperty('client_secret');
    await expect(listUserApps(env, 'admin', 'missing')).rejects.toMatchObject({ status: 404, code: 'user_not_found' });
  });
});

describe('administrator Connect verification records', () => {
  it('relates trusted subject and actual actor IDs while keeping mismatched identities and unknown snapshots distinct', async () => {
    await fixtures();
    await verification('success', { subjectUsername: 'previous-name' });
    await verification('mismatch', { actor: 'user-b', subject: 'user-a', subjectUsername: 'previous-name', result: 'failed', identityConfirmed: true });
    await verification('unknown-but-associated', { actor: null, subject: 'user-a', identityConfirmed: false, result: 'canceled' });
    await verification('untrusted-name', { actor: null, subject: null, subjectUsername: 'Alpha', identityConfirmed: false, result: 'failed' });
    await verification('other', { actor: 'user-b', subject: 'user-b' });
    await verification('non-connect', { action: 'app.updated' });
    await env.DB.prepare("UPDATE user SET username='renamed' WHERE id='user-a'").run();
    const records = await listConnectRecords(env, 'admin', 'user-a');
    expect(new Set(records.entries.map((entry) => entry.id))).toEqual(new Set(['success', 'mismatch', 'unknown-but-associated']));
    expect(records.entries.find((entry) => entry.id === 'mismatch')).toMatchObject({ actor_id: 'user-b', actor_username: 'Beta',
      subject_user_id: 'user-a', subject_username: 'previous-name', identity_confirmed: true, result: 'failed', reason: 'identity_mismatch' });
    expect(records.entries.find((entry) => entry.id === 'unknown-but-associated')).toMatchObject({ actor_id: null,
      actor_username: null, identity_confirmed: false, subject_user_id: 'user-a' });
    expect(records.entries.find((entry) => entry.id === 'success')?.actor_username).toBe('Alpha');
    const otherRecords = await listConnectRecords(env, 'admin', 'user-b');
    expect(new Set(otherRecords.entries.map((entry) => entry.id))).toEqual(new Set(['mismatch', 'other']));
  });

  it('retains ID-linked legacy facts without inventing fields or including new duplicate business audits', async () => {
    await fixtures();
    await verification('new', { eventKey: 'connect:new' });
    await env.DB.prepare(`INSERT INTO audit (id,action,actor_id,created_at,result)
      VALUES ('old-login','account.login','user-a',?,'success')`).bind(Date.now()).run();
    await env.DB.prepare(`INSERT INTO audit (id,action,actor_id,created_at,event_key)
      VALUES ('new-login-duplicate','account.login','user-a',?,'business:new')`).bind(Date.now()).run();
    await env.DB.prepare(`INSERT INTO audit (id,action,actor_id,subject_username,created_at,result)
      VALUES ('name-only','account.login_failed',NULL,'Alpha',?,'failed')`).bind(Date.now()).run();
    const records = await listConnectRecords(env, 'admin', 'user-a');
    expect(new Set(records.entries.map((entry) => entry.id))).toEqual(new Set(['new', 'old-login']));
    expect(records.entries.find((entry) => entry.id === 'old-login')).toMatchObject({ actor_id: 'user-a', actor_username: null,
      upstream_client_id: null, subject_user_id: null, verification_purpose: null, identity_confirmed: false });
  });

  it('filters and pages seven-day records without exposing older or unrelated verification data', async () => {
    const now = await fixtures();
    for (const id of ['r1', 'r2', 'r3']) await verification(id, { createdAt: now, upstream: id === 'r3' ? 'old-a' : 'active-a', result: id === 'r2' ? 'failed' : 'success' });
    await verification('too-old', { createdAt: now - LOG_RETENTION_MS - 60_000 });
    await verification('in-window', { createdAt: now - LOG_RETENTION_MS + 60_000 });
    const first = await listConnectRecords(env, 'admin', 'user-a', { limit: 1 });
    expect(first.entries[0].id).toBe('r3');
    const next = await listConnectRecords(env, 'admin', 'user-a', { limit: 100, cursor: first.next_cursor! });
    expect(new Set([...first.entries, ...next.entries].map((entry) => entry.id))).toEqual(new Set(['r1', 'r2', 'r3', 'in-window']));
    expect(next.next_cursor).toBeNull();
    expect((await listConnectRecords(env, 'admin', 'user-a', { result: 'failed', upstream_client_id: 'active-a' })).entries.map((entry) => entry.id)).toEqual(['r2']);
    expect((await listConnectRecords(env, 'admin', 'user-a', { upstream_client_id: "' OR 1=1 --" })).entries).toHaveLength(0);
    const range = { from: new Date(now - 1000).toISOString(), to: new Date(now + 1000).toISOString() };
    expect((await listConnectRecords(env, 'admin', 'user-a', range)).entries).toHaveLength(3);
    expect(parseAdminConnectFilters({ ...range, limit: '25' }).limit).toBe(25);
    await expect(listConnectRecords(env, 'admin', 'user-a', { from: range.to, to: range.from })).rejects.toMatchObject({ status: 400, code: 'invalid_filters' });
    await expect(listConnectRecords(env, 'admin', 'user-a', { cursor: 'invalid' })).rejects.toMatchObject({ status: 400, code: 'invalid_cursor' });
    await expect(listConnectRecords(env, 'admin', 'missing')).rejects.toMatchObject({ status: 404, code: 'user_not_found' });
  });

  it('enforces actual session permissions and no-store on the Hono administrator endpoints', async () => {
    await fixtures();
    const paths = ['/api/admin/users', '/api/admin/users/user-a', '/api/admin/users/user-a/apps', '/api/admin/users/user-a/connect-records'];
    for (const path of paths) {
      expect((await app.request(path, {}, env)).status).toBe(401);
      expect((await app.request(path, { headers: { Cookie: await cookie('user-a') } }, env)).status).toBe(403);
      const allowed = await app.request(path, { headers: { Cookie: await cookie('admin') } }, env);
      expect(allowed.status).toBe(200);
      expect(allowed.headers.get('Cache-Control')).toBe('no-store');
    }
    const search = await app.request('/api/admin/users?q=1001', { headers: { Cookie: await cookie('admin') } }, env);
    expect((await search.json() as AdminUsersPage).users.map((user) => user.id)).toEqual(['user-a']);
    await verification('match', { result: 'failed' });
    const filtered = await app.request('/api/admin/users/user-a/connect-records?result=failed&upstream_client_id=active-a', { headers: { Cookie: await cookie('admin') } }, env);
    expect((await filtered.json() as ConnectRecordsPage).entries.map((entry) => entry.id)).toEqual(['match']);
    await env.DB.prepare("UPDATE user SET disabled=1 WHERE id='admin'").run();
    for (const path of paths) expect((await app.request(path, { headers: { Cookie: await cookie('admin') } }, env)).status).toBe(401);
  });
});
