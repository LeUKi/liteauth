import { env } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';
import { makeSignature } from 'better-auth/crypto';
import { audit, authorizationOutcomeStatement, LOG_RETENTION_MS, queryAudit } from '../src/audit';
import { cleanup, cleanupHistory } from '../src/cleanup';
import { app } from '../src/index';
import { connectOutcomeStatement } from '../src/connect-audit';

async function fixtures() {
  const now = Date.now();
  for (const [id, admin, linuxdoId] of [['owner', 0, 123], ['other', 0, 456], ['admin', 1, 900001]] as const) {
    await env.DB.batch([
      env.DB.prepare('INSERT INTO user (id,name,email,email_verified,created_at,updated_at,linuxdo_id,username,is_admin) VALUES (?,?,?,0,?,?,?,?,?)')
        .bind(id, id, `${id}@example.test`, now, now, linuxdoId, id, admin),
      env.DB.prepare('INSERT INTO auth_event (id,user_id,login_method,upstream_client_id,profile,trust_level,created_at) VALUES (?,?,?,?,?,?,?)')
        .bind(`event-${id}`, id, 'lite_self_app', `upstream-${id}`, JSON.stringify({ id: linuxdoId, username: id, name: id, trust_level: 2 }), 2, now),
      env.DB.prepare('INSERT INTO session (id,token,user_id,expires_at,created_at,updated_at,auth_event_id) VALUES (?,?,?,?,?,?,?)')
        .bind(`session-${id}`, `token-${id}`, id, now + 3600_000, now, now, `event-${id}`),
    ]);
  }
  for (const id of ['owner', 'other']) {
    await env.DB.batch([
      env.DB.prepare('INSERT INTO oauth_client (id,client_id,user_id,name,redirect_uris,disabled) VALUES (?,?,?,?,?,0)')
        .bind(`app-${id}`, `client-${id}`, id, `${id} application`, '["https://example.test/callback"]'),
      env.DB.prepare('INSERT INTO app_settings (client_id) VALUES (?)').bind(`client-${id}`),
    ]);
  }
}
async function cookie(user: string) {
  const token = `token-${user}`;
  return `liteauth.session=${encodeURIComponent(`${token}.${await makeSignature(token, env.BETTER_AUTH_SECRET)}`)}`;
}
async function request(id: string, client = 'owner', actor: string | null = 'owner', expires = Date.now() + 600_000) {
  await env.DB.prepare('INSERT INTO authorization_request (id,client_id,signed_query,browser_hash,auth_event_id,stage,status,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?)')
    .bind(id, `client-${client}`, '', 'browser-fixture', actor ? `event-${actor}` : null, 'consent', 'pending', Date.now(), expires).run();
}

describe('traceable seven-day audit and app authorization history', () => {
  it('keeps the intended account separate from the verified callback identity after rename and transaction deletion', async () => {
    await fixtures();
    const now = Date.now();
    await env.DB.prepare(`INSERT INTO connect_transaction (id,state_hash,browser_hash,method,client_id,expected_user_id,expected_username,candidate,status,created_at,expires_at)
      VALUES ('mismatch','state','browser','lite_self_app','connect-owner','owner','owner',1,'consumed',?,?)`).bind(now, now + 600_000).run();
    await env.DB.batch([
      connectOutcomeStatement(env.DB, "t.id='mismatch' AND t.status='consumed'", [], 'failed', 'identity_mismatch', { id: 456, username: 'other', name: 'Other', trust_level: 2 }),
      env.DB.prepare("UPDATE connect_transaction SET status='canceled' WHERE id='mismatch'"),
    ]);
    await env.DB.batch([
      env.DB.prepare("UPDATE user SET username='renamed' WHERE id='other'"),
      env.DB.prepare("DELETE FROM connect_transaction WHERE id='mismatch'"),
    ]);
    expect((await queryAudit(env.DB, {})).entries[0]).toMatchObject({
      action: 'connect.verification', subject_user_id: 'owner', subject_linuxdo_id: 123, subject_username: 'owner',
      actor_id: 'other', actor_linuxdo_id: 456, actor_username: 'other', identity_confirmed: true,
      upstream_client_id: 'connect-owner', verification_purpose: 'credential_validation', reason: 'identity_mismatch',
    });
  });

  it('expires Connect attempts once and never uses a submitted username as verified identity', async () => {
    await fixtures(); const now = Date.now();
    for (const [id, expected] of [['unknown-connect', null], ['known-connect', 'owner']] as const) {
      await env.DB.prepare(`INSERT INTO connect_transaction (id,state_hash,browser_hash,method,client_id,expected_user_id,expected_username,candidate,status,created_at,expires_at)
        VALUES (?,?,?,'lite_self_app',?,?,'owner',1,'pending',?,?)`).bind(id, id, 'browser', id, expected, now - 700_000, now - 1).run();
    }
    await cleanup(env); await cleanup(env);
    const page = await queryAudit(env.DB, {});
    expect(page.entries).toHaveLength(2);
    expect(page.entries.find((e) => e.connect_transaction_id === 'unknown-connect')).toMatchObject({ subject_user_id: null, actor_id: null, actor_username: null, identity_confirmed: false, result: 'expired' });
    expect(page.entries.find((e) => e.connect_transaction_id === 'known-connect')).toMatchObject({ subject_user_id: 'owner', subject_linuxdo_id: 123, actor_id: null, actor_username: null, identity_confirmed: false, result: 'expired' });
  });

  it('snapshots actor/target, allowlists setting changes, and survives names changing', async () => {
    await fixtures();
    await audit(env.DB, 'app.updated', 'owner', 'app-owner', { changes: {
      min_trust_level: { before: 0, after: 2 }, client_secret: { before: 'must-not-store', after: 'also-private' },
    } });
    await env.DB.batch([
      env.DB.prepare("UPDATE user SET username='renamed' WHERE id='owner'"),
      env.DB.prepare("UPDATE oauth_client SET name='new name' WHERE id='app-owner'"),
    ]);
    const page = await queryAudit(env.DB, {});
    expect(page.entries[0]).toMatchObject({ actor_username: 'owner', actor_linuxdo_id: 123, target_type: 'app', target_name: 'owner application', client_id: 'client-owner', changes: { min_trust_level: { before: 0, after: 2 } } });
    expect(JSON.stringify(page)).not.toContain('must-not-store');
    expect(page.entries[0].changes).not.toHaveProperty('client_secret');
  });

  it('isolates owner history, exposes all users to admin, and gives stable filtered pagination', async () => {
    await fixtures();
    for (let i = 0; i < 3; i++) {
      await request(`req-${i}`);
      await authorizationOutcomeStatement(env.DB, 'request', 'r.id = ?', [`req-${i}`], i === 0 ? 'denied' : 'success', i === 0 ? 'user_denied' : null).run();
    }
    await request('other-request', 'other', 'other');
    await authorizationOutcomeStatement(env.DB, 'request', 'r.id = ?', ['other-request'], 'success').run();
    await audit(env.DB, 'credential.deleted', 'other', 'other');
    const url = '/api/apps/app-owner/login-records';
    expect((await app.request(url, { headers: { Cookie: await cookie('other') } }, env)).status).toBe(404);
    const ownerResponse = await app.request(`${url}?limit=1`, { headers: { Cookie: await cookie('owner') } }, env);
    expect(ownerResponse.status).toBe(200);
    const first = await ownerResponse.json() as Awaited<ReturnType<typeof queryAudit>>;
    expect(first.entries).toHaveLength(1); expect(first.next_cursor).toBeTruthy();
    const next = await queryAudit(env.DB, { cursor: first.next_cursor!, limit: 100 }, 'client-owner');
    expect(next.entries).toHaveLength(2);
    expect(new Set([...first.entries, ...next.entries].map((e) => e.id)).size).toBe(3);
    const filtered = await app.request(`${url}?result=denied&user=123`, { headers: { Cookie: await cookie('owner') } }, env);
    expect((await filtered.json() as { entries: unknown[] }).entries).toHaveLength(1);
    expect((await app.request('/api/admin/audit', { headers: { Cookie: await cookie('owner') } }, env)).status).toBe(403);
    const admin = await app.request('/api/admin/audit', { headers: { Cookie: await cookie('admin') } }, env);
    expect((await admin.json() as { entries: unknown[] }).entries).toHaveLength(5);
    expect((await app.request(`${url}?cursor=invalid`, { headers: { Cookie: await cookie('owner') } }, env)).status).toBe(400);
    expect((await queryAudit(env.DB, { user: '%' })).entries).toHaveLength(0);
  });

  it('deduplicates terminal outcomes and never invents an actor for unverified login', async () => {
    await fixtures(); await request('unknown', 'owner', null, Date.now() - 1);
    await cleanup(env); await cleanup(env);
    const history = await queryAudit(env.DB, {}, 'client-owner');
    expect(history.entries).toHaveLength(1);
    expect(history.entries[0]).toMatchObject({ result: 'expired', actor_type: 'unknown', actor_id: null, actor_username: null, request_id: 'unknown' });
  });

  it('purges seven-day records daily but keeps live authentication and unique reservations', async () => {
    await fixtures();
    const old = Date.now() - LOG_RETENTION_MS - 1000;
    await audit(env.DB, 'account.login', 'owner', 'owner');
    await env.DB.prepare('UPDATE audit SET created_at = ?').bind(old).run();
    await audit(env.DB, 'account.login', 'other', 'other');
    await env.DB.prepare('UPDATE auth_event SET created_at = ?').bind(old).run();
    await env.DB.prepare("INSERT INTO upstream_credential (client_id,kind,status,created_at,updated_at) VALUES ('reserved','self','revoked',?,?)").bind(old, old).run();
    await cleanup(env);
    expect((await env.DB.prepare('SELECT id FROM audit').all()).results).toHaveLength(2);
    expect((await queryAudit(env.DB, {})).entries).toHaveLength(1);
    await cleanupHistory(env); await cleanupHistory(env);
    expect((await env.DB.prepare('SELECT id FROM audit').all()).results).toHaveLength(1);
    expect((await env.DB.prepare('SELECT id FROM auth_event').all()).results).toHaveLength(3);
    expect(await env.DB.prepare("SELECT client_id FROM upstream_credential WHERE client_id='reserved'").first()).toBeTruthy();
    await env.DB.prepare("DELETE FROM session WHERE user_id='other'").run();
    await cleanupHistory(env);
    expect(await env.DB.prepare("SELECT id FROM auth_event WHERE id='event-other'").first()).toBeNull();
    expect(await env.DB.prepare("SELECT id FROM auth_event WHERE id='event-owner'").first()).toBeTruthy();
  });

  it('keeps old authentication evidence while an access token still refers to it', async () => {
    await fixtures();
    const old = Date.now() - LOG_RETENTION_MS - 1000;
    await env.DB.prepare("UPDATE auth_event SET created_at=? WHERE id='event-owner'").bind(old).run();
    await env.DB.prepare("DELETE FROM session WHERE user_id='owner'").run();
    await env.DB.prepare('INSERT INTO oauth_access_token (id,token,client_id,user_id,reference_id,expires_at,created_at,scopes) VALUES (?,?,?,?,?,?,?,?)')
      .bind('token-active', 'hashed-token', 'client-owner', 'owner', 'event-owner', Date.now() + 3600_000, Date.now(), '["profile"]').run();
    await cleanupHistory(env);
    expect(await env.DB.prepare("SELECT id FROM auth_event WHERE id='event-owner'").first()).toBeTruthy();
  });
});
