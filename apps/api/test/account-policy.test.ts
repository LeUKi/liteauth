import { env } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';
import { officialLockStatements, backfillOfficialLocks } from '../src/account-policy';
import { createAuth, eventClaims } from '../src/auth';

async function user(id = 'owner', stableId = 123) {
  const now = Date.now();
  await env.DB.prepare(`INSERT INTO user (id,name,email,email_verified,created_at,updated_at,linuxdo_id,username)
    VALUES (?, ?, ?, 0, ?, ?, ?, ?)`).bind(id, id, `${id}@example.invalid`, now, now, stableId, id).run();
  return id;
}
async function event(id: string, userId: string, method = 'lite_self_app', stableId = 123, at = Date.now()) {
  await env.DB.prepare(`INSERT INTO auth_event (id,user_id,login_method,upstream_client_id,trust_level,profile,created_at)
    VALUES (?, ?, ?, 'self-client', 2, ?, ?)`).bind(id, userId, method, JSON.stringify({ id: stableId, username: `${userId}-then`, trust_level: 2 }), at).run();
}

describe('persistent official authentication policy', () => {
  it('rolls official proof, account lock and cancellations back together when the authentication commit fails', async () => {
    await user(); const now = Date.now();
    await env.DB.prepare(`INSERT INTO connect_transaction
      (id,state_hash,browser_hash,method,client_id,encrypted_payload,expected_user_id,status,created_at,expires_at)
      VALUES ('waiting','state','browser','lite_self_app','owner-client','encrypted','owner','pending',?,?)`).bind(now, now + 600_000).run();
    await expect(env.DB.batch([
      env.DB.prepare(`INSERT INTO auth_event (id,user_id,login_method,upstream_client_id,trust_level,profile,created_at)
        VALUES ('official-proof','owner','official_connect','platform-client',0,?,?)`).bind(JSON.stringify({ id: 123, username: 'owner', trust_level: 0 }), now),
      ...officialLockStatements(env.DB, 'owner', now),
      env.DB.prepare("INSERT INTO mutation_guard (id,ok) VALUES ('forced-failure',0)"),
    ])).rejects.toThrow();
    expect(await env.DB.prepare("SELECT official_verified_at FROM user WHERE id='owner'").first()).toEqual({ official_verified_at: null });
    expect(await env.DB.prepare("SELECT status,encrypted_payload FROM connect_transaction WHERE id='waiting'").first()).toEqual({ status: 'pending', encrypted_payload: 'encrypted' });
    expect(await env.DB.prepare('SELECT id FROM auth_event').first()).toBeNull();
    expect(await env.DB.prepare('SELECT id FROM audit').first()).toBeNull();
  });

  it('cancels only pending Lite work, preserves issued tokens and binding, and keeps the current official request', async () => {
    await user(); await user('other', 456);
    await event('owner-lite', 'owner'); await event('owner-official', 'owner', 'official_connect'); await event('other-lite', 'other', 'lite_self_app', 456);
    const now = Date.now();
    await env.DB.prepare(`INSERT INTO oauth_client (id,client_id,name,disabled,redirect_uris)
      VALUES ('client-row','rp-client','RP',0,'["https://rp.example/callback"]')`).run();
    await env.DB.prepare("INSERT INTO app_settings (client_id) VALUES ('rp-client')").run();
    await env.DB.prepare(`INSERT INTO upstream_credential (client_id,owner_user_id,kind,ciphertext,status,created_at,updated_at)
      VALUES ('owner-client','owner','self','encrypted','active',?,?)`).bind(now, now).run();
    for (const [id, authEvent] of [['lite-request', 'owner-lite'], ['official-request', 'owner-official'], ['other-request', 'other-lite'], ['bound-request', null]] as const) {
      await env.DB.prepare(`INSERT INTO authorization_request (id,client_id,signed_query,browser_hash,auth_event_id,stage,status,created_at,expires_at)
        VALUES (?,'rp-client','signed','browser',?,'login','pending',?,?)`).bind(id, authEvent, now, now + 600_000).run();
    }
    for (const [id, requestId, owner, clientId] of [
      ['known', 'lite-request', 'owner', 'owner-client'], ['old-on-official', 'official-request', 'owner', 'owner-client'],
      ['bound', 'bound-request', null, 'owner-client'], ['other', 'other-request', 'other', 'other-client'], ['unknown', null, null, 'new-client'],
    ] as const) {
      await env.DB.prepare(`INSERT INTO connect_transaction
        (id,state_hash,browser_hash,request_id,method,client_id,encrypted_payload,expected_user_id,status,created_at,expires_at)
        VALUES (?,?,'browser',?,'lite_self_app',?,'encrypted',?,'pending',?,?)`)
        .bind(id, id, requestId, clientId, owner, now, now + 600_000).run();
    }
    for (const [id, authEvent, state] of [['pending', 'owner-lite', 'pending'], ['issued', 'owner-lite', 'issued'], ['other-code', 'other-lite', 'pending']] as const) {
      await env.DB.prepare(`INSERT INTO grant_ledger (code_id,client_id,auth_event_id,state,created_at,expires_at)
        VALUES (?,'rp-client',?,?,?,?)`).bind(id, authEvent, state, now, now + 120_000).run();
      await env.DB.prepare(`INSERT INTO verification (id,identifier,value,created_at,updated_at,expires_at) VALUES (?,?,'{}',?,?,?)`)
        .bind(id, id, now, now, now + 120_000).run();
    }
    const context = await createAuth(env).$context;
    const session = await context.internalAdapter.createSession('owner', false, { authEventId: 'owner-lite' }, true);
    await env.DB.prepare(`INSERT INTO oauth_access_token (id,token,client_id,session_id,user_id,reference_id,authorization_code_id,scopes,created_at,expires_at)
      VALUES ('issued-token','token','rp-client',?,'owner','owner-lite','issued','["profile"]',?,?)`)
      .bind(session!.id, now, now + 3600_000).run();

    await env.DB.batch(officialLockStatements(env.DB, 'owner', now));
    await env.DB.batch(officialLockStatements(env.DB, 'owner', now + 100));
    expect(await env.DB.prepare("SELECT official_verified_at FROM user WHERE id='owner'").first()).toEqual({ official_verified_at: now });
    expect((await env.DB.prepare('SELECT id,status FROM connect_transaction ORDER BY id').all()).results).toEqual([
      { id: 'bound', status: 'canceled' }, { id: 'known', status: 'canceled' }, { id: 'old-on-official', status: 'canceled' },
      { id: 'other', status: 'pending' }, { id: 'unknown', status: 'pending' },
    ]);
    expect((await env.DB.prepare('SELECT id,status FROM authorization_request ORDER BY id').all()).results).toEqual([
      { id: 'bound-request', status: 'canceled' }, { id: 'lite-request', status: 'canceled' }, { id: 'official-request', status: 'pending' }, { id: 'other-request', status: 'pending' },
    ]);
    expect((await env.DB.prepare('SELECT code_id,state FROM grant_ledger ORDER BY code_id').all()).results).toEqual([
      { code_id: 'issued', state: 'issued' }, { code_id: 'other-code', state: 'pending' }, { code_id: 'pending', state: 'canceled' },
    ]);
    expect(await env.DB.prepare("SELECT id FROM verification WHERE identifier='pending'").first()).toBeNull();
    expect(await env.DB.prepare("SELECT revoked FROM oauth_access_token WHERE id='issued-token'").first()).toEqual({ revoked: null });
    expect(await env.DB.prepare('SELECT id FROM session WHERE id=?').bind(session!.id).first()).toBeTruthy();
    expect(await env.DB.prepare("SELECT status,ciphertext FROM upstream_credential WHERE client_id='owner-client'").first()).toEqual({ status: 'active', ciphertext: 'encrypted' });
    expect(await eventClaims(env, 'owner-lite')).toMatchObject({ login_method: 'lite_self_app', username: 'owner-then' });
    const audits = (await env.DB.prepare('SELECT event_key FROM audit').all<{ event_key: string }>()).results;
    expect(audits).toHaveLength(7); expect(new Set(audits.map(a => a.event_key)).size).toBe(audits.length);
  });

  it('backfills only retained stable-identity success evidence and is safely repeatable', async () => {
    const now = Date.now();
    for (const [id, stableId] of [['event', 1], ['audit', 2], ['snapshot', 3], ['failed', 4], ['name-only', 5], ['mismatch', 6], ['malformed', 7], ['unknown', 8]] as const) await user(id, stableId);
    await event('official-event', 'event', 'official_connect', 1, now - 1000);
    await event('wrong-id', 'mismatch', 'official_connect', 777);
    await event('malformed-event', 'malformed', 'official_connect', 7);
    await env.DB.prepare("UPDATE auth_event SET profile='not-json' WHERE id='malformed-event'").run();
    await env.DB.prepare(`INSERT INTO audit (id,action,actor_id,actor_linuxdo_id,result,login_method,created_at)
      VALUES ('audit-success','account.login','audit',2,'success','official_connect',?)`).bind(now - 2000).run();
    await env.DB.prepare(`INSERT INTO audit (id,action,actor_id,actor_linuxdo_id,result,login_method,created_at)
      VALUES ('audit-failure','account.login_failed','failed',4,'failed','official_connect',?)`).bind(now).run();
    await env.DB.prepare(`INSERT INTO audit (id,action,target_name,result,login_method,created_at)
      VALUES ('name-hint','connect.verification','name-only','success','official_connect',?)`).bind(now).run();
    await env.DB.prepare("UPDATE user SET last_login_method='official_connect',last_authenticated_at=?,last_trust_level=1 WHERE id='snapshot'").bind(now - 3000).run();
    expect(await backfillOfficialLocks(env.DB, 2)).toEqual({ inspected: 2, locked: 2, remaining: 1 });
    expect(await backfillOfficialLocks(env.DB, 2)).toEqual({ inspected: 1, locked: 1, remaining: 0 });
    expect(await backfillOfficialLocks(env.DB)).toEqual({ inspected: 0, locked: 0, remaining: 0 });
    expect((await env.DB.prepare('SELECT id,official_verified_at FROM user WHERE official_verified_at IS NOT NULL ORDER BY id').all()).results).toEqual([
      { id: 'audit', official_verified_at: now - 2000 }, { id: 'event', official_verified_at: now - 1000 }, { id: 'snapshot', official_verified_at: now - 3000 },
    ]);
    expect((await env.DB.prepare("SELECT event_key FROM audit WHERE action='account.official_verified'").all()).results).toHaveLength(3);
  });

  it('also trusts a confirmed successful Connect audit, and retains the earliest evidence without overwriting an existing flag', async () => {
    await user(); const now = Date.now();
    await event('official-later', 'owner', 'official_connect', 123, now - 1000);
    await env.DB.prepare(`INSERT INTO audit (id,action,actor_id,actor_linuxdo_id,subject_user_id,subject_linuxdo_id,identity_confirmed,result,login_method,created_at)
      VALUES ('connect-success','connect.verification','owner',123,'owner',123,1,'success','official_connect',?)`).bind(now - 2000).run();
    expect((await backfillOfficialLocks(env.DB)).locked).toBe(1);
    expect(await env.DB.prepare("SELECT official_verified_at FROM user WHERE id='owner'").first()).toEqual({ official_verified_at: now - 2000 });
    await env.DB.prepare("UPDATE user SET username='renamed',last_login_method='lite_self_app',disabled=1 WHERE id='owner'").run();
    await env.DB.prepare("DELETE FROM audit").run(); await env.DB.prepare("DELETE FROM auth_event").run();
    await env.DB.prepare("UPDATE user SET disabled=0,credential_epoch=credential_epoch+1 WHERE id='owner'").run();
    expect(await env.DB.prepare("SELECT official_verified_at FROM user WHERE id='owner'").first()).toEqual({ official_verified_at: now - 2000 });
    expect((await backfillOfficialLocks(env.DB)).locked).toBe(0);
  });
});
