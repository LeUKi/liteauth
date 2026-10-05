/**
 * Isolated, synthetic proof of the deployed D1 adapter's final issuance commit.
 * Run only through `wrangler dev --ip 127.0.0.1` with an ephemeral config using
 * a remote D1 binding (or an isolated remote preview),
 * no domain routes, an explicit staging/proof D1 binding, and a protected random
 * REMOTE_D1_PROOF_TOKEN. This is not evidence of real upstream authentication.
 */
import { APIError } from 'better-auth';
import { createAuth, eventClaims } from '../src/auth';
import { setAppPolicy } from '../src/db/policy';
import type { Env } from '../src/env';

interface ProofEnv extends Env {
  REMOTE_D1_PROOF_ENABLED: string;
  REMOTE_D1_PROOF_TOKEN: string;
}
class ProofFailure extends Error {
  constructor(readonly code: string) { super(code); }
}
function ensure(condition: unknown, code: string): asserts condition {
  if (!condition) throw new ProofFailure(code);
}
function invalidGrant(error: unknown) {
  return error instanceof APIError && error.body?.error === 'invalid_grant';
}
type Fixture = {
  userId: string; sessionId: string; eventId: string; clientId: string;
  codeId: string; verificationId: string; nativeId: number; env: Env;
  context: Awaited<ReturnType<typeof createAuth>['$context']>;
};
type ProofResult = { scenario: string; passed: true; ledger_state: string; token_count: number; cleanup_verified: boolean };

async function cleanup(f: Fixture) {
  const db = f.env.DB;
  await db.batch([
    db.prepare('DELETE FROM oauth_access_token WHERE client_id = ? OR user_id = ?').bind(f.clientId, f.userId),
    db.prepare('DELETE FROM oauth_refresh_token WHERE client_id = ? OR user_id = ?').bind(f.clientId, f.userId),
    db.prepare('DELETE FROM oauth_consent WHERE client_id = ? OR user_id = ?').bind(f.clientId, f.userId),
    db.prepare('DELETE FROM verification WHERE id = ? OR identifier = ?').bind(f.verificationId, f.codeId),
    db.prepare('DELETE FROM grant_ledger WHERE code_id = ? OR client_id = ?').bind(f.codeId, f.clientId),
    db.prepare('DELETE FROM audit WHERE actor_id = ? OR target_id = ?').bind(f.userId, f.clientId),
    db.prepare('DELETE FROM connect_transaction WHERE id = ?').bind(f.codeId),
    db.prepare('DELETE FROM mutation_guard WHERE id = ?').bind(f.codeId),
    db.prepare('DELETE FROM app_settings WHERE client_id = ?').bind(f.clientId),
    db.prepare('DELETE FROM oauth_client WHERE client_id = ?').bind(f.clientId),
    db.prepare('DELETE FROM session WHERE user_id = ?').bind(f.userId),
    db.prepare('DELETE FROM auth_event WHERE user_id = ?').bind(f.userId),
    db.prepare('DELETE FROM user WHERE id = ?').bind(f.userId),
  ]);
  const residual = await db.prepare(`SELECT
    (SELECT count(*) FROM user WHERE id = ?) +
    (SELECT count(*) FROM session WHERE user_id = ?) +
    (SELECT count(*) FROM auth_event WHERE user_id = ?) +
    (SELECT count(*) FROM oauth_client WHERE client_id = ?) +
    (SELECT count(*) FROM app_settings WHERE client_id = ?) +
    (SELECT count(*) FROM oauth_access_token WHERE client_id = ? OR user_id = ?) +
    (SELECT count(*) FROM oauth_refresh_token WHERE client_id = ? OR user_id = ?) +
    (SELECT count(*) FROM oauth_consent WHERE client_id = ? OR user_id = ?) +
    (SELECT count(*) FROM verification WHERE id = ? OR identifier = ?) +
    (SELECT count(*) FROM grant_ledger WHERE code_id = ? OR client_id = ?) +
    (SELECT count(*) FROM connect_transaction WHERE id = ?) +
    (SELECT count(*) FROM mutation_guard WHERE id = ?) +
    (SELECT count(*) FROM audit WHERE actor_id = ? OR target_id = ?) AS count`)
    .bind(f.userId, f.userId, f.userId, f.clientId, f.clientId, f.clientId, f.userId,
      f.clientId, f.userId, f.clientId, f.userId, f.verificationId, f.codeId,
      f.codeId, f.clientId, f.codeId, f.codeId, f.userId, f.clientId).first<{ count: number }>();
  ensure(residual?.count === 0, 'scoped_cleanup_incomplete');
}

async function setup(f: Fixture) {
  const now = Date.now();
  await f.env.DB.batch([
    f.env.DB.prepare(`INSERT INTO user (id, name, email, email_verified, created_at, updated_at, linuxdo_id, username)
      VALUES (?, 'Synthetic D1 proof', ?, 0, ?, ?, ?, ?)`)
      .bind(f.userId, `${f.userId}@d1-proof.liteauth.invalid`, now, now, f.nativeId, f.userId),
    f.env.DB.prepare(`INSERT INTO auth_event (id, user_id, login_method, upstream_client_id, profile, trust_level, created_at)
      VALUES (?, ?, 'official_connect', ?, ?, 1, ?)`)
      .bind(f.eventId, f.userId, `${f.clientId}-synthetic-upstream`, JSON.stringify({ id: f.nativeId, username: f.userId, name: 'Synthetic D1 proof', trust_level: 1 }), now),
    f.env.DB.prepare(`INSERT INTO session (id, token, user_id, expires_at, created_at, updated_at, auth_event_id)
      VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .bind(f.sessionId, crypto.randomUUID(), f.userId, now + 3600_000, now, now, f.eventId),
    f.env.DB.prepare(`INSERT INTO oauth_client (id, client_id, disabled, user_id, redirect_uris, scopes,
      token_endpoint_auth_method, application_type, grant_types, response_types, require_pkce, created_at, updated_at)
      VALUES (?, ?, 0, ?, ?, ?, 'none', 'native', ?, ?, 1, ?, ?)`)
      .bind(f.clientId, f.clientId, f.userId, JSON.stringify(['http://127.0.0.1:9445/callback']),
        JSON.stringify(['profile']), JSON.stringify(['authorization_code']), JSON.stringify(['code']), now, now),
    f.env.DB.prepare('INSERT INTO app_settings (client_id, lite_only) VALUES (?, 0)').bind(f.clientId),
  ]);
  // Use the actual decorated adapter to create both the code and grant ledger.
  await f.context.adapter.create({ model: 'verification', forceAllowId: true, data: {
    id: f.verificationId, identifier: f.codeId,
    value: JSON.stringify({ type: 'authorization_code', userId: f.userId, referenceId: f.eventId, query: { client_id: f.clientId } }),
    createdAt: new Date(now), updatedAt: new Date(now), expiresAt: new Date(now + 120_000),
  } });
}
async function consume(f: Fixture) {
  const consumed = await f.context.internalAdapter.consumeVerificationValue(f.codeId);
  ensure(consumed, 'code_not_consumed');
  const row = await f.env.DB.prepare('SELECT count(*) AS count FROM verification WHERE identifier = ?')
    .bind(f.codeId).first<{ count: number }>();
  ensure(row?.count === 0, 'consumed_code_remains');
}
function issue(f: Fixture) {
  // This is the provider's actual transaction callback / final opaque-token write.
  // No fake protocol response is returned, and no token leaves this Worker.
  return f.context.adapter.transaction(adapter => adapter.create({ model: 'oauthAccessToken', data: {
    token: crypto.randomUUID(), clientId: f.clientId, sessionId: f.sessionId,
    userId: f.userId, referenceId: f.eventId, authorizationCodeId: f.codeId,
    scopes: ['profile'], createdAt: new Date(), expiresAt: new Date(Date.now() + 3600_000),
  } }));
}
async function denial(f: Fixture) {
  let denied = false;
  try { await issue(f); } catch (error) { denied = invalidGrant(error); }
  ensure(denied, 'issuance_not_rejected_invalid_grant');
}
async function snapshot(f: Fixture, expected: 'issued' | 'canceled') {
  const ledger = await f.env.DB.prepare('SELECT state, token_id FROM grant_ledger WHERE code_id = ?')
    .bind(f.codeId).first<{ state: string; token_id: string | null }>();
  const tokens = await f.env.DB.prepare('SELECT count(*) AS count FROM oauth_access_token WHERE client_id = ?')
    .bind(f.clientId).first<{ count: number }>();
  ensure(ledger?.state === expected, 'ledger_state_mismatch');
  ensure(tokens?.count === Number(expected === 'issued'), 'token_count_mismatch');
  if (expected === 'issued') {
    const token = await f.env.DB.prepare(`SELECT reference_id, authorization_code_id, revoked FROM oauth_access_token
      WHERE id = ? AND client_id = ?`).bind(ledger.token_id, f.clientId)
      .first<{ reference_id: string; authorization_code_id: string; revoked: number | null }>();
    ensure(token?.reference_id === f.eventId && token.authorization_code_id === f.codeId && token.revoked === null, 'issued_token_changed');
    ensure((await eventClaims(f.env, token.reference_id, f.userId)).login_method === 'official_connect', 'issued_provenance_changed');
    ensure((await eventClaims(f.env, token.reference_id, f.userId)).trust_level === 1, 'issued_level_changed');
  } else ensure(ledger.token_id === null, 'canceled_grant_has_token');
  return { ledger_state: ledger.state, token_count: tokens.count };
}

async function scenario(env: Env, runId: string, label: string, action: (f: Fixture) => Promise<'issued' | 'canceled'>): Promise<ProofResult> {
  const prefix = `${runId}-${label}`;
  const f: Fixture = {
    userId: `${prefix}-user`, sessionId: `${prefix}-session`, eventId: `${prefix}-event`,
    clientId: `${prefix}-client`, codeId: `${prefix}-code`, verificationId: `${prefix}-verification`,
    nativeId: -1 - Number.parseInt(crypto.randomUUID().replaceAll('-', '').slice(0, 12), 16),
    env, context: await createAuth(env).$context,
  };
  try {
    await setup(f);
    const expected = await action(f);
    const final = await snapshot(f, expected);
    await denial(f); // An issued or canceled ledger cannot issue another token.
    return { scenario: label, passed: true, ...final, cleanup_verified: true };
  } finally { await cleanup(f); }
}

async function proof(env: ProofEnv) {
  const runId = `d1-proof-${crypto.randomUUID()}`;
  // Isolate the synthetic auth realm and signing secret from real staging sessions.
  const syntheticEnv: Env = { ...env, APP_ORIGIN: 'http://127.0.0.1:9445', BETTER_AUTH_SECRET: crypto.randomUUID() + crypto.randomUUID() };
  const results: ProofResult[] = [];
  results.push(await scenario(syntheticEnv, runId, 'token-issue-first', async f => {
    await consume(f);
    await issue(f);
    await snapshot(f, 'issued');
    await setAppPolicy(env.DB, f.clientId, true);
    await snapshot(f, 'issued');
    await setAppPolicy(env.DB, f.clientId, false);
    return 'issued';
  }));
  results.push(await scenario(syntheticEnv, runId, 'policy-first', async f => {
    await setAppPolicy(env.DB, f.clientId, true);
    await consume(f);
    await denial(f);
    await setAppPolicy(env.DB, f.clientId, false);
    return 'canceled';
  }));
  results.push(await scenario(syntheticEnv, runId, 'consumed-before-toggle-on-off', async f => {
    await consume(f);
    await setAppPolicy(env.DB, f.clientId, true);
    await setAppPolicy(env.DB, f.clientId, false);
    return 'canceled';
  }));
  for (let attempt = 0; attempt < 8; attempt++) {
    results.push(await scenario(syntheticEnv, runId, `concurrent-${attempt + 1}`, async f => {
      await consume(f);
      const operations = attempt % 2 === 0
        ? await Promise.allSettled([issue(f), setAppPolicy(env.DB, f.clientId, true)])
        : (await Promise.allSettled([setAppPolicy(env.DB, f.clientId, true), issue(f)])).reverse();
      ensure(operations[1].status === 'fulfilled', 'policy_update_failed');
      if (operations[0].status === 'fulfilled') return 'issued';
      ensure(invalidGrant(operations[0].reason), 'unexpected_issuance_failure');
      return 'canceled';
    }));
  }
  results.push(await scenario(syntheticEnv, runId, 'credential-revision-ordering', async f => {
    await env.DB.prepare(`INSERT INTO connect_transaction
      (id,state_hash,browser_hash,method,client_id,candidate,status,created_at,expires_at,started_credential_revision)
      SELECT ?,?,?, 'lite_self_app',?,1,'consumed',?,?,revision FROM credential_clock WHERE id=1`)
      .bind(f.codeId, f.codeId, f.codeId, f.clientId, Date.now(), Date.now() + 600_000).run();
    // Exercise the old Worker's epoch-only write; the database trigger must cover it too.
    await env.DB.prepare('UPDATE user SET credential_epoch=credential_epoch+1 WHERE id=?').bind(f.userId).run();
    const row = await env.DB.prepare(`SELECT u.credential_revision AS current_revision,t.started_credential_revision AS started_revision
      FROM user u JOIN connect_transaction t ON t.id=? WHERE u.id=?`).bind(f.codeId, f.userId)
      .first<{ current_revision: number; started_revision: number }>();
    ensure(row && row.current_revision > row.started_revision, 'credential_revision_not_advanced');
    let blocked = false;
    try {
      await env.DB.batch([
        env.DB.prepare("UPDATE user SET username='must-rollback' WHERE id=?").bind(f.userId),
        env.DB.prepare(`INSERT INTO mutation_guard (id,ok) SELECT ?,CASE WHEN u.credential_revision<=t.started_credential_revision THEN 1 ELSE 0 END
          FROM user u JOIN connect_transaction t ON t.id=? WHERE u.id=?`).bind(f.codeId, f.codeId, f.userId),
      ]);
    } catch { blocked = true; }
    ensure(blocked, 'revoked_candidate_not_blocked');
    ensure((await env.DB.prepare('SELECT username FROM user WHERE id=?').bind(f.userId).first<{ username: string }>())?.username === f.userId, 'credential_guard_not_atomic');
    const next = await env.DB.prepare('SELECT revision FROM credential_clock WHERE id=1').first<{ revision: number }>();
    ensure(next && next.revision >= row.current_revision, 'credential_clock_not_monotonic');
    await consume(f); await issue(f);
    return 'issued';
  }));
  results.push(await scenario(syntheticEnv, runId, 'level-token-first', async f => {
    await consume(f); await issue(f); await setAppPolicy(env.DB, f.clientId, false, 2);
    await snapshot(f, 'issued'); await setAppPolicy(env.DB, f.clientId, false, 0);
    return 'issued';
  }));
  results.push(await scenario(syntheticEnv, runId, 'level-policy-first', async f => {
    await setAppPolicy(env.DB, f.clientId, false, 2); await consume(f); await denial(f);
    await setAppPolicy(env.DB, f.clientId, false, 0);
    return 'canceled';
  }));
  results.push(await scenario(syntheticEnv, runId, 'level-consumed-before-raise-lower', async f => {
    await consume(f); await setAppPolicy(env.DB, f.clientId, false, 2); await setAppPolicy(env.DB, f.clientId, false, 0);
    return 'canceled';
  }));
  for (let attempt = 0; attempt < 8; attempt++) {
    results.push(await scenario(syntheticEnv, runId, `level-concurrent-${attempt + 1}`, async f => {
      await consume(f);
      const operations = attempt % 2 === 0
        ? await Promise.allSettled([issue(f), setAppPolicy(env.DB, f.clientId, false, 2)])
        : (await Promise.allSettled([setAppPolicy(env.DB, f.clientId, false, 2), issue(f)])).reverse();
      ensure(operations[1].status === 'fulfilled', 'level_update_failed');
      if (operations[0].status === 'fulfilled') return 'issued';
      ensure(invalidGrant(operations[0].reason), 'unexpected_level_issuance_failure');
      return 'canceled';
    }));
  }
  return { passed: true, synthetic: true, upstream_authentication_verified: false,
    boundary: 'actual_d1_decorated_adapter_final_commit', checked_at: new Date().toISOString(),
    cleanup_verified: true, results };
}

export default {
  async fetch(request: Request, env: ProofEnv): Promise<Response> {
    const headers = { 'content-type': 'application/json', 'cache-control': 'no-store' };
    if (env.ENVIRONMENT === 'production' || env.REMOTE_D1_PROOF_ENABLED !== 'isolated-synthetic-proof' ||
      typeof env.REMOTE_D1_PROOF_TOKEN !== 'string' || env.REMOTE_D1_PROOF_TOKEN.length < 32 ||
      request.headers.get('Authorization') !== `Bearer ${env.REMOTE_D1_PROOF_TOKEN}`) {
      return new Response(JSON.stringify({ error: 'proof_disabled_or_unauthorized' }), { status: 403, headers });
    }
    if (request.method !== 'POST' || new URL(request.url).pathname !== '/proof') {
      return new Response(JSON.stringify({ error: 'proof_route_unavailable' }), { status: 404, headers });
    }
    try { return new Response(JSON.stringify(await proof(env)), { headers }); }
    catch (error) {
      // D1/provider error messages may contain bound values; never serialize them.
      return new Response(JSON.stringify({ passed: false, synthetic: true,
        error: error instanceof ProofFailure ? error.code : 'proof_operation_failed' }), { status: 500, headers });
    }
  },
};
