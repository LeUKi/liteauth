import type { CredentialInput, LiteLoginInput, LoginMethod } from '@liteauth/contracts';
import { APIError } from 'better-auth';
import { setSessionCookie } from 'better-auth/cookies';
import { cookieName, isConfiguredAdmin, TRANSACTION_TTL, type Env } from './env';
import { hash, randomId } from './crypto';
import { invariant } from './errors';
import { appEligibility, getRequest } from './requests';
import { seal, open } from './secrets';
import { audit } from './db/policy';
import { authorizationOutcomeStatement } from './audit';
import { connectOutcomeStatement, type VerifiedConnectIdentity } from './connect-audit';
import { startUpstream, finishUpstream } from './upstream';
import { OFFICIAL_LOGIN_REQUIRED_MESSAGE, officialLockStatements } from './account-policy';

type ExistingUser = { id: string; linuxdo_id: number; username: string; credential_epoch: number; credential_revision?: number; disabled: number; official_verified_at?: number | null };
type CredentialRow = { client_id: string; owner_user_id: string | null; kind: string; ciphertext: string | null; version: number; status: string; updated_at: number };
type Payload = { secret: string; state: string; codeVerifier: string; returnTo: '/apps' | '/credentials' };
type TransactionRow = {
  id: string; client_id: string; browser_hash: string; encrypted_payload: string | null; method: LoginMethod;
  expected_user_id: string | null; expected_linuxdo_id: number | null; expected_username: string | null;
  credential_epoch: number | null; credential_version: number | null; candidate: number; request_id: string | null; status: string; expires_at: number;
  started_credential_revision: number | null;
};
type CallbackContext = Parameters<typeof setSessionCookie>[0];

export async function reservePlatformClient(env: Env) {
  if (!env.CONNECT_CLIENT_ID || env.CONNECT_CLIENT_ID.startsWith('PLACEHOLDER')) return;
  const now = Date.now();
  await env.DB.prepare(`INSERT INTO upstream_credential (client_id, owner_user_id, kind, ciphertext, version, status, created_at, updated_at)
    VALUES (?, NULL, 'platform', NULL, 1, 'active', ?, ?) ON CONFLICT(client_id) DO NOTHING`).bind(env.CONNECT_CLIENT_ID, now, now).run();
  const reservation = await env.DB.prepare('SELECT kind FROM upstream_credential WHERE client_id = ?').bind(env.CONNECT_CLIENT_ID).first<{ kind: string }>();
  invariant(reservation?.kind === 'platform', 503, 'connect_unavailable', '登录暂不可用，请稍后再试');
}

async function userById(env: Env, id: string) {
  return env.DB.prepare('SELECT id, linuxdo_id, username, credential_epoch, credential_revision, disabled, official_verified_at FROM user WHERE id = ?')
    .bind(id).first<ExistingUser>();
}

export async function beginConnect(env: Env, browserToken: string, method: LoginMethod, input: { request?: string } & Partial<LiteLoginInput>, user?: ExistingUser, credentialInput?: CredentialInput) {
  await reservePlatformClient(env);
  if (input.request) {
    const { app } = await getRequest(env, input.request, browserToken);
    invariant(method !== 'official_connect' || !app.lite_only, 403, 'lite_only', '此应用仅支持 Lite 登录');
  }
  let clientId = env.CONNECT_CLIENT_ID;
  let secret = env.CONNECT_CLIENT_SECRET;
  let expectedUser = user;
  let credentialVersion: number | null = null;
  const candidate = Boolean(credentialInput || input.client_id);
  if (method === 'lite_self_app') {
    if (expectedUser && (expectedUser.credential_revision === undefined || expectedUser.official_verified_at === undefined)) expectedUser = await userById(env, expectedUser.id) ?? expectedUser;
    const supplied = credentialInput ?? (input.client_id && input.client_secret ? { client_id: input.client_id, client_secret: input.client_secret } : undefined);
    if (supplied) {
      clientId = supplied.client_id; secret = supplied.client_secret;
      const reserved = await env.DB.prepare('SELECT * FROM upstream_credential WHERE client_id = ?').bind(clientId).first<CredentialRow>();
      invariant(!reserved || (reserved.kind === 'self' && reserved.owner_user_id), 409, 'credential_bound', '该 Connect 应用已被其他账号绑定');
      if (reserved?.owner_user_id) {
        invariant(!expectedUser || expectedUser.id === reserved.owner_user_id, 409, 'credential_bound', '该 Connect 应用已被其他账号绑定');
        expectedUser = await userById(env, reserved.owner_user_id) ?? expectedUser;
      }
    } else {
      invariant(input.username, 404, 'credentials_required', '请填写你的 Connect 密钥');
      const matches = await env.DB.prepare(`SELECT u.id, u.linuxdo_id, u.username, u.credential_epoch, u.credential_revision, u.disabled, u.official_verified_at,
        k.client_id, k.owner_user_id, k.kind, k.ciphertext, k.version, k.status, k.updated_at
        FROM user u JOIN upstream_credential k ON k.owner_user_id = u.id
        WHERE lower(u.username) = lower(?) AND k.status = 'active' AND k.kind = 'self' LIMIT 2`)
        .bind(input.username).all<ExistingUser & CredentialRow>();
      invariant(matches.results.length === 1, 404, 'credentials_required', '请填写你的 Connect 密钥');
      expectedUser = matches.results[0];
      const credential = matches.results[0];
      invariant(!expectedUser.disabled, 403, 'account_disabled', '此账号暂不可用');
      invariant(expectedUser.official_verified_at == null, 403, 'official_login_required', OFFICIAL_LOGIN_REQUIRED_MESSAGE);
      invariant(credential?.ciphertext, 404, 'credentials_required', '请填写你的 Connect 密钥');
      clientId = credential.client_id;
      credentialVersion = credential.version;
      secret = await open<string>(env, credential.ciphertext, `upstream:${clientId}:v${credential.version}`);
    }
    invariant(!expectedUser?.disabled, 403, 'account_disabled', '此账号暂不可用');
    invariant(expectedUser?.official_verified_at == null, 403, 'official_login_required', OFFICIAL_LOGIN_REQUIRED_MESSAGE);
  }
  invariant(clientId && secret && !clientId.startsWith('PLACEHOLDER') && !secret.startsWith('PLACEHOLDER'), 503, 'connect_unavailable', '登录暂不可用，请稍后再试');
  const callback = `${env.APP_ORIGIN}/auth/connect/callback`;
  const upstream = await startUpstream(clientId, secret, callback);
  const id = randomId('ctx_');
  const payload = await seal(env, { secret, state: upstream.state, codeVerifier: upstream.codeVerifier, returnTo: credentialInput ? '/credentials' : '/apps' } satisfies Payload, `connect-tx:${id}`);
  const browserHash = await hash(browserToken);
  const now = Date.now();
  const inserted = await env.DB.prepare(`INSERT INTO connect_transaction
    (id, state_hash, browser_hash, request_id, method, client_id, encrypted_payload, expected_user_id, expected_linuxdo_id,
    expected_username, credential_epoch, credential_version, candidate, started_credential_revision, status, created_at, expires_at)
    SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CASE WHEN ? = 'lite_self_app' THEN (SELECT revision FROM credential_clock WHERE id = 1) ELSE NULL END, 'pending', ?, ?
    WHERE (? != 'lite_self_app' OR (EXISTS (SELECT 1 FROM credential_clock WHERE id = 1)
      AND (? IS NULL OR EXISTS (SELECT 1 FROM user WHERE id = ? AND disabled = 0 AND official_verified_at IS NULL)))) AND (? IS NULL OR EXISTS (
      SELECT 1 FROM authorization_request r JOIN oauth_client c ON c.client_id = r.client_id
      JOIN app_settings a ON a.client_id = c.client_id
      WHERE r.id = ? AND r.browser_hash = ? AND r.status = 'pending' AND r.expires_at > ?
      AND c.disabled = 0 AND a.deleted_at IS NULL AND (a.lite_only = 0 OR ? = 'lite_self_app')))`)
    .bind(id, await hash(upstream.state), browserHash, input.request ?? null, method, clientId, payload,
      expectedUser?.id ?? null, expectedUser?.linuxdo_id ?? null,
      method === 'lite_self_app' && !expectedUser ? input.username ?? null : null,
      expectedUser?.credential_epoch ?? null, credentialVersion, Number(candidate),
      method, now, now + TRANSACTION_TTL,
      method, expectedUser?.id ?? null, expectedUser?.id ?? null, input.request ?? null, input.request ?? null, browserHash, now, method).run();
  if (inserted.meta.changes !== 1 && method === 'lite_self_app' && expectedUser) {
    const current = await userById(env, expectedUser.id);
    invariant(current?.official_verified_at == null, 403, 'official_login_required', OFFICIAL_LOGIN_REQUIRED_MESSAGE);
  }
  invariant(inserted.meta.changes === 1, 400, 'request_expired', '登录请求已过期，请重新开始');
  return { redirect_url: upstream.authorizationUrl };
}

async function browserCookie(ctx: CallbackContext, env: Env) {
  const token = ctx.getCookie(cookieName(env, 'browser'));
  invariant(token, 400, 'request_expired', '登录请求已过期，请重新开始');
  return token;
}

export async function finishConnect(env: Env, ctx: CallbackContext) {
  const state = ctx.query?.state;
  invariant(typeof state === 'string', 400, 'invalid_state', '登录请求无效，请重新开始');
  const browserToken = await browserCookie(ctx, env);
  const transaction = await env.DB.prepare(`UPDATE connect_transaction SET status = 'consumed' WHERE state_hash = ?
    AND browser_hash = ? AND status = 'pending' AND expires_at > ? RETURNING *`)
    .bind(await hash(state), await hash(browserToken), Date.now()).first<TransactionRow>();
  if (!transaction) {
    const locked = await env.DB.prepare(`SELECT t.id FROM connect_transaction t JOIN user u ON
      u.id = t.expected_user_id OR u.linuxdo_id = t.expected_linuxdo_id OR u.id IN
      (SELECT owner_user_id FROM upstream_credential WHERE client_id = t.client_id AND kind = 'self')
      WHERE t.state_hash = ? AND t.browser_hash = ? AND t.method = 'lite_self_app'
      AND t.status = 'canceled' AND u.official_verified_at IS NOT NULL`).bind(await hash(state), await hash(browserToken)).first();
    invariant(!locked, 403, 'official_login_required', OFFICIAL_LOGIN_REQUIRED_MESSAGE);
  }
  invariant(transaction?.encrypted_payload, 400, 'request_expired', '登录请求已过期，请重新开始');
  const downstreamClientId = transaction.request_id
    ? (await env.DB.prepare('SELECT client_id FROM authorization_request WHERE id = ?').bind(transaction.request_id).first<{ client_id: string }>())?.client_id
    : undefined;
  const outcomeKey = `connect:${transaction.id}:outcome`;
  if (ctx.query?.error || typeof ctx.query?.code !== 'string') {
    await env.DB.batch([
      connectOutcomeStatement(env.DB, "t.id = ? AND t.status IN ('pending','consumed')", [transaction.id], 'denied', 'authorization_denied'),
      env.DB.prepare("UPDATE connect_transaction SET status = 'canceled', encrypted_payload = NULL WHERE id = ?").bind(transaction.id),
    ]);
    await audit(env.DB, transaction.request_id ? 'authorization.denied' : 'account.login_failed', null, downstreamClientId ?? transaction.client_id, {
      clientId: downstreamClientId, loginMethod: transaction.method, requestId: transaction.request_id ?? undefined,
      result: 'denied', reason: 'authorization_denied', eventKey: outcomeKey,
    });
    return `${env.APP_ORIGIN}/login?error=authorization_denied`;
  }
  let verifiedUserId: string | null = null;
  let verifiedIdentity: VerifiedConnectIdentity | undefined;
  try {
    const payload = await open<Payload>(env, transaction.encrypted_payload, `connect-tx:${transaction.id}`);
    if (transaction.request_id) {
      const { app } = await getRequest(env, transaction.request_id, browserToken);
      invariant(transaction.method !== 'official_connect' || !app.lite_only, 403, 'lite_only', '此应用仅支持 Lite 登录');
    }
    const callback = new URL('/auth/connect/callback', env.APP_ORIGIN);
    callback.searchParams.set('code', ctx.query.code);
    callback.searchParams.set('state', state);
    const profile = await finishUpstream(transaction.client_id, payload.secret, `${env.APP_ORIGIN}/auth/connect/callback`, callback.toString(), payload.state, payload.codeVerifier);
    verifiedIdentity = { id: profile.id, username: profile.username, name: profile.name ?? null, trust_level: profile.trust_level };
    const expectedTarget = transaction.expected_user_id && !transaction.expected_linuxdo_id ? await userById(env, transaction.expected_user_id) : null;
    const expectedLinuxdoId = transaction.expected_linuxdo_id ?? expectedTarget?.linuxdo_id ?? null;
    invariant(!expectedLinuxdoId || profile.id === expectedLinuxdoId, 403, 'identity_mismatch', '登录账号不一致，请重新开始');
    invariant(expectedLinuxdoId || !transaction.expected_username || profile.username.toLowerCase() === transaction.expected_username.toLowerCase(), 403, 'identity_mismatch', '登录账号不一致，请重新开始');
    const oldUser = await env.DB.prepare('SELECT * FROM user WHERE linuxdo_id = ?').bind(profile.id).first<ExistingUser>();
    invariant(!transaction.expected_user_id || !oldUser || oldUser.id === transaction.expected_user_id, 403, 'identity_mismatch', '登录账号不一致，请重新开始');
    invariant(!oldUser?.disabled, 403, 'account_disabled', '此账号暂不可用');
    const id = oldUser?.id ?? randomId('la_');
    const now = Date.now();
    if (!oldUser) {
      await env.DB.prepare(`INSERT INTO user (id, name, email, email_verified, image, created_at, updated_at, linuxdo_id, username, is_admin, disabled, credential_epoch, credential_revision)
        VALUES (?, ?, ?, 0, ?, ?, ?, ?, ?, ?, 0, 0, 0)
        ON CONFLICT(linuxdo_id) DO NOTHING`)
        .bind(id, profile.name || profile.username, `${profile.id}@linuxdo.liteauth.invalid`, profile.avatar_url ?? null, now, now,
          profile.id, profile.username, Number(isConfiguredAdmin(env, profile.id))).run();
    }
    const savedUser = await env.DB.prepare('SELECT * FROM user WHERE linuxdo_id = ?').bind(profile.id).first<ExistingUser>();
    invariant(savedUser && !savedUser.disabled, 403, 'account_disabled', '此账号暂不可用');
    const userId = savedUser.id;
    verifiedIdentity.user_id = userId;
    verifiedUserId = userId;
    invariant(transaction.method !== 'lite_self_app' || savedUser.official_verified_at == null, 403, 'official_login_required', OFFICIAL_LOGIN_REQUIRED_MESSAGE);
    const expectedEpoch = transaction.method === 'lite_self_app' ? transaction.credential_epoch : null;
    invariant(transaction.method !== 'lite_self_app' || transaction.started_credential_revision !== null, 400, 'credential_changed', 'Connect 密钥已变更，请重新开始');
    invariant(transaction.method !== 'lite_self_app' || (savedUser.credential_revision ?? 0) <= transaction.started_credential_revision!, 400, 'credential_changed', 'Connect 密钥已变更，请重新开始');
    invariant(expectedEpoch === null || savedUser.credential_epoch === expectedEpoch, 400, 'credential_changed', 'Connect 密钥已变更，请重新开始');
    const eventId = randomId('ae_');
    const guardId = randomId('guard_');
    const statements: D1PreparedStatement[] = [env.DB.prepare(`INSERT INTO mutation_guard (id, ok)
      SELECT ?, CASE WHEN EXISTS (SELECT 1 FROM connect_transaction t JOIN user u ON u.id = ? WHERE t.id = ?
      AND t.status = 'consumed' AND t.expires_at > ? AND u.disabled = 0
      AND (t.method != 'lite_self_app' OR u.official_verified_at IS NULL)
      AND (t.method != 'lite_self_app' OR (t.started_credential_revision IS NOT NULL AND u.credential_revision <= t.started_credential_revision))
      AND (? IS NULL OR u.credential_epoch = ?)
      AND (? IS NULL OR EXISTS (SELECT 1 FROM upstream_credential k WHERE k.client_id = t.client_id
      AND k.owner_user_id = u.id AND k.version = ? AND k.status = 'active'))
      AND (t.request_id IS NULL OR EXISTS (SELECT 1 FROM authorization_request r JOIN app_settings a ON a.client_id = r.client_id
      JOIN oauth_client c ON c.client_id = r.client_id WHERE r.id = t.request_id AND r.status = 'pending' AND r.expires_at > ?
      AND c.disabled = 0 AND a.deleted_at IS NULL AND (a.lite_only = 0 OR t.method = 'lite_self_app')))) THEN 1 ELSE 0 END`)
      .bind(guardId, userId, transaction.id, now, expectedEpoch, expectedEpoch,
        transaction.credential_version, transaction.credential_version, now)];
    let version = transaction.credential_version;
    if (transaction.candidate) {
      const reserved = await env.DB.prepare('SELECT * FROM upstream_credential WHERE client_id = ?').bind(transaction.client_id).first<CredentialRow>();
      version = (reserved?.version ?? 0) + 1;
      const encrypted = await seal(env, payload.secret, `upstream:${transaction.client_id}:v${version}`);
      statements.push(
        env.DB.prepare(`INSERT INTO mutation_guard (id, ok) SELECT ?, CASE WHEN NOT EXISTS
          (SELECT 1 FROM upstream_credential WHERE client_id = ? AND (kind != 'self' OR owner_user_id != ? OR owner_user_id IS NULL OR version != ?)) THEN 1 ELSE 0 END`)
          .bind(`${guardId}_binding`, transaction.client_id, userId, reserved?.version ?? 0),
        env.DB.prepare("UPDATE upstream_credential SET status = 'revoked', ciphertext = NULL, updated_at = ? WHERE owner_user_id = ? AND status = 'active' AND client_id != ?")
          .bind(now, userId, transaction.client_id),
        env.DB.prepare(`INSERT INTO upstream_credential (client_id, owner_user_id, kind, ciphertext, version, status, created_at, updated_at)
          VALUES (?, ?, 'self', ?, ?, 'active', ?, ?) ON CONFLICT(client_id) DO UPDATE SET ciphertext = excluded.ciphertext,
          version = excluded.version, status = 'active', updated_at = excluded.updated_at WHERE kind = 'self' AND owner_user_id = excluded.owner_user_id`)
          .bind(transaction.client_id, userId, encrypted, version, now, now),
        env.DB.prepare('UPDATE user SET credential_epoch = credential_epoch + 1 WHERE id = ?').bind(userId),
      );
    }
    statements.push(
      env.DB.prepare(`INSERT INTO auth_event (id, user_id, login_method, upstream_client_id, credential_version, trust_level, profile, created_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)`)
        .bind(eventId, userId, transaction.method, transaction.client_id, version, profile.trust_level, JSON.stringify(profile), now),
      env.DB.prepare(`UPDATE user SET name = ?, username = ?, image = ?, updated_at = ?, is_admin = ?,
        last_authenticated_at = ?, last_login_method = ?, last_trust_level = ? WHERE id = ?`)
        .bind(profile.name || profile.username, profile.username, profile.avatar_url ?? null, now,
          Number(isConfiguredAdmin(env, profile.id)), now, transaction.method, profile.trust_level, userId),
      connectOutcomeStatement(env.DB, "t.id = ? AND t.status IN ('pending','consumed')", [transaction.id], 'success', null, verifiedIdentity),
      env.DB.prepare("UPDATE connect_transaction SET status = 'completed', encrypted_payload = NULL WHERE id = ?").bind(transaction.id),
    );
    if (transaction.request_id) statements.push(env.DB.prepare("UPDATE authorization_request SET auth_event_id = ? WHERE id = ? AND status = 'pending'").bind(eventId, transaction.request_id));
    // Bind the current official request first; canceling older Lite work must not cancel this new flow.
    if (transaction.method === 'official_connect') statements.push(...officialLockStatements(env.DB, userId, now));
    statements.push(env.DB.prepare('DELETE FROM mutation_guard WHERE id IN (?, ?)').bind(guardId, `${guardId}_binding`));
    await env.DB.batch(statements);
    const user = await ctx.context.internalAdapter.findUserById(userId);
    invariant(user, 400, 'account_unavailable', '登录暂不可用');
    const session = await ctx.context.internalAdapter.createSession(userId, false, { authEventId: eventId }, true);
    invariant(session, 400, 'session_failed', '登录暂不可用，请重新开始');
    await setSessionCookie(ctx, { user, session });
    await audit(env.DB, transaction.candidate ? 'credential.verified' : 'account.login', userId, transaction.client_id, {
      targetType: transaction.candidate ? 'credential' : 'account', targetName: transaction.candidate ? transaction.client_id : profile.username,
      loginMethod: transaction.method, trustLevel: profile.trust_level, result: 'success', eventKey: `connect:${transaction.id}:authenticated`,
    });
    if (!transaction.request_id) return `${env.APP_ORIGIN}${payload.returnTo}`;
    const { app } = await getRequest(env, transaction.request_id, browserToken);
    if (!appEligibility(app, { login_method: transaction.method, trust_level: profile.trust_level, official_verified_at: transaction.method === 'official_connect' ? now : null }).allowed) {
      // The identity and credential have been verified. Keep this management session, but let the
      // login page show the current level and offer a new verification instead of issuing a grant.
      await audit(env.DB, 'authorization.failed', userId, app.client_id, {
        clientId: app.client_id, loginMethod: transaction.method, trustLevel: profile.trust_level,
        result: 'failed', reason: 'trust_level_required', requestId: transaction.request_id, eventKey: outcomeKey,
      });
      return `${env.APP_ORIGIN}/login?request=${transaction.request_id}`;
    }
    return `${env.APP_ORIGIN}/auth/resume?request=${transaction.request_id}`;
  } catch (error) {
    let code = error instanceof APIError ? (error.body?.error === 'official_login_required' ? 'official_login_required' : 'authorization_failed') : error instanceof Error && 'code' in error ? String(error.code) : 'authorization_failed';
    if (transaction.method === 'lite_self_app' && verifiedUserId) {
      const current = await userById(env, verifiedUserId);
      if (current?.official_verified_at != null) code = 'official_login_required';
    }
    await env.DB.batch([
      connectOutcomeStatement(env.DB, "t.id = ? AND t.status IN ('pending','consumed')", [transaction.id], 'failed', code, verifiedIdentity),
      env.DB.prepare("UPDATE connect_transaction SET status = 'canceled', encrypted_payload = NULL WHERE id = ? AND status != 'completed'").bind(transaction.id),
    ]);
    await audit(env.DB, transaction.request_id ? 'authorization.failed' : 'account.login_failed', verifiedUserId, downstreamClientId ?? transaction.client_id, {
      clientId: downstreamClientId, loginMethod: transaction.method, result: 'failed', reason: code,
      requestId: transaction.request_id ?? undefined, eventKey: outcomeKey,
    });
    return `${env.APP_ORIGIN}/login?error=${encodeURIComponent(code)}`;
  }
}

export async function revokeCredentials(env: Env, userId: string) {
  const now = Date.now();
  await env.DB.batch([
    authorizationOutcomeStatement(env.DB, 'grant', `g.state = 'pending' AND g.auth_event_id IN
      (SELECT id FROM auth_event WHERE user_id = ? AND login_method = 'lite_self_app')`, [userId], 'canceled', 'credential_revoked'),
    authorizationOutcomeStatement(env.DB, 'request', `r.status IN ('pending','processing') AND
      (r.auth_event_id IN (SELECT id FROM auth_event WHERE user_id = ? AND login_method = 'lite_self_app')
      OR r.id IN (SELECT request_id FROM connect_transaction WHERE expected_user_id = ? AND method = 'lite_self_app' AND status IN ('pending','consumed')))`,
    [userId, userId], 'canceled', 'credential_revoked'),
    env.DB.prepare("UPDATE upstream_credential SET ciphertext = NULL, status = 'revoked', updated_at = ? WHERE owner_user_id = ? AND kind = 'self'").bind(now, userId),
    env.DB.prepare('UPDATE user SET credential_epoch = credential_epoch + 1 WHERE id = ?').bind(userId),
    connectOutcomeStatement(env.DB, "t.expected_user_id = ? AND t.method = 'lite_self_app' AND t.status IN ('pending','consumed')", [userId], 'canceled', 'credential_revoked'),
    env.DB.prepare(`UPDATE authorization_request SET status = 'canceled' WHERE status IN ('pending','processing') AND
      (auth_event_id IN (SELECT id FROM auth_event WHERE user_id = ? AND login_method = 'lite_self_app')
      OR id IN (SELECT request_id FROM connect_transaction WHERE expected_user_id = ? AND method = 'lite_self_app' AND status IN ('pending','consumed')))`)
      .bind(userId, userId),
    env.DB.prepare("UPDATE connect_transaction SET status = 'canceled', encrypted_payload = NULL WHERE expected_user_id = ? AND status IN ('pending', 'consumed')").bind(userId),
    env.DB.prepare("UPDATE auth_event SET revoked_at = ? WHERE user_id = ? AND login_method = 'lite_self_app' AND revoked_at IS NULL").bind(now, userId),
    env.DB.prepare("UPDATE grant_ledger SET state = 'canceled' WHERE state = 'pending' AND auth_event_id IN (SELECT id FROM auth_event WHERE user_id = ? AND login_method = 'lite_self_app')").bind(userId),
    env.DB.prepare("UPDATE oauth_access_token SET revoked = ? WHERE user_id = ? AND reference_id IN (SELECT id FROM auth_event WHERE user_id = ? AND login_method = 'lite_self_app')").bind(now, userId, userId),
    env.DB.prepare("DELETE FROM session WHERE user_id = ? AND auth_event_id IN (SELECT id FROM auth_event WHERE user_id = ? AND login_method = 'lite_self_app')").bind(userId, userId),
  ]);
  await audit(env.DB, 'credential.deleted', userId, userId);
}
