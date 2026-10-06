import { APIError, type BetterAuthOptions, type DBAdapter } from 'better-auth';
import { drizzleAdapter } from 'better-auth/adapters/drizzle';
import { drizzle } from 'drizzle-orm/d1';
import { randomId } from '../crypto';
import { authorizationOutcomeStatement } from '../audit';
import type { createAppSecretCapture } from '../app-secrets';
import * as schema from './schema';
import { OFFICIAL_LOGIN_REQUIRED_MESSAGE } from '../account-policy';

type StoredCode = { type?: string; query?: { client_id?: string }; referenceId?: string; userId?: string };
type Row = Record<string, unknown>;
const invalidGrant = () => new APIError('BAD_REQUEST', { error: 'invalid_grant', error_description: 'This authorization is no longer available' });
const ms = (value: unknown) => value instanceof Date ? value.getTime() : typeof value === 'number' ? value : Date.now();
const json = (value: unknown) => value == null ? null : JSON.stringify(value);

/** The provider owns protocol parsing. This decorator guards durable session and issuance writes. */
export function policyAdapter(db: D1Database, requestId?: string, secretCapture?: ReturnType<typeof createAppSecretCapture>) {
  const baseFactory = drizzleAdapter(drizzle(db, { schema }), { provider: 'sqlite', schema, transaction: false });

  function decorate(base: DBAdapter): DBAdapter {
    const wrapped: DBAdapter = {
      ...base,
      async create<T extends Row, R = T>({ model, data, select, forceAllowId }: { model: string; data: Omit<T, 'id'>; select?: string[]; forceAllowId?: boolean }): Promise<R> {
        if (model === 'session') {
          const id = typeof data.id === 'string' ? data.id : randomId();
          const result = await db.prepare(`INSERT INTO session
            (id, token, user_id, expires_at, created_at, updated_at, ip_address, user_agent, auth_event_id)
            SELECT ?, ?, ?, ?, ?, ?, ?, ?, ? FROM auth_event e JOIN user u ON u.id = e.user_id
            WHERE e.id = ? AND e.user_id = ? AND e.revoked_at IS NULL AND u.disabled = 0
            AND (e.login_method != 'lite_self_app' OR u.official_verified_at IS NULL)`)
            .bind(id, data.token, data.userId, ms(data.expiresAt), ms(data.createdAt), ms(data.updatedAt),
              data.ipAddress ?? null, data.userAgent ?? null, data.authEventId, data.authEventId, data.userId).run();
          if (result.meta.changes !== 1) {
            const locked = await db.prepare(`SELECT u.id FROM user u JOIN auth_event e ON e.user_id = u.id
              WHERE u.id = ? AND e.id = ? AND e.login_method = 'lite_self_app' AND u.official_verified_at IS NOT NULL`)
              .bind(data.userId, data.authEventId).first();
            if (locked) throw new APIError('FORBIDDEN', { error: 'official_login_required', message: OFFICIAL_LOGIN_REQUIRED_MESSAGE });
            throw new APIError('UNAUTHORIZED', { error: 'session_unavailable' });
          }
          return { ...data, id } as unknown as R;
        }
        if (model === 'oauthClient' && typeof data.clientSecret === 'string') {
          if (!secretCapture || typeof data.clientId !== 'string') throw new APIError('INTERNAL_SERVER_ERROR');
          const secretCiphertext = await secretCapture.seal(data.clientId, data.clientSecret);
          return base.create<T, R>({ model, data: { ...data, secretCiphertext }, select, forceAllowId });
        }
        if (model === 'verification') {
          let code: StoredCode;
          try { code = JSON.parse(String(data.value)) as StoredCode; } catch {
            if (requestId) throw invalidGrant();
            return base.create<T, R>({ model, data, select, forceAllowId });
          }
          if (code.type !== 'authorization_code') return base.create<T, R>({ model, data, select, forceAllowId });
          if (!code.referenceId || !code.userId || !code.query?.client_id) throw invalidGrant();
          const id = typeof data.id === 'string' ? data.id : randomId();
          const expiresAt = Math.min(ms(data.expiresAt), Date.now() + 120_000);
          const result = await db.batch([
            db.prepare(`INSERT INTO verification (id, identifier, value, expires_at, created_at, updated_at)
              SELECT ?, ?, ?, ?, ?, ? FROM auth_event e JOIN user u ON u.id = e.user_id
              JOIN oauth_client c ON c.client_id = ? JOIN app_settings a ON a.client_id = c.client_id
              WHERE e.id = ? AND e.user_id = ? AND e.revoked_at IS NULL AND u.disabled = 0 AND c.disabled = 0 AND a.deleted_at IS NULL
              AND (e.login_method != 'lite_self_app' OR u.official_verified_at IS NULL)
              AND (? IS NULL OR EXISTS (SELECT 1 FROM authorization_request r WHERE r.id = ? AND r.client_id = c.client_id
              AND r.auth_event_id = e.id AND r.status IN ('pending', 'processing') AND r.expires_at > ?))
              AND (a.lite_only = 0 OR e.login_method = 'lite_self_app') AND e.trust_level >= a.min_trust_level`)
              .bind(id, data.identifier, data.value, expiresAt, ms(data.createdAt), ms(data.updatedAt), code.query.client_id, code.referenceId, code.userId,
                requestId ?? null, requestId ?? null, Date.now()),
            db.prepare(`INSERT INTO grant_ledger (code_id, client_id, auth_event_id, request_id, state, created_at, expires_at)
              SELECT identifier, ?, ?, ?, 'pending', created_at, expires_at FROM verification WHERE id = ?`)
              .bind(code.query.client_id, code.referenceId, requestId ?? null, id),
            authorizationOutcomeStatement(db, 'grant', "g.code_id = ? AND EXISTS (SELECT 1 FROM verification WHERE id = ?)", [String(data.identifier), id], 'pending'),
          ]);
          if (result[0].meta.changes !== 1 || result[1].meta.changes !== 1) throw invalidGrant();
          return { ...data, id, expiresAt: new Date(expiresAt) } as unknown as R;
        }
        if (model === 'oauthAccessToken') {
          if (!data.authorizationCodeId || !data.referenceId || data.refreshId || (Array.isArray(data.resources) && data.resources.length)) throw invalidGrant();
          const id = typeof data.id === 'string' ? data.id : randomId();
          const result = await db.batch([
            db.prepare(`INSERT INTO oauth_access_token
              (id, token, client_id, session_id, user_id, reference_id, authorization_code_id, resources,
              requested_user_info_claims, refresh_id, expires_at, created_at, revoked, confirmation, scopes)
              SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, NULL, ?, ?
              FROM grant_ledger g JOIN auth_event e ON e.id = g.auth_event_id JOIN user u ON u.id = e.user_id
              JOIN oauth_client c ON c.client_id = g.client_id JOIN app_settings a ON a.client_id = c.client_id
              JOIN session s ON s.id = ? AND s.auth_event_id = e.id
              WHERE g.code_id = ? AND g.state = 'pending' AND g.client_id = ? AND g.auth_event_id = ?
              AND g.expires_at > ? AND s.expires_at > ? AND e.revoked_at IS NULL AND u.disabled = 0 AND c.disabled = 0 AND a.deleted_at IS NULL
              AND (e.login_method != 'lite_self_app' OR u.official_verified_at IS NULL)
              AND e.user_id = ? AND (a.lite_only = 0 OR e.login_method = 'lite_self_app') AND e.trust_level >= a.min_trust_level`)
              .bind(id, data.token, data.clientId, data.sessionId ?? null, data.userId ?? null, data.referenceId,
                data.authorizationCodeId, json(data.resources), json(data.requestedUserInfoClaims), ms(data.expiresAt), ms(data.createdAt),
                json(data.confirmation), json(data.scopes), data.sessionId ?? null, data.authorizationCodeId, data.clientId, data.referenceId,
                Date.now(), Date.now(), data.userId ?? null),
            db.prepare(`UPDATE grant_ledger SET state = 'issued', token_id = ? WHERE code_id = ? AND state = 'pending'
              AND EXISTS (SELECT 1 FROM oauth_access_token WHERE id = ?)`)
              .bind(id, data.authorizationCodeId, id),
            authorizationOutcomeStatement(db, 'grant', "g.code_id = ? AND g.state = 'issued' AND g.token_id = ?", [String(data.authorizationCodeId), id], 'success'),
          ]);
          if (result[0].meta.changes !== 1 || result[1].meta.changes !== 1) throw invalidGrant();
          return { ...data, id } as unknown as R;
        }
        if (model === 'oauthRefreshToken') throw invalidGrant();
        return base.create<T, R>({ model, data, select, forceAllowId });
      },
      async update<T>({ model, where, update }: Parameters<DBAdapter['update']>[0]) {
        if (model !== 'oauthClient' || typeof update.clientSecret !== 'string') return base.update<T>({ model, where, update });
        const previous = await base.findOne<{ clientId: string; clientSecret: string; userId: string; disabled: boolean }>({ model, where });
        if (!previous || previous.disabled || !previous.userId || !secretCapture) throw new APIError('BAD_REQUEST', { error: 'secret_rotation_conflict' });
        const available = await db.prepare('SELECT client_id FROM app_settings WHERE client_id = ? AND deleted_at IS NULL').bind(previous.clientId).first();
        if (!available) throw new APIError('NOT_FOUND');
        const secretCiphertext = await secretCapture.seal(previous.clientId, update.clientSecret);
        const result = await base.update<T>({ model, where: [...where,
          { field: 'clientSecret', value: previous.clientSecret }, { field: 'userId', value: previous.userId }, { field: 'disabled', value: false }],
          update: { ...update, secretCiphertext } });
        if (!result) throw new APIError('CONFLICT', { error: 'secret_rotation_conflict' });
        return result;
      },
      // D1 has no interactive transactions. Preserve the decorator when the library enters its fallback callback.
      transaction: (callback) => base.transaction((transaction) => callback(decorate(transaction as DBAdapter))),
    };
    return wrapped;
  }
  return (options: BetterAuthOptions): DBAdapter => decorate(baseFactory(options));
}
