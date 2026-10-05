import { HttpError } from '../errors';
import { authorizationOutcomeStatement } from '../audit';
import { connectOutcomeStatement } from '../connect-audit';
export { audit } from '../audit';

export async function setAppPolicy(db: D1Database, clientId: string, liteOnly: boolean, minTrustLevel?: number) {
  if (minTrustLevel !== undefined && (!Number.isInteger(minTrustLevel) || minTrustLevel < 0 || minTrustLevel > 4)) {
    throw new HttpError(400, 'invalid_trust_level', '请选择 0 至 4 级');
  }
  const minimum = minTrustLevel ?? null;
  const grantCondition = `g.client_id = ? AND g.state = 'pending'
    AND g.auth_event_id IN (SELECT e.id FROM auth_event e JOIN app_settings a ON a.client_id = ?
    WHERE (? = 1 AND e.login_method = 'official_connect')
    OR (? > a.min_trust_level AND (e.trust_level IS NULL OR e.trust_level < ?)))`;
  const grantBindings = [clientId, clientId, Number(liteOnly), minimum, minimum];
  const requestCondition = `r.client_id = ? AND r.status IN ('pending', 'processing')
    AND ((? = 1 AND (r.auth_event_id IN (SELECT id FROM auth_event WHERE login_method = 'official_connect')
    OR r.id IN (SELECT request_id FROM connect_transaction WHERE method = 'official_connect' AND status IN ('pending', 'consumed'))))
    OR (? > (SELECT min_trust_level FROM app_settings WHERE client_id = ?) AND
    (r.auth_event_id IS NULL OR r.auth_event_id IN (SELECT id FROM auth_event WHERE trust_level IS NULL OR trust_level < ?)
    OR r.id IN (SELECT request_id FROM connect_transaction WHERE status IN ('pending', 'consumed')))))`;
  const requestBindings = [clientId, Number(liteOnly), minimum, clientId, minimum];
  // Inspect the previous policy inside the same batch: a concurrent editor must not make a stale read
  // decide whether this change raises the minimum. Cancellations precede the policy update atomically.
  await db.batch([
    authorizationOutcomeStatement(db, 'grant', grantCondition, grantBindings, 'canceled', 'policy_changed'),
    authorizationOutcomeStatement(db, 'request', requestCondition, requestBindings, 'canceled', 'policy_changed'),
    db.prepare(`UPDATE grant_ledger AS g SET state = 'canceled' WHERE ${grantCondition}`).bind(...grantBindings),
    db.prepare(`UPDATE authorization_request AS r SET status = 'canceled' WHERE ${requestCondition}`).bind(...requestBindings),
    connectOutcomeStatement(db, "t.status IN ('pending','consumed') AND t.request_id IN (SELECT id FROM authorization_request WHERE client_id = ? AND status = 'canceled')", [clientId], 'canceled', 'policy_changed'),
    db.prepare(`UPDATE connect_transaction SET status = 'canceled', encrypted_payload = NULL WHERE status IN ('pending', 'consumed')
      AND request_id IN (SELECT id FROM authorization_request WHERE client_id = ? AND status = 'canceled')`)
      .bind(clientId),
    db.prepare('UPDATE app_settings SET lite_only = ?, min_trust_level = COALESCE(?, min_trust_level) WHERE client_id = ?')
      .bind(Number(liteOnly), minimum, clientId),
  ]);
}

export async function rateLimit(db: D1Database, key: string, limit: number, windowMs = 60_000) {
  const now = Date.now();
  const row = await db.prepare(`INSERT INTO rate_limit (key, count, expires_at) VALUES (?, 1, ?)
    ON CONFLICT(key) DO UPDATE SET count = CASE WHEN expires_at <= ? THEN 1 ELSE count + 1 END,
    expires_at = CASE WHEN expires_at <= ? THEN ? ELSE expires_at END RETURNING count`)
    .bind(key, now + windowMs, now, now, now + windowMs).first<{ count: number }>();
  if (!row || row.count > limit) throw new HttpError(429, 'rate_limited', '操作太频繁，请稍后再试');
}
