import { auditStatement, authorizationOutcomeStatement } from './audit';
import { connectOutcomeStatement } from './connect-audit';

export const OFFICIAL_LOGIN_REQUIRED_MESSAGE = '此账号已完成非 Lite 验证，请使用非 Lite 用户登录。';

/** Keep issued events, sessions and tokens intact. Only new Lite authentication/issuance is prohibited. */
export function officialLockStatements(db: D1Database, userId: string, verifiedAt: number): D1PreparedStatement[] {
  if (!Number.isSafeInteger(verifiedAt) || verifiedAt <= 0) throw new Error('Invalid official authentication timestamp');
  const transactionCondition = `t.method = 'lite_self_app' AND t.status IN ('pending','consumed') AND
    (t.expected_user_id = ? OR t.expected_linuxdo_id = (SELECT linuxdo_id FROM user WHERE id = ?)
    OR t.client_id IN (SELECT client_id FROM upstream_credential WHERE kind = 'self' AND owner_user_id = ?))`;
  const transactionBindings = [userId, userId, userId];
  const grantCondition = `g.state = 'pending' AND g.auth_event_id IN
    (SELECT id FROM auth_event WHERE user_id = ? AND login_method = 'lite_self_app')`;
  const requestCondition = `r.status IN ('pending','processing') AND
    NOT EXISTS (SELECT 1 FROM auth_event e WHERE e.id = r.auth_event_id AND e.user_id = ? AND e.login_method = 'official_connect') AND
    (r.auth_event_id IN (SELECT id FROM auth_event WHERE user_id = ? AND login_method = 'lite_self_app')
    OR r.id IN (SELECT t.request_id FROM connect_transaction t WHERE ${transactionCondition}))`;
  const requestBindings = [userId, userId, ...transactionBindings];
  return [
    db.prepare('UPDATE user SET official_verified_at = ? WHERE id = ? AND official_verified_at IS NULL').bind(verifiedAt, userId),
    auditStatement(db, 'account.official_verified', userId, userId, {
      targetType: 'user', loginMethod: 'official_connect', result: 'success', eventKey: `account:${userId}:official_verified`,
    }),
    authorizationOutcomeStatement(db, 'grant', grantCondition, [userId], 'canceled', 'official_login_required'),
    authorizationOutcomeStatement(db, 'request', requestCondition, requestBindings, 'canceled', 'official_login_required'),
    connectOutcomeStatement(db, transactionCondition, transactionBindings, 'canceled', 'official_login_required'),
    db.prepare(`UPDATE grant_ledger AS g SET state = 'canceled' WHERE ${grantCondition}`).bind(userId),
    db.prepare(`DELETE FROM verification WHERE identifier IN
      (SELECT g.code_id FROM grant_ledger g WHERE g.state = 'canceled' AND g.auth_event_id IN
      (SELECT id FROM auth_event WHERE user_id = ? AND login_method = 'lite_self_app'))`).bind(userId),
    db.prepare(`UPDATE authorization_request AS r SET status = 'canceled' WHERE ${requestCondition}`).bind(...requestBindings),
    db.prepare(`UPDATE connect_transaction AS t SET status = 'canceled', encrypted_payload = NULL WHERE ${transactionCondition}`).bind(...transactionBindings),
  ];
}

// Each source already stores a verified stable identity. A typed username is never backfill evidence.
const officialEvidence = `SELECT e.user_id, e.created_at AS verified_at FROM auth_event e JOIN user u ON u.id = e.user_id
  WHERE e.login_method = 'official_connect' AND e.created_at > 0
  AND json_extract(CASE WHEN json_valid(e.profile) THEN e.profile ELSE '{}' END, '$.id') = u.linuxdo_id
  UNION ALL
  SELECT u.id, a.created_at FROM audit a JOIN user u ON u.id = a.actor_id
  WHERE a.login_method = 'official_connect' AND a.result = 'success' AND a.created_at > 0
  AND a.actor_linuxdo_id = u.linuxdo_id AND
  (a.action = 'account.login' OR (a.action = 'connect.verification' AND a.identity_confirmed = 1
    AND a.subject_user_id = u.id AND a.subject_linuxdo_id = u.linuxdo_id))
  UNION ALL
  SELECT id, last_authenticated_at FROM user WHERE last_login_method = 'official_connect'
  AND last_authenticated_at > 0 AND last_trust_level BETWEEN 0 AND 4`;

/** Run only after deploying the enforcing API. Repeating this operation cannot unlock or duplicate cancellation records. */
export async function backfillOfficialLocks(db: D1Database, limit = 50) {
  if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new Error('Invalid backfill limit');
  const pending = await db.prepare(`SELECT evidence.user_id, MIN(evidence.verified_at) AS verified_at
    FROM (${officialEvidence}) evidence JOIN user u ON u.id = evidence.user_id
    WHERE u.official_verified_at IS NULL GROUP BY evidence.user_id ORDER BY evidence.user_id LIMIT ?`)
    .bind(limit).all<{ user_id: string; verified_at: number }>();
  let locked = 0;
  for (const row of pending.results) {
    const results = await db.batch(officialLockStatements(db, row.user_id, row.verified_at));
    locked += results[0].meta.changes;
  }
  const remaining = await db.prepare(`SELECT count(DISTINCT evidence.user_id) AS count
    FROM (${officialEvidence}) evidence JOIN user u ON u.id = evidence.user_id WHERE u.official_verified_at IS NULL`)
    .first<{ count: number }>();
  return { inspected: pending.results.length, locked, remaining: remaining?.count ?? 0 };
}
