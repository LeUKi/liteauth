import type { AuditResult } from '@liteauth/contracts';

export type VerifiedConnectIdentity = {
  id: number; username: string; name?: string | null; trust_level: number; user_id?: string;
};

/** Write before the matching terminal transition in the same D1 batch. Input names are never identity evidence. */
export function connectOutcomeStatement(
  db: D1Database, condition: string, bindings: (string | number | null)[],
  result: Exclude<AuditResult, 'pending'>, reason?: string | null, verified?: VerifiedConnectIdentity,
) {
  return db.prepare(`INSERT INTO audit
    (id, action, actor_id, actor_type, actor_linuxdo_id, actor_username, actor_name,
     target_id, target_type, target_name, client_id, app_name, login_method, trust_level,
     result, reason, request_id, event_key, created_at, subject_user_id, subject_linuxdo_id,
     subject_username, upstream_client_id, connect_transaction_id, identity_confirmed, verification_purpose)
    SELECT 'au_' || lower(hex(randomblob(16))), 'connect.verification', actual.id,
      CASE WHEN ? IS NULL THEN 'unknown' ELSE 'user' END, ?, ?, ?,
      subject.id, 'user', subject.username, r.client_id, c.name, t.method, ?,
      ?, ?, t.request_id, 'connect:' || t.id || ':verification', ?, subject.id, subject.linuxdo_id,
      CASE WHEN subject.linuxdo_id = ? THEN ? ELSE subject.username END,
      t.client_id, t.id, CASE WHEN ? IS NOT NULL THEN 1 ELSE 0 END,
      CASE WHEN t.candidate = 1 THEN 'credential_validation' ELSE 'login' END
    FROM connect_transaction t
    LEFT JOIN user actual ON actual.linuxdo_id = ?
    LEFT JOIN user subject ON subject.id = COALESCE(t.expected_user_id, actual.id)
    LEFT JOIN authorization_request r ON r.id = t.request_id
    LEFT JOIN oauth_client c ON c.client_id = r.client_id
    WHERE ${condition}
    ON CONFLICT(event_key) DO NOTHING`)
    .bind(verified?.id ?? null, verified?.id ?? null, verified?.username ?? null, verified?.name ?? null,
      verified?.trust_level ?? null, result, reason ?? null, Date.now(), verified?.id ?? null,
      verified?.username ?? null, verified?.id ?? null, verified?.id ?? null, ...bindings);
}
