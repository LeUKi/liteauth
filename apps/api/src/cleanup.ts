import type { Env } from './env';
import { authorizationOutcomeStatement, LOG_RETENTION_MS } from './audit';
import { connectOutcomeStatement } from './connect-audit';

export const HISTORY_CRON = '30 20 * * *'; // 04:30 Asia/Shanghai, daily.

export async function cleanup(env: Env) {
  const now = Date.now();
  const day = 24 * 3600_000;
  await env.DB.batch([
    authorizationOutcomeStatement(env.DB, 'request', "r.expires_at <= ? AND r.status IN ('pending','processing')", [now], 'expired', 'request_expired'),
    authorizationOutcomeStatement(env.DB, 'grant', "g.expires_at <= ? AND g.state = 'pending'", [now], 'expired', 'code_expired'),
    connectOutcomeStatement(env.DB, "t.expires_at <= ? AND t.status IN ('pending','consumed')", [now], 'expired', 'request_expired'),
    env.DB.prepare("UPDATE connect_transaction SET encrypted_payload = NULL, status = 'expired' WHERE expires_at <= ? AND status IN ('pending', 'consumed')").bind(now),
    env.DB.prepare("UPDATE authorization_request SET status = 'expired' WHERE expires_at <= ? AND status IN ('pending', 'processing')").bind(now),
    env.DB.prepare("UPDATE grant_ledger SET state = 'canceled' WHERE expires_at <= ? AND state = 'pending'").bind(now),
    env.DB.prepare('DELETE FROM verification WHERE expires_at <= ?').bind(now),
    env.DB.prepare('DELETE FROM oauth_access_token WHERE expires_at < ?').bind(now - day),
    env.DB.prepare('DELETE FROM session WHERE expires_at < ?').bind(now - day),
    env.DB.prepare('DELETE FROM connect_transaction WHERE expires_at < ?').bind(now - day),
    env.DB.prepare('DELETE FROM authorization_request WHERE expires_at < ?').bind(now - day),
    env.DB.prepare('DELETE FROM rate_limit WHERE expires_at < ?').bind(now - day),
  ]);
}

export async function cleanupHistory(env: Env) {
  await cleanup(env);
  const cutoff = Date.now() - LOG_RETENTION_MS;
  // Retain authentication evidence until every consuming row is gone. Consent alone
  // cannot keep an expired authentication alive and is removed with the orphan event.
  const orphanEvent = `e.created_at < ?
    AND NOT EXISTS (SELECT 1 FROM session s WHERE s.auth_event_id = e.id)
    AND NOT EXISTS (SELECT 1 FROM oauth_access_token t WHERE t.reference_id = e.id)
    AND NOT EXISTS (SELECT 1 FROM oauth_refresh_token t WHERE t.reference_id = e.id)
    AND NOT EXISTS (SELECT 1 FROM grant_ledger g WHERE g.auth_event_id = e.id)
    AND NOT EXISTS (SELECT 1 FROM authorization_request r WHERE r.auth_event_id = e.id)`;
  await env.DB.batch([
    env.DB.prepare('DELETE FROM audit WHERE created_at < ?').bind(cutoff),
    env.DB.prepare(`DELETE FROM grant_ledger WHERE expires_at < ? AND state != 'pending'
      AND NOT EXISTS (SELECT 1 FROM oauth_access_token t WHERE t.authorization_code_id = grant_ledger.code_id)
      AND NOT EXISTS (SELECT 1 FROM oauth_refresh_token t WHERE t.authorization_code_id = grant_ledger.code_id)
      AND NOT EXISTS (SELECT 1 FROM verification v WHERE v.identifier = grant_ledger.code_id)`)
      .bind(cutoff),
    env.DB.prepare(`DELETE FROM oauth_consent WHERE reference_id IN (SELECT e.id FROM auth_event e WHERE ${orphanEvent})`).bind(cutoff),
    env.DB.prepare(`DELETE FROM auth_event AS e WHERE ${orphanEvent}`).bind(cutoff),
  ]);
}
