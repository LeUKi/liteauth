import type { AuditFilters } from '@liteauth/contracts';
import { getApp, revokeAppStatements } from './apps';
import { audit } from './db/policy';
import type { Env } from './env';
import { invariant } from './errors';
import { authorizationOutcomeStatement, queryAudit } from './audit';
import { connectOutcomeStatement } from './connect-audit';
import { requireAdmin } from './admin-users';
export { getAdminUser, listConnectRecords, listUserApps, listUsers, parseAdminConnectFilters, parseAdminUserFilters } from './admin-users';

export async function listAudit(env: Env, actorId: string, filters: AuditFilters = {}) {
  await requireAdmin(env, actorId);
  return queryAudit(env.DB, filters);
}

export async function listLoginRecords(env: Env, actorId: string, appId: string, isAdmin: boolean, filters: AuditFilters = {}) {
  const { app } = await getApp(env, appId, actorId, isAdmin);
  return queryAudit(env.DB, filters, app.client_id);
}

export async function disableUser(env: Env, actorId: string, targetId: string, disabled: boolean): Promise<void> {
  await requireAdmin(env, actorId);
  const target = await env.DB.prepare('SELECT id, is_admin FROM user WHERE id = ?').bind(targetId).first<{ id: string; is_admin: number }>();
  invariant(target, 404, 'user_not_found', '账号不存在');
  invariant(!disabled || !target.is_admin, 400, 'admin_protected', '不能停用管理员账号');
  const statements = [env.DB.prepare('UPDATE user SET disabled = ?, updated_at = ? WHERE id = ?').bind(Number(disabled), Date.now(), targetId)];
  if (disabled) {
    statements.push(
      authorizationOutcomeStatement(env.DB, 'request', "r.status IN ('pending','processing') AND (e.user_id = ? OR r.id IN (SELECT request_id FROM connect_transaction WHERE expected_user_id = ? AND status IN ('pending','consumed')))", [targetId, targetId], 'canceled', 'account_disabled'),
      authorizationOutcomeStatement(env.DB, 'grant', "g.state = 'pending' AND e.user_id = ?", [targetId], 'canceled', 'account_disabled'),
      connectOutcomeStatement(env.DB, "t.expected_user_id = ? AND t.status IN ('pending','consumed')", [targetId], 'canceled', 'account_disabled'),
      env.DB.prepare('UPDATE user SET credential_epoch = credential_epoch + 1 WHERE id = ?').bind(targetId),
      env.DB.prepare('UPDATE auth_event SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL').bind(Date.now(), targetId),
      env.DB.prepare('UPDATE oauth_access_token SET revoked = ? WHERE user_id = ? AND revoked IS NULL').bind(Date.now(), targetId),
      env.DB.prepare('UPDATE oauth_refresh_token SET revoked = ? WHERE user_id = ? AND revoked IS NULL').bind(Date.now(), targetId),
      env.DB.prepare("UPDATE grant_ledger SET state = 'canceled' WHERE state = 'pending' AND auth_event_id IN (SELECT id FROM auth_event WHERE user_id = ?)").bind(targetId),
      env.DB.prepare(`UPDATE authorization_request SET status = 'canceled' WHERE status IN ('pending','processing') AND
        (auth_event_id IN (SELECT id FROM auth_event WHERE user_id = ?)
        OR id IN (SELECT request_id FROM connect_transaction WHERE expected_user_id = ? AND status IN ('pending','consumed')))`)
        .bind(targetId, targetId),
      env.DB.prepare("UPDATE connect_transaction SET status = 'canceled', encrypted_payload = NULL WHERE expected_user_id = ? AND status IN ('pending','consumed')").bind(targetId),
      env.DB.prepare('DELETE FROM session WHERE user_id = ?').bind(targetId),
    );
  }
  await env.DB.batch(statements);
  await audit(env.DB, disabled ? 'user.disabled' : 'user.enabled', actorId, targetId);
}

export async function disableApp(env: Env, actorId: string, appId: string, disabled: boolean): Promise<void> {
  await requireAdmin(env, actorId);
  const { app } = await getApp(env, appId, actorId, true);
  await env.DB.batch([
    env.DB.prepare(`UPDATE oauth_client SET disabled = ?, updated_at = ? WHERE id = ?
      AND EXISTS (SELECT 1 FROM app_settings WHERE client_id = oauth_client.client_id AND deleted_at IS NULL)`)
      .bind(Number(disabled), Date.now(), appId),
    ...(disabled ? revokeAppStatements(env, app.client_id) : []),
  ]);
  await audit(env.DB, disabled ? 'app.disabled' : 'app.enabled', actorId, appId);
}
