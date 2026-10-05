import { z } from 'zod';
import type { AuditChanges, AuditEntry, AuditFilters, AuditPage, AuditResult, LoginMethod } from '@liteauth/contracts';
import { randomId } from './crypto';
import { invariant } from './errors';

export const LOG_RETENTION_MS = 7 * 24 * 3600_000;
export type AuditOptions = {
  targetType?: string; targetName?: string; clientId?: string; appName?: string;
  loginMethod?: LoginMethod; trustLevel?: number; result?: AuditResult; reason?: string;
  requestId?: string; eventKey?: string; changes?: AuditChanges; actorType?: 'user' | 'system' | 'unknown';
};
const changeFields = new Set(['name', 'redirect_uris', 'lite_only', 'min_trust_level', 'pkce_required', 'disabled']);
function safeChanges(changes?: AuditChanges) {
  if (!changes) return null;
  return JSON.stringify(Object.fromEntries(Object.entries(changes).filter(([key]) => changeFields.has(key))));
}

/** Snapshots contain only allowlisted business context, never request bodies or credentials. */
export function auditStatement(db: D1Database, action: string, actorId: string | null, targetId: string | null, options: AuditOptions = {}) {
  const targetType = options.targetType ?? (action.startsWith('app.') || action.startsWith('authorization.') ? 'app' : action.startsWith('user.') || action.startsWith('account.') ? 'user' : action.startsWith('credential.') ? 'credential' : null);
  return db.prepare(`INSERT INTO audit
    (id, action, actor_id, target_id, created_at, actor_type, actor_linuxdo_id, actor_username, actor_name,
     target_type, target_name, client_id, app_name, login_method, trust_level, result, reason, request_id, changes, event_key)
    SELECT ?, ?, ?, ?, ?, ?, u.linuxdo_id, u.username, u.name,
      ?, COALESCE(?, c.name, t.username), c.client_id, COALESCE(?, c.name), ?, ?, ?, ?, ?, ?, ?
    FROM (SELECT 1) LEFT JOIN user u ON u.id = ? LEFT JOIN user t ON t.id = ? AND ? = 'user'
    LEFT JOIN oauth_client c ON c.client_id = COALESCE(?,
      (SELECT client_id FROM authorization_request WHERE id = ?),
      (SELECT client_id FROM oauth_client WHERE id = ?),
      (SELECT client_id FROM oauth_client WHERE client_id = ? AND ? = 'app'))
    ON CONFLICT(event_key) DO NOTHING`)
    .bind(randomId('au_'), action, actorId, targetId, Date.now(), options.actorType ?? (actorId ? 'user' : 'unknown'),
      targetType, options.targetName ?? null, options.appName ?? null, options.loginMethod ?? null, options.trustLevel ?? null,
      options.result ?? 'success', options.reason ?? null, options.requestId ?? null, safeChanges(options.changes), options.eventKey ?? null,
      actorId, targetId, targetType, options.clientId ?? null, options.requestId ?? null, targetId, targetId, targetType);
}
export async function audit(db: D1Database, action: string, actorId: string | null, targetId: string | null, options?: AuditOptions) {
  await auditStatement(db, action, actorId, targetId, options).run();
}

/** Use in the same batch, before the guarded terminal transition. Conditions are internal SQL only. */
export function authorizationOutcomeStatement(db: D1Database, source: 'request' | 'grant', condition: string, bindings: (string | number | null)[], result: AuditResult, reason: string | null = null) {
  const requestId = source === 'request' ? 'r.id' : 'g.request_id';
  const eventId = source === 'request' ? 'r.auth_event_id' : 'g.auth_event_id';
  const clientId = source === 'request' ? 'r.client_id' : 'g.client_id';
  const eventKey = (source === 'request' ? "'authorization:' || r.id" : "'authorization:' || COALESCE(g.request_id, 'grant:' || g.code_id)") + (result === 'pending' ? " || ':code'" : '');
  const from = source === 'request' ? 'authorization_request r' : 'grant_ledger g LEFT JOIN authorization_request r ON r.id = g.request_id';
  const action = result === 'success' ? 'authorization.issued' : result === 'pending' ? 'authorization.code_created' : `authorization.${result}`;
  return db.prepare(`INSERT INTO audit
    (id, action, actor_id, target_id, created_at, actor_type, actor_linuxdo_id, actor_username, actor_name,
     target_type, target_name, client_id, app_name, login_method, trust_level, result, reason, request_id, event_key)
    SELECT 'au_' || lower(hex(randomblob(16))), ?, e.user_id, c.id, ?, CASE WHEN e.user_id IS NULL THEN 'unknown' ELSE 'user' END,
      u.linuxdo_id, COALESCE(json_extract(e.profile, '$.username'), u.username), COALESCE(json_extract(e.profile, '$.name'), u.name),
      'app', c.name, c.client_id, c.name, COALESCE(e.login_method,
        (SELECT method FROM connect_transaction t WHERE t.request_id = ${requestId} AND t.status IN ('pending','consumed') ORDER BY t.created_at DESC LIMIT 1)),
      e.trust_level, ?, ?, ${requestId}, ${eventKey}
    FROM ${from} JOIN oauth_client c ON c.client_id = ${clientId}
    LEFT JOIN auth_event e ON e.id = ${eventId} LEFT JOIN user u ON u.id = e.user_id
    WHERE ${condition} ON CONFLICT(event_key) DO NOTHING`).bind(action, Date.now(), result, reason, ...bindings);
}

const filterSchema = z.object({
  cursor: z.string().max(512).optional(), user: z.string().trim().max(128).optional(), client_id: z.string().max(256).optional(),
  action: z.string().max(80).optional(), result: z.enum(['success', 'denied', 'failed', 'canceled', 'expired', 'pending']).optional(),
  from: z.iso.datetime({ offset: true }).optional(), to: z.iso.datetime({ offset: true }).optional(), limit: z.coerce.number().int().min(1).max(100).default(50),
});
export function parseAuditFilters(value: Record<string, string>): AuditFilters {
  const result = filterSchema.safeParse(value);
  invariant(result.success, 400, 'invalid_filters', '请检查筛选条件');
  return result.data;
}

type AuditRow = Omit<AuditEntry, 'created_at' | 'changes'> & { created_at: number; changes: string | null };
export async function queryAudit(db: D1Database, input: AuditFilters, clientId?: string): Promise<AuditPage> {
  const filters = filterSchema.parse(input);
  const conditions = ['a.created_at >= ?'];
  const binds: (string | number)[] = [Date.now() - LOG_RETENTION_MS];
  if (clientId) {
    conditions.push("a.client_id = ? AND a.action IN ('authorization.issued','authorization.denied','authorization.failed','authorization.canceled','authorization.expired')");
    binds.push(clientId);
  } else if (filters.client_id) { conditions.push('a.client_id = ?'); binds.push(filters.client_id); }
  if (filters.user) {
    conditions.push('(a.actor_id = ? OR COALESCE(a.actor_username, u.username) LIKE ? ESCAPE \'\\\' OR CAST(COALESCE(a.actor_linuxdo_id, u.linuxdo_id) AS TEXT) = ?)');
    const term = filters.user.replaceAll('\\', '\\\\').replaceAll('%', '\\%').replaceAll('_', '\\_');
    binds.push(filters.user, `%${term}%`, filters.user);
  }
  if (filters.action) { conditions.push('a.action = ?'); binds.push(filters.action); }
  if (filters.result) { conditions.push('a.result = ?'); binds.push(filters.result); }
  for (const [key, op] of [['from', '>='], ['to', '<=']] as const) {
    if (filters[key]) { conditions.push(`a.created_at ${op} ?`); binds.push(Date.parse(filters[key])); }
  }
  if (filters.cursor) {
    let cursor: unknown;
    try { cursor = JSON.parse(atob(filters.cursor)); } catch { invariant(false, 400, 'invalid_cursor', '分页信息已失效，请重新加载'); }
    const parsed = z.tuple([z.number().int().nonnegative(), z.string().min(1).max(128)]).safeParse(cursor);
    invariant(parsed.success, 400, 'invalid_cursor', '分页信息已失效，请重新加载');
    conditions.push('(a.created_at < ? OR (a.created_at = ? AND a.id < ?))');
    binds.push(parsed.data[0], parsed.data[0], parsed.data[1]);
  }
  const result = await db.prepare(`SELECT a.id, a.action, a.actor_id, a.target_id, a.created_at,
    CASE WHEN a.actor_id IS NOT NULL THEN 'user' ELSE a.actor_type END AS actor_type,
    COALESCE(a.actor_linuxdo_id, u.linuxdo_id) AS actor_linuxdo_id,
    COALESCE(a.actor_username, u.username) AS actor_username, COALESCE(a.actor_name, u.name) AS actor_name,
    a.target_type, a.target_name, a.client_id, a.app_name, a.login_method, a.trust_level,
    a.result, a.reason, a.request_id, a.changes, a.subject_user_id, a.subject_linuxdo_id, a.subject_username,
    a.upstream_client_id, a.connect_transaction_id, a.identity_confirmed, a.verification_purpose
    FROM audit a LEFT JOIN user u ON u.id = a.actor_id
    WHERE ${conditions.join(' AND ')} ORDER BY a.created_at DESC, a.id DESC LIMIT ?`).bind(...binds, filters.limit + 1).all<AuditRow>();
  const rows = result.results.slice(0, filters.limit);
  const last = rows.at(-1);
  return { entries: rows.map((row) => ({ ...row, identity_confirmed: Boolean(row.identity_confirmed), created_at: new Date(row.created_at).toISOString(), changes: row.changes ? JSON.parse(row.changes) as AuditChanges : null })),
    next_cursor: result.results.length > filters.limit && last ? btoa(JSON.stringify([last.created_at, last.id])) : null };
}
