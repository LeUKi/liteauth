import type { AuditChanges, AuditResult, LoginMethod } from '@liteauth/contracts';

export const resultNames: Record<AuditResult, string> = {
  success: '成功', denied: '拒绝', failed: '失败', canceled: '已取消', expired: '已过期', pending: '进行中',
};

export const actionNames: Record<string, string> = {
  'login.official': '非 Lite 用户登录', 'login.lite': 'Lite 用户登录', 'login.failed': '登录失败',
  'account.login': '账号登录', 'account.login_failed': '账号登录失败',
  'connect.verification': 'Connect 验证',
  'logout': '退出登录', 'session.logout': '退出登录',
  'credential.bound': '绑定 Connect 密钥', 'credential.updated': '更新 Connect 密钥', 'credential.deleted': '删除 Connect 密钥', 'credential.verified': '验证 Connect 密钥',
  'app.created': '创建应用', 'app.updated': '更新应用', 'app.deleted': '删除应用',
  'app.secret_rotated': '轮换应用密钥', 'app.disabled': '停用应用', 'app.enabled': '启用应用',
  'user.disabled': '停用账号', 'user.enabled': '启用账号',
  'consent.accepted': '允许授权', 'consent.denied': '拒绝授权',
  'authorization.code_created': '生成授权码', 'authorization.issued': '登录应用',
  'authorization.denied': '拒绝登录应用', 'authorization.failed': '登录应用失败',
  'authorization.canceled': '取消登录应用', 'authorization.expired': '登录应用请求过期',
};

const reasonNames: Record<string, string> = {
  access_denied: '用户拒绝', consent_denied: '用户拒绝', user_denied: '用户拒绝',
  trust_level_required: '等级不足', min_trust_level_changed: '最低等级已调整', lite_required: '仅允许 Lite 用户登录',
  policy_changed: '应用要求已更新', app_disabled: '应用已停用', app_deleted: '应用已删除',
  user_disabled: '账号已停用', credential_deleted: 'Connect 密钥已删除', credential_revoked: 'Connect 密钥已撤销',
  account_changed: '账号信息已更新',
  credential_invalid: 'Connect 密钥无效', identity_mismatch: '登录账号不一致', user_mismatch: '登录账号不一致',
  credential_changed: '账号信息已更新，请重新开始登录',
  invalid_state: '登录请求无效', invalid_grant: '授权无效', request_expired: '登录请求过期',
  expired_request: '登录请求过期', code_expired: '授权码过期', authorization_failed: '授权未完成',
  expired: '已过期', logout: '退出登录', account_disabled: '账号已停用',
};

export function reasonName(reason: string | null): string {
  return reason ? reasonNames[reason] ?? reason : '—';
}

export function loginMethodName(method: LoginMethod | null): string {
  return method === 'official_connect' ? '非 Lite 用户登录' : method === 'lite_self_app' ? 'Lite 用户登录' : '—';
}

const changeNames: Record<string, string> = {
  name: '应用名称', redirect_uris: '回调地址', lite_only: '仅允许 Lite 用户登录', min_trust_level: '最低等级', pkce_required: '启用 PKCE', disabled: '停用状态',
};
function changeValue(value: unknown): string {
  return Array.isArray(value) ? value.join('、') : typeof value === 'boolean' ? (value ? '开启' : '关闭') : value === null ? '—' : String(value);
}
export function describeChanges(changes: AuditChanges): string[] {
  return Object.entries(changes).map(([field, value]) => `${changeNames[field] ?? field}：${changeValue(value.before)} → ${changeValue(value.after)}`);
}
