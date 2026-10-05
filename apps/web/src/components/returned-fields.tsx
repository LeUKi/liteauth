import { Panel } from './ui';

type FieldRow = { name: string; description: string; source: string; type: string; values: string; condition: string };
const protocol = '协议字段';
const generated = 'LiteAuth 生成';
const upstream = '上游透传';
const identityFields: FieldRow[] = [
  { name: 'id', description: 'Linux.do 用户 ID', source: upstream, type: 'integer', values: '正整数', condition: '用户信息 / ID Token' },
  { name: 'username', description: 'Linux.do 用户名', source: upstream, type: 'string', values: '认证时的用户名', condition: '用户信息 / ID Token' },
  { name: 'name', description: '显示名称', source: '上游透传 / 标准映射', type: 'string', values: '显示名称', condition: '普通 OAuth 用户信息；OIDC UserInfo 需 profile' },
  { name: 'avatar_url', description: '头像地址', source: upstream, type: 'string | null', values: 'URL 或 null', condition: '用户信息 / ID Token' },
  { name: 'trust_level', description: '本次认证时的等级', source: upstream, type: 'integer', values: '0 / 1 / 2 / 3 / 4', condition: '用户信息 / ID Token' },
  { name: 'active', description: '账号是否活跃', source: upstream, type: 'boolean', values: 'true / false', condition: '用户信息 / ID Token' },
  { name: 'silenced', description: '账号是否被禁言', source: upstream, type: 'boolean', values: 'true / false', condition: '用户信息 / ID Token' },
  { name: 'sub', description: 'LiteAuth 稳定主体标识', source: '标准映射', type: 'string', values: '与 liteauth_user_id 对应', condition: '用户信息 / ID Token' },
  { name: 'liteauth_user_id', description: 'LiteAuth 账号 ID', source: generated, type: 'string', values: 'LiteAuth 账号标识', condition: '用户信息 / ID Token' },
  { name: 'login_method', description: '本次授权的实际登录方式', source: generated, type: 'string', values: 'official_connect / lite_self_app', condition: '用户信息 / ID Token' },
  { name: 'auth_source', description: '账号来源', source: generated, type: 'string', values: 'linuxdo', condition: '用户信息 / ID Token' },
  { name: 'upstream_client_id', description: '本次认证所用 Connect 应用 ID', source: generated, type: 'string', values: '平台应用或用户自有应用的 ID', condition: '用户信息 / ID Token' },
  { name: 'picture', description: '标准头像声明', source: '标准映射', type: 'string', values: '头像 URL，有值时返回', condition: 'OIDC UserInfo，需 profile' },
  { name: 'given_name / family_name', description: '按显示名称映射的名字 / 姓氏', source: '标准映射', type: 'string', values: '有对应名称时返回', condition: 'OIDC UserInfo，需 profile' },
];
const groups: { title: string; description: string; rows: FieldRow[]; open?: boolean }[] = [
  {
    title: '用户信息', open: true,
    description: '普通 OAuth 用户信息需要 profile；OIDC UserInfo 需要 openid。登录方式与认证等级来自本次授权，不会随之后的登录改变。',
    rows: identityFields,
  },
  {
    title: '授权回调', description: '回调 URL 返回授权结果。用户资料通过用户信息接口或 ID Token 获取。',
    rows: [
      { name: 'code', description: '用于兑换令牌的一次性授权码', source: protocol, type: 'string', values: '有效期 2 分钟', condition: '授权成功' },
      { name: 'state', description: '原样返回请求中的 state', source: '请求透传', type: 'string', values: '由接入网站生成', condition: '请求提供 state 时' },
      { name: 'iss', description: '授权服务器标识', source: protocol, type: 'string', values: new URL('/api/auth', window.location.origin).href, condition: '授权成功' },
      { name: 'error', description: '授权失败原因', source: protocol, type: 'string', values: '如 access_denied、invalid_request', condition: '可安全回调的授权失败' },
      { name: 'error_description', description: '错误补充说明', source: protocol, type: 'string', values: '错误说明文本', condition: '授权失败，有补充说明时' },
    ],
  },
  {
    title: 'Token 响应', description: '向 Token 地址兑换授权码后返回。当前不签发刷新令牌。',
    rows: [
      { name: 'access_token', description: '访问令牌', source: protocol, type: 'string', values: '不透明令牌', condition: '兑换成功' },
      { name: 'token_type', description: '访问令牌类型', source: protocol, type: 'string', values: 'Bearer', condition: '兑换成功' },
      { name: 'expires_in', description: '访问令牌剩余有效期', source: protocol, type: 'integer', values: '秒，通常为 3600', condition: '兑换成功' },
      { name: 'expires_at', description: '访问令牌到期时间', source: protocol, type: 'integer', values: 'Unix 时间戳，秒', condition: '兑换成功' },
      { name: 'scope', description: '授予的权限', source: protocol, type: 'string', values: 'profile / openid，空格分隔', condition: '兑换成功' },
      { name: 'id_token', description: '签名身份令牌', source: protocol, type: 'string', values: 'RS256 签名 JWT，有效期 10 分钟', condition: '请求包含 openid' },
    ],
  },
  {
    title: 'ID Token 标准声明', description: '请求 openid 时返回；还包括用户信息表中标注适用的认证字段。接入网站应使用 OpenID 配置与 JWKS 验证签名及声明。',
    rows: [
      { name: 'iss', description: '签发者', source: protocol, type: 'string', values: new URL('/api/auth', window.location.origin).href, condition: 'ID Token' },
      { name: 'sub', description: 'LiteAuth 稳定主体标识', source: '标准映射', type: 'string', values: '与用户信息的 sub 一致', condition: 'ID Token' },
      { name: 'aud', description: '接收此令牌的应用', source: protocol, type: 'string', values: '当前应用的 Client ID', condition: 'ID Token' },
      { name: 'iat / exp', description: '签发时间 / 到期时间', source: protocol, type: 'integer', values: 'Unix 时间戳，秒', condition: 'ID Token' },
      { name: 'auth_time', description: '本次认证时间', source: protocol, type: 'integer', values: 'Unix 时间戳，秒', condition: 'ID Token，有认证时间时' },
      { name: 'nonce', description: '原样返回请求中的 nonce', source: '请求透传', type: 'string', values: '由接入网站生成', condition: '请求提供 nonce 时' },
      { name: 'at_hash', description: '访问令牌摘要', source: protocol, type: 'string', values: '按签名算法计算', condition: 'ID Token，与访问令牌一起签发' },
      { name: 'acr', description: '认证上下文', source: protocol, type: 'string', values: '0；不代表 Linux.do 用户等级', condition: 'ID Token' },
    ],
  },
];

export function ReturnedFields() {
  return <Panel><div className="panel-heading"><h2>返回字段</h2></div><div className="protocol-groups">{groups.map((group) => <details className="protocol-group" key={group.title} open={group.open}><summary>{group.title}</summary><p className="muted field-table-description">{group.description}</p><div className="table-scroll" role="region" aria-label={group.title} tabIndex={0}><table className="data-table field-table"><thead><tr><th>字段</th><th>含义</th><th>来源</th><th>类型</th><th>可能值</th><th>返回条件</th></tr></thead><tbody>{group.rows.map((row) => <tr key={row.name}><td><code>{row.name}</code></td><td>{row.description}</td><td>{row.source}</td><td><code>{row.type}</code></td><td>{row.values}</td><td>{row.condition}</td></tr>)}</tbody></table></div></details>)}</div></Panel>;
}
