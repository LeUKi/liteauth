import type { AdminConnectFilters, AuditResult, ConnectRecord } from '@liteauth/contracts';
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { ArrowLeft, ChevronRight } from 'lucide-react';
import { useState } from 'react';
import type { FormEvent } from 'react';
import { Button, Confirm, CopyButton, Field, Loading, Notice, Page, PageHeading, Panel, QueryError, ValueRow, formatRecordDate } from '../components/ui';
import { api, errorMessage, queryKeys } from '../lib/api';
import { loginMethodName, reasonName, resultNames } from '../lib/records';
import { useSession } from '../lib/session';
import { adminUserDetailRoute } from '../router';

function ConnectRecordRow({ entry }: { entry: ConnectRecord }) {
  const mismatch = entry.identity_confirmed && entry.subject_linuxdo_id !== null && entry.actor_linuxdo_id !== null && entry.subject_linuxdo_id !== entry.actor_linuxdo_id;
  return <tr>
    <td><div className="table-cell-stack"><time dateTime={entry.created_at}>{formatRecordDate(entry.created_at)}</time>{(entry.connect_transaction_id || entry.request_id) && <details className="audit-reference"><summary>关联请求</summary>{entry.connect_transaction_id && <div>Connect：<code>{entry.connect_transaction_id}</code></div>}{entry.request_id && <div>应用授权：<code>{entry.request_id}</code></div>}</details>}</div></td>
    <td><div className="table-cell-stack"><span>{entry.subject_username ? `@${entry.subject_username}` : '—'}</span>{entry.subject_linuxdo_id && <span className="muted">Linux.do ID {entry.subject_linuxdo_id}</span>}</div></td>
    <td><div className="table-cell-stack"><span>{entry.identity_confirmed && entry.actor_username ? `@${entry.actor_username}` : '身份未确认'}</span>{entry.identity_confirmed && entry.actor_linuxdo_id && <span className="muted">Linux.do ID {entry.actor_linuxdo_id}</span>}{entry.identity_confirmed && entry.actor_username && <span className="muted">{mismatch ? '身份不一致' : '身份已验证'}</span>}</div></td>
    <td><div className="table-cell-stack"><span>{entry.verification_purpose === 'credential_validation' ? '验证 Connect 密钥' : entry.verification_purpose === 'login' ? '登录' : '验证'}</span><span className="muted">{loginMethodName(entry.login_method)}</span>{entry.trust_level !== null && <span className="muted">{entry.trust_level} 级</span>}</div></td>
    <td>{entry.upstream_client_id ? <div className="inline-copy"><code>{entry.upstream_client_id}</code><CopyButton value={entry.upstream_client_id} label="复制验证记录 Connect Client ID" /></div> : '—'}</td>
    <td><div className="table-cell-stack"><span className={`badge ${entry.result === 'success' ? 'badge-green' : ''}`}>{resultNames[entry.result]}</span>{entry.reason && <span>{reasonName(entry.reason)}</span>}</div></td>
  </tr>;
}

function ConnectRecords({ userId }: { userId: string }) {
  const [draft, setDraft] = useState({ upstream_client_id: '', result: '' as AuditResult | '', from: '', to: '' });
  const [filters, setFilters] = useState<AdminConnectFilters>({});
  const [invalidRange, setInvalidRange] = useState(false);
  const records = useInfiniteQuery({
    queryKey: queryKeys.adminConnectRecords(userId, filters),
    queryFn: ({ pageParam, signal }) => api.admin.connectRecords(userId, { ...filters, cursor: pageParam }, signal),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (page) => page.next_cursor ?? undefined,
  });
  const entries = records.data?.pages.flatMap((page) => page.entries) ?? [];
  function filter(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const from = draft.from ? new Date(`${draft.from}:00+08:00`) : undefined;
    const to = draft.to ? new Date(`${draft.to}:00+08:00`) : undefined;
    if ((from && Number.isNaN(from.valueOf())) || (to && Number.isNaN(to.valueOf())) || (from && to && from > to)) { setInvalidRange(true); return; }
    setInvalidRange(false);
    setFilters({
      ...(draft.upstream_client_id.trim() ? { upstream_client_id: draft.upstream_client_id.trim() } : {}),
      ...(draft.result ? { result: draft.result } : {}), ...(from ? { from: from.toISOString() } : {}), ...(to ? { to: to.toISOString() } : {}),
    });
  }
  return <Panel><div className="panel-heading"><h2>Connect 验证记录</h2><span className="muted table-period">最近七天 · 北京时间（UTC+8）</span></div>
    <form className="record-filters connect-record-filters" onSubmit={filter}>
      <Field label="Connect Client ID" htmlFor="connect-record-client"><input id="connect-record-client" autoComplete="off" spellCheck={false} value={draft.upstream_client_id} onChange={(event) => setDraft({ ...draft, upstream_client_id: event.target.value })} /></Field>
      <Field label="结果" htmlFor="connect-record-result"><select id="connect-record-result" value={draft.result} onChange={(event) => setDraft({ ...draft, result: event.target.value as AuditResult | '' })}><option value="">全部结果</option>{Object.entries(resultNames).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></Field>
      <Field label="开始时间" htmlFor="connect-record-from"><input id="connect-record-from" type="datetime-local" value={draft.from} onChange={(event) => setDraft({ ...draft, from: event.target.value })} /></Field>
      <Field label="结束时间" htmlFor="connect-record-to"><input id="connect-record-to" type="datetime-local" value={draft.to} onChange={(event) => setDraft({ ...draft, to: event.target.value })} /></Field>
      <Button variant="secondary" type="submit">筛选</Button>
    </form>
    {invalidRange && <Notice>请填写有效的时间范围，结束时间不能早于开始时间</Notice>}
    {records.isPending ? <Loading /> : records.isError && !records.data ? <div className="stack"><Notice>{errorMessage(records.error)}</Notice><Button variant="secondary" onClick={() => void records.refetch()}>重试</Button></div> : entries.length === 0 ? <div className="empty-state">暂无验证记录</div> : <>
      <div className="table-scroll" role="region" aria-label="Connect 验证记录" tabIndex={0}><table className="data-table connect-records-table"><thead><tr><th>时间</th><th>目标账号</th><th>实际返回账号</th><th>用途 / 登录方式</th><th>Connect Client ID</th><th>结果</th></tr></thead><tbody>{entries.map((entry) => <ConnectRecordRow key={entry.id} entry={entry} />)}</tbody></table></div>
      {records.isFetchNextPageError && <Notice>读取更多验证记录失败，请重试</Notice>}
      {records.hasNextPage && <div className="record-pagination"><Button variant="secondary" busy={records.isFetchingNextPage} onClick={() => void records.fetchNextPage()}>加载更多记录</Button></div>}
    </>}
  </Panel>;
}

function UserApps({ userId }: { userId: string }) {
  const apps = useInfiniteQuery({
    queryKey: queryKeys.adminUserApps(userId),
    queryFn: ({ pageParam, signal }) => api.admin.userApps(userId, { cursor: pageParam }, signal),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (page) => page.next_cursor ?? undefined,
  });
  const entries = apps.data?.pages.flatMap((page) => page.apps) ?? [];
  return <Panel><div className="panel-heading"><h2>创建的 LiteAuth 应用</h2></div>{apps.isPending ? <Loading /> : apps.isError && !apps.data ? <div className="stack"><Notice>{errorMessage(apps.error)}</Notice><Button variant="secondary" onClick={() => void apps.refetch()}>重试</Button></div> : entries.length === 0 ? <div className="empty-state">尚未创建应用</div> : <>
    <div className="user-apps">{entries.map((app) => <Link key={app.id} className="user-app-link" to="/apps/$id" params={{ id: app.id }}><div className="app-row-content"><span className="app-row-name">{app.name}</span><code className="muted client-id">{app.client_id}</code><div className="app-row-badges"><span className="badge">{app.client_type === 'confidential' ? '服务端应用' : '浏览器 / 原生应用'}</span><span className="badge">最低 {app.min_trust_level} 级</span><span className={`badge ${app.lite_only ? 'badge-green' : ''}`}>{app.lite_only ? '仅 Lite' : '面向全部老友'}</span>{app.disabled && <span className="badge">已停用</span>}</div></div><ChevronRight size={18} className="muted" aria-hidden="true" /></Link>)}</div>
    {apps.isFetchNextPageError && <Notice>读取更多应用失败，请重试</Notice>}
    {apps.hasNextPage && <div className="record-pagination"><Button variant="secondary" busy={apps.isFetchingNextPage} onClick={() => void apps.fetchNextPage()}>加载更多应用</Button></div>}
  </>}</Panel>;
}

export function AdminUserDetailPage() {
  const { userId } = adminUserDetailRoute.useParams();
  const session = useSession();
  const queryClient = useQueryClient();
  const detail = useQuery({ queryKey: queryKeys.adminUser(userId), queryFn: ({ signal }) => api.admin.user(userId, signal) });
  const user = detail.data?.user;
  const disable = useMutation({ mutationFn: () => api.admin.disableUser(userId, !user?.disabled), onSuccess: () => queryClient.invalidateQueries({ queryKey: ['admin'] }) });
  return <Page><PageHeading title={user ? `@${user.username}` : '账号详情'} back={<Link to="/admin" className="back-link"><ArrowLeft size={15} />管理账号</Link>} />{detail.isPending ? <Loading /> : detail.isError ? <QueryError error={detail.error} retry={detail.refetch} /> : user && <div className="stack section-stack">
    <Panel><div className="panel-heading"><h2>账号资料</h2><div className="app-row-badges">{user.is_admin && <span className="badge">管理员</span>}<span className={`badge ${user.disabled ? '' : 'badge-green'}`}>{user.disabled ? '已停用' : '正常'}</span>{user.official_verified_at && <span className="badge">仅可非 Lite 登录</span>}</div></div>
      <ValueRow label="Linux.do 用户名" value={`@${user.username}`} />
      <ValueRow label="显示名称" value={user.name || user.username} />
      <ValueRow label="Linux.do ID" value={String(user.linuxdo_id)} copy />
      <ValueRow label="LiteAuth ID" value={user.id} copy />
      <ValueRow label="Connect Client ID" value={user.connect_client_id ?? '未绑定'} copy={Boolean(user.connect_client_id)} />
      <ValueRow label="最近验证等级" value={user.last_trust_level === null ? '未验证' : `${user.last_trust_level} 级`} />
      <ValueRow label="最近登录方式" value={loginMethodName(user.last_login_method)} />
      <ValueRow label="最近验证时间" value={user.last_authenticated_at ? `${formatRecordDate(user.last_authenticated_at)}（UTC+8）` : '未验证'} />
      {user.official_verified_at && <ValueRow label="首次非 Lite 确认" value={`${formatRecordDate(user.official_verified_at)}（UTC+8）`} />}
      <ValueRow label="创建时间" value={`${formatRecordDate(user.created_at)}（UTC+8）`} />
      <div className="panel-footer"><Confirm title={user.disabled ? '启用账号？' : '停用账号？'} description={user.disabled ? '此账号将恢复登录。' : '此账号将无法继续登录和授权。'} confirmLabel={user.disabled ? '启用' : '停用'} onConfirm={() => disable.mutateAsync()}><Button variant="secondary" disabled={user.id === session.data?.user?.id || disable.isPending}>{user.disabled ? '启用账号' : '停用账号'}</Button></Confirm></div>
    </Panel>
    <Panel><div className="panel-heading"><h2>Connect 绑定历史</h2><span className="muted table-period">北京时间（UTC+8）</span></div>{detail.data.credentials.length === 0 ? <div className="empty-state">未绑定 Connect 应用</div> : <div className="table-scroll" role="region" aria-label="Connect 绑定历史" tabIndex={0}><table className="data-table credential-history-table"><thead><tr><th>Connect Client ID</th><th>状态</th><th>首次绑定</th><th>更新时间</th></tr></thead><tbody>{detail.data.credentials.map((credential) => <tr key={credential.client_id}><td><div className="inline-copy"><code>{credential.client_id}</code><CopyButton value={credential.client_id} label="复制历史 Connect Client ID" /></div></td><td><span className={`badge ${credential.status === 'active' ? 'badge-green' : ''}`}>{credential.status === 'active' ? '有效' : '已撤销'}</span></td><td><time dateTime={credential.created_at}>{formatRecordDate(credential.created_at)}</time></td><td><time dateTime={credential.updated_at}>{formatRecordDate(credential.updated_at)}</time></td></tr>)}</tbody></table></div>}</Panel>
    <ConnectRecords userId={userId} />
    <UserApps userId={userId} />
  </div>}</Page>;
}
