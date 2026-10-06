import type { AdminUserFilters, AdminUserSummary } from '@liteauth/contracts';
import { useInfiniteQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { useState } from 'react';
import type { FormEvent } from 'react';
import { api, errorMessage, queryKeys } from '../lib/api';
import { loginMethodName } from '../lib/records';
import { useSession } from '../lib/session';
import { Button, Confirm, CopyButton, Field, Loading, Notice, Panel, formatRecordDate } from './ui';

function UserRow({ user, currentUserId, pending, onDisable }: { user: AdminUserSummary; currentUserId?: string; pending: boolean; onDisable: () => Promise<unknown> }) {
  return <tr>
    <td><div className="table-cell-stack"><Link className="user-detail-link" to="/admin/users/$userId" params={{ userId: user.id }}>@{user.username}</Link><span className="muted">{user.name || user.username}</span><span className="muted">Linux.do ID {user.linuxdo_id}</span></div></td>
    <td>{user.connect_client_id ? <div className="inline-copy"><code>{user.connect_client_id}</code><CopyButton value={user.connect_client_id} label={`复制 ${user.username} 的 Connect Client ID`} /></div> : <span className="muted">未绑定</span>}</td>
    <td><div className="table-cell-stack"><span>{user.last_trust_level === null ? '未验证' : `${user.last_trust_level} 级`}</span><span className="muted">{loginMethodName(user.last_login_method)}</span>{user.last_authenticated_at && <time dateTime={user.last_authenticated_at}>{formatRecordDate(user.last_authenticated_at)}</time>}</div></td>
    <td><div className="table-cell-stack">{user.is_admin && <span className="badge">管理员</span>}<span className={`badge ${user.disabled ? '' : 'badge-green'}`}>{user.disabled ? '已停用' : '正常'}</span>{user.official_verified_at && <><span className="badge">仅可非 Lite 登录</span><time className="muted" dateTime={user.official_verified_at}>首次确认：{formatRecordDate(user.official_verified_at)}</time></>}</div></td>
    <td><Confirm title={user.disabled ? '启用账号？' : '停用账号？'} description={user.disabled ? '此账号将恢复登录。' : '此账号将无法继续登录和授权。'} confirmLabel={user.disabled ? '启用' : '停用'} onConfirm={onDisable}><Button variant="secondary" disabled={user.id === currentUserId || pending}>{user.disabled ? '启用' : '停用'}</Button></Confirm></td>
  </tr>;
}

export function AdminUsers() {
  const session = useSession();
  const queryClient = useQueryClient();
  const [q, setQ] = useState('');
  const [status, setStatus] = useState('');
  const [filters, setFilters] = useState<AdminUserFilters>({});
  const users = useInfiniteQuery({
    queryKey: queryKeys.adminUsers(filters),
    queryFn: ({ pageParam, signal }) => api.admin.users({ ...filters, cursor: pageParam }, signal),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (page) => page.next_cursor ?? undefined,
  });
  const disable = useMutation({ mutationFn: ({ id, disabled }: { id: string; disabled: boolean }) => api.admin.disableUser(id, disabled), onSuccess: () => queryClient.invalidateQueries({ queryKey: ['admin'] }) });
  const entries = users.data?.pages.flatMap((page) => page.users) ?? [];
  function filter(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFilters({ ...(q.trim() ? { q: q.trim() } : {}), ...(status ? { disabled: status === 'disabled' } : {}) });
  }
  return <Panel><div className="panel-heading"><h2>账号</h2><span className="muted table-period">验证时间为北京时间（UTC+8）</span></div><form className="record-filters" onSubmit={filter}>
    <Field label="搜索账号" htmlFor="users-search"><input id="users-search" placeholder="用户名、用户 ID 或 Connect Client ID" value={q} onChange={(event) => setQ(event.target.value)} /></Field>
    <Field label="状态" htmlFor="users-status"><select id="users-status" value={status} onChange={(event) => setStatus(event.target.value)}><option value="">全部状态</option><option value="active">正常</option><option value="disabled">已停用</option></select></Field>
    <Button type="submit" variant="secondary">搜索</Button>
  </form>{users.isPending ? <Loading /> : users.isError && !users.data ? <div className="stack"><Notice>{errorMessage(users.error)}</Notice><Button variant="secondary" onClick={() => void users.refetch()}>重试</Button></div> : entries.length === 0 ? <div className="empty-state">暂无账号</div> : <>
    <div className="table-scroll" role="region" aria-label="管理员账号列表" tabIndex={0}><table className="data-table admin-users-table"><thead><tr><th>账号</th><th>Connect Client ID</th><th>最近验证</th><th>状态</th><th>操作</th></tr></thead><tbody>{entries.map((user) => <UserRow key={user.id} user={user} currentUserId={session.data?.user?.id} pending={disable.isPending} onDisable={() => disable.mutateAsync({ id: user.id, disabled: !user.disabled })} />)}</tbody></table></div>
    {users.isFetchNextPageError && <Notice>读取更多账号失败，请重试</Notice>}
    {users.hasNextPage && <div className="record-pagination"><Button variant="secondary" busy={users.isFetchingNextPage} onClick={() => void users.fetchNextPage()}>加载更多</Button></div>}
  </>}</Panel>;
}
