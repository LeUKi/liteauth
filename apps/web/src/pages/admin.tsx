import type { AuditEntry, AuditFilters, AuditResult } from '@liteauth/contracts';
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import type { FormEvent } from 'react';
import { AdminUsers } from '../components/admin-users';
import { Button, Confirm, Field, Loading, Notice, Page, PageHeading, Panel, QueryError, formatRecordDate } from '../components/ui';
import { api, queryKeys } from '../lib/api';
import { actionNames, describeChanges, loginMethodName, reasonName, resultNames } from '../lib/records';

type Tab = 'users' | 'apps' | 'audit';
const targetNames: Record<string, string> = { user: '账号', app: '应用', credential: 'Connect 密钥', authorization: '应用授权', session: '会话', request: '登录请求' };

function AuditRow({ entry }: { entry: AuditEntry }) {
  const unconfirmed = entry.action === 'connect.verification' && entry.identity_confirmed === false;
  const actor = !unconfirmed && entry.actor_username ? `@${entry.actor_username}` : entry.actor_type === 'system' ? '系统' : '身份未确认';
  const mismatch = entry.identity_confirmed === true && entry.subject_linuxdo_id != null && entry.actor_linuxdo_id !== null && entry.subject_linuxdo_id !== entry.actor_linuxdo_id;
  return <tr>
    <td><time dateTime={entry.created_at}>{formatRecordDate(entry.created_at)}</time></td>
    <td>{actionNames[entry.action] ?? entry.action}</td>
    <td><div className="table-cell-stack"><span>{actor}</span>{!unconfirmed && entry.actor_linuxdo_id && <span className="muted">Linux.do ID {entry.actor_linuxdo_id}</span>}{!unconfirmed && entry.actor_id && <code className="muted">{entry.actor_id}</code>}</div></td>
    <td><div className="table-cell-stack"><span>{entry.target_type ? targetNames[entry.target_type] ?? entry.target_type : '—'}{entry.target_name ? ` · ${entry.target_name}` : ''}</span>{entry.target_id && <code className="muted">{entry.target_id}</code>}{entry.app_name && <span className="muted">应用：{entry.app_name}</span>}{entry.client_id && <code className="muted">{entry.client_id}</code>}</div></td>
    <td><span className={`badge ${entry.result === 'success' ? 'badge-green' : ''}`}>{resultNames[entry.result]}</span></td>
    <td><div className="table-cell-stack">{entry.reason && <span>{reasonName(entry.reason)}</span>}{mismatch && <span>身份不一致</span>}{entry.login_method && <span>{loginMethodName(entry.login_method)}{entry.trust_level !== null ? ` · ${entry.trust_level} 级` : ''}</span>}{(entry.subject_username || entry.subject_linuxdo_id) && <span>目标账号：{entry.subject_username ? `@${entry.subject_username}` : '名称未知'}{entry.subject_linuxdo_id ? ` · Linux.do ID ${entry.subject_linuxdo_id}` : ''}</span>}{entry.upstream_client_id && <div className="table-cell-stack"><span className="muted">Connect Client ID</span><code>{entry.upstream_client_id}</code></div>}{entry.changes && describeChanges(entry.changes).map((change, index) => <span key={index} className="audit-change">{change}</span>)}{(entry.request_id || entry.connect_transaction_id) && <details className="audit-reference"><summary>关联请求</summary>{entry.request_id && <code>{entry.request_id}</code>}{entry.connect_transaction_id && <div>Connect：<code>{entry.connect_transaction_id}</code></div>}</details>}{!entry.reason && !entry.login_method && !entry.changes && !entry.request_id && !entry.connect_transaction_id && !entry.subject_username && !entry.upstream_client_id && '—'}</div></td>
  </tr>;
}

function AuditRecords() {
  const [draft, setDraft] = useState({ user: '', client_id: '', action: '', result: '' as AuditResult | '', from: '', to: '' });
  const [filters, setFilters] = useState<AuditFilters>({});
  const [invalidRange, setInvalidRange] = useState(false);
  const audit = useInfiniteQuery({
    queryKey: queryKeys.adminAudit(filters),
    queryFn: ({ pageParam, signal }) => api.admin.audit({ ...filters, cursor: pageParam }, signal),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (page) => page.next_cursor ?? undefined,
  });
  const entries = audit.data?.pages.flatMap((page) => page.entries) ?? [];
  function filter(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const from = draft.from ? new Date(`${draft.from}:00+08:00`) : undefined;
    const to = draft.to ? new Date(`${draft.to}:00+08:00`) : undefined;
    if ((from && Number.isNaN(from.valueOf())) || (to && Number.isNaN(to.valueOf())) || (from && to && from > to)) { setInvalidRange(true); return; }
    setInvalidRange(false);
    setFilters({
      ...(draft.user.trim() ? { user: draft.user.trim() } : {}), ...(draft.client_id.trim() ? { client_id: draft.client_id.trim() } : {}),
      ...(draft.action ? { action: draft.action } : {}), ...(draft.result ? { result: draft.result } : {}),
      ...(from ? { from: from.toISOString() } : {}), ...(to ? { to: to.toISOString() } : {}),
    });
  }
  return <Panel><div className="panel-heading"><h2>全站操作记录</h2><span className="muted table-period">最近七天 · 北京时间（UTC+8）</span></div>
    <form className="record-filters audit-filters" onSubmit={filter}>
      <Field label="操作人" htmlFor="audit-user"><input id="audit-user" placeholder="用户名或用户 ID" value={draft.user} onChange={(event) => setDraft({ ...draft, user: event.target.value })} /></Field>
      <Field label="应用" htmlFor="audit-client"><input id="audit-client" placeholder="Client ID" value={draft.client_id} onChange={(event) => setDraft({ ...draft, client_id: event.target.value })} /></Field>
      <Field label="操作" htmlFor="audit-action"><select id="audit-action" value={draft.action} onChange={(event) => setDraft({ ...draft, action: event.target.value })}><option value="">全部操作</option>{Object.entries(actionNames).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></Field>
      <Field label="结果" htmlFor="audit-result"><select id="audit-result" value={draft.result} onChange={(event) => setDraft({ ...draft, result: event.target.value as AuditResult | '' })}><option value="">全部结果</option>{Object.entries(resultNames).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></Field>
      <Field label="开始时间" htmlFor="audit-from"><input id="audit-from" type="datetime-local" value={draft.from} onChange={(event) => setDraft({ ...draft, from: event.target.value })} /></Field>
      <Field label="结束时间" htmlFor="audit-to"><input id="audit-to" type="datetime-local" value={draft.to} onChange={(event) => setDraft({ ...draft, to: event.target.value })} /></Field>
      <Button type="submit" variant="secondary">筛选</Button>
    </form>
    {invalidRange && <Notice>请填写有效的时间范围，结束时间不能早于开始时间</Notice>}
    {audit.isPending ? <Loading /> : audit.isError && !audit.data ? <div className="stack"><Notice>{audit.error.message}</Notice><Button variant="secondary" onClick={() => void audit.refetch()}>重试</Button></div> : entries.length === 0 ? <div className="empty-state">暂无操作记录</div> : <>
      <div className="table-scroll" role="region" aria-label="全站操作记录" tabIndex={0}><table className="data-table audit-table"><thead><tr><th>时间</th><th>操作</th><th>操作人</th><th>目标</th><th>结果</th><th>详情</th></tr></thead><tbody>{entries.map((entry) => <AuditRow key={entry.id} entry={entry} />)}</tbody></table></div>
      {audit.isFetchNextPageError && <Notice>读取更多记录失败，请重试</Notice>}
      {audit.hasNextPage && <div className="record-pagination"><Button variant="secondary" busy={audit.isFetchingNextPage} onClick={() => void audit.fetchNextPage()}>加载更多</Button></div>}
    </>}
  </Panel>;
}

export function AdminPage() {
  const [tab, setTab] = useState<Tab>('users');
  const queryClient = useQueryClient();
  const apps = useQuery({ queryKey: queryKeys.adminApps, queryFn: ({ signal }) => api.admin.apps(signal), enabled: tab === 'apps' });
  const disableApp = useMutation({ mutationFn: ({ id, disabled }: { id: string; disabled: boolean }) => api.admin.disableApp(id, disabled), onSuccess: () => queryClient.invalidateQueries({ queryKey: ['admin'] }) });
  return <Page><PageHeading title="管理" /><div className="tabs" role="tablist" aria-label="管理分类">{(['users', 'apps', 'audit'] as const).map((value) => <button key={value} className={tab === value ? 'active' : ''} role="tab" id={`tab-${value}`} aria-selected={tab === value} aria-controls={`panel-${value}`} onClick={() => setTab(value)}>{value === 'users' ? '账号' : value === 'apps' ? '应用' : '操作记录'}</button>)}</div><div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>{tab === 'users' ? <AdminUsers /> : tab === 'audit' ? <AuditRecords /> : apps.isPending ? <Loading /> : apps.isError ? <QueryError error={apps.error} retry={apps.refetch} /> : <Panel className="admin-list">
    {apps.data?.apps.length ? apps.data.apps.map((app) => <div className="admin-row" key={app.id}><div className="admin-row-main"><strong>{app.name}</strong><code className="muted client-id">{app.client_id}</code><span className="muted">{app.client_type === 'confidential' ? '服务端应用' : '浏览器 / 原生应用'} · 最低 {app.min_trust_level} 级</span></div><div className="admin-row-controls">{app.disabled && <span className="badge">已停用</span>}<span className={`badge ${app.lite_only ? 'badge-green' : ''}`}>{app.lite_only ? '仅 Lite' : '面向全部老友'}</span><Confirm title={app.disabled ? '启用应用？' : '停用应用？'} description={app.disabled ? '此应用将恢复登录和授权。' : '此应用将无法继续登录和授权。'} confirmLabel={app.disabled ? '启用' : '停用'} onConfirm={() => disableApp.mutateAsync({ id: app.id, disabled: !app.disabled })}><Button variant="secondary" disabled={disableApp.isPending}>{app.disabled ? '启用' : '停用'}</Button></Confirm></div></div>) : <div className="empty-state">暂无应用</div>}
  </Panel>}</div></Page>;
}
