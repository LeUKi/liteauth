import type { AuditFilters, AuditResult } from '@liteauth/contracts';
import { useInfiniteQuery } from '@tanstack/react-query';
import { useState } from 'react';
import type { FormEvent } from 'react';
import { api, queryKeys } from '../lib/api';
import { loginMethodName, reasonName, resultNames } from '../lib/records';
import { Button, Field, Loading, Notice, Panel, formatRecordDate } from './ui';

const results: AuditResult[] = ['success', 'denied', 'failed', 'canceled', 'expired'];

export function LoginRecords({ appId }: { appId: string }) {
  const [user, setUser] = useState('');
  const [result, setResult] = useState<AuditResult | ''>('');
  const [filters, setFilters] = useState<AuditFilters>({});
  const records = useInfiniteQuery({
    queryKey: queryKeys.appRecords(appId, filters),
    queryFn: ({ pageParam, signal }) => api.apps.loginRecords(appId, { ...filters, cursor: pageParam }, signal),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (page) => page.next_cursor ?? undefined,
  });
  const entries = records.data?.pages.flatMap((page) => page.entries) ?? [];
  function filter(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFilters({ ...(user.trim() ? { user: user.trim() } : {}), ...(result ? { result } : {}) });
  }
  return <div id="login-records" className="record-section"><Panel>
    <div className="panel-heading"><h2>登录记录</h2><span className="muted table-period">最近七天 · 北京时间（UTC+8）</span></div>
    <form className="record-filters" onSubmit={filter}>
      <Field label="用户" htmlFor="record-user"><input id="record-user" placeholder="用户名或用户 ID" value={user} onChange={(event) => setUser(event.target.value)} /></Field>
      <Field label="结果" htmlFor="record-result"><select id="record-result" value={result} onChange={(event) => setResult(event.target.value as AuditResult | '')}><option value="">全部结果</option>{results.map((value) => <option key={value} value={value}>{resultNames[value]}</option>)}</select></Field>
      <Button type="submit" variant="secondary">筛选</Button>
    </form>
    {records.isPending ? <Loading /> : records.isError && !records.data ? <div className="stack"><Notice>{records.error.message}</Notice><Button variant="secondary" onClick={() => void records.refetch()}>重试</Button></div> : entries.length === 0 ? <div className="empty-state">暂无登录记录</div> : <>
      <div className="table-scroll" role="region" aria-label="应用登录记录" tabIndex={0}><table className="data-table record-table"><thead><tr><th>用户</th><th>登录方式</th><th>等级</th><th>结果</th><th>原因</th><th>时间</th></tr></thead><tbody>{entries.map((entry) => <tr key={entry.id}><td><div className="table-cell-stack"><span>{entry.actor_username ? `@${entry.actor_username}` : '身份未确认'}</span>{entry.actor_linuxdo_id && <span className="muted">Linux.do ID {entry.actor_linuxdo_id}</span>}</div></td><td>{loginMethodName(entry.login_method)}</td><td>{entry.trust_level === null ? '—' : `${entry.trust_level} 级`}</td><td><span className={`badge ${entry.result === 'success' ? 'badge-green' : ''}`}>{resultNames[entry.result]}</span></td><td>{reasonName(entry.reason)}</td><td><time dateTime={entry.created_at}>{formatRecordDate(entry.created_at)}</time></td></tr>)}</tbody></table></div>
      {records.isFetchNextPageError && <Notice>读取更多记录失败，请重试</Notice>}
      {records.hasNextPage && <div className="record-pagination"><Button variant="secondary" busy={records.isFetchingNextPage} onClick={() => void records.fetchNextPage()}>加载更多</Button></div>}
    </>}
  </Panel></div>;
}
