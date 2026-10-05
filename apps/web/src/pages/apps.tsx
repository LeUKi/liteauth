import type { AppInput } from '@liteauth/contracts';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link, useNavigate } from '@tanstack/react-router';
import { ChevronRight, History, Plus } from 'lucide-react';
import { useState } from 'react';
import { AppForm } from '../components/app-form';
import { Button, Loading, Modal, Page, PageHeading, Panel, QueryError } from '../components/ui';
import { api, queryKeys } from '../lib/api';

export function AppsPage() {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [creating, setCreating] = useState(false);
  const apps = useQuery({ queryKey: queryKeys.apps, queryFn: ({ signal }) => api.apps.list(signal) });
  const create = useMutation({
    mutationFn: async (input: AppInput) => {
      const result = await api.apps.create(input);
      queryClient.setQueryData(queryKeys.app(result.app.id), { app: result.app });
      setCreating(false);
      await navigate({ to: '/apps/$id', params: { id: result.app.id } });
      return result.app;
    },
    onSuccess: async (app) => {
      queryClient.setQueryData(queryKeys.app(app.id), { app });
      await queryClient.invalidateQueries({ queryKey: queryKeys.apps });
    },
  });
  return <Page><PageHeading title="LiteAuth 应用" action={<Button onClick={() => { create.reset(); setCreating(true); }}><Plus size={17} />创建应用</Button>} />
    {apps.isPending ? <Loading /> : apps.isError ? <QueryError error={apps.error} retry={apps.refetch} /> : apps.data.apps.length === 0 ? <Panel><div className="empty-state"><p>尚未创建应用</p><Button variant="secondary" onClick={() => setCreating(true)}>创建应用</Button></div></Panel> : <Panel className="app-list">{apps.data.apps.map((app) => <div key={app.id} className="app-row"><Link className="app-row-link" to="/apps/$id" params={{ id: app.id }}><div className="app-row-content"><span className="app-row-name">{app.name}</span><code className="muted client-id">{app.client_id}</code><div className="app-row-badges"><span className="badge">{app.client_type === 'confidential' ? '服务端应用' : '浏览器 / 原生应用'}</span><span className="badge">最低 {app.min_trust_level} 级</span></div></div><div className="app-row-state">{app.disabled ? <span className="badge">已停用</span> : app.lite_only ? <span className="badge badge-green">仅 Lite</span> : <span className="badge">面向全部老友</span>}<ChevronRight size={18} className="muted" aria-hidden="true" /></div></Link><Link className="text-link app-history-link" to="/apps/$id" params={{ id: app.id }} hash="login-records"><History size={14} aria-hidden="true" />登录记录</Link></div>)}</Panel>}
    <Modal title="创建 LiteAuth 应用" open={creating} onOpenChange={(open) => { if (!create.isPending) setCreating(open); }}><AppForm pending={create.isPending} error={create.error} onSubmit={(input) => create.mutate(input)} submitLabel="创建应用" onCancel={() => setCreating(false)} /></Modal>
  </Page>;
}
