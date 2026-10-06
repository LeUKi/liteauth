import type {
  App,
  AdminAppsPage,
  AdminConnectFilters,
  AdminUserDetail,
  AdminUserFilters,
  AdminUsersPage,
  AppInput,
  AppResponse,
  AppSecretResponse,
  AppsResponse,
  AuditFilters,
  AuditPage,
  ConsentContext,
  ConnectRecordsPage,
  CredentialInput,
  CredentialsResponse,
  LiteLoginInput,
  LoginContext,
  RedirectResponse,
  SessionResponse,
} from '@liteauth/contracts';

export class ApiFailure extends Error {
  constructor(public readonly code: string, message: string, public readonly status: number) {
    super(message);
    this.name = 'ApiFailure';
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`/api${path}`, {
      ...init,
      credentials: 'same-origin',
      cache: 'no-store',
      headers: {
        Accept: 'application/json',
        ...(init.body ? { 'Content-Type': 'application/json' } : {}),
        ...init.headers,
      },
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') throw error;
    throw new ApiFailure('network_error', '连接失败，请重试', 0);
  }
  if (response.status === 204) return undefined as T;
  const result: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const failure = result as { error?: { code?: string; message?: string } } | null;
    throw new ApiFailure(
      failure?.error?.code ?? 'request_failed',
      failure?.error?.message ?? (response.status === 401 ? '请重新登录' : '操作失败，请重试'),
      response.status,
    );
  }
  if (result === null) throw new ApiFailure('invalid_response', '服务暂不可用，请重试', response.status);
  return result as T;
}

const body = (value: unknown): RequestInit => ({ method: 'POST', body: JSON.stringify(value) });
const idPath = (id: string) => encodeURIComponent(id);
const withRequest = (opaque?: string) => opaque ? `?request=${encodeURIComponent(opaque)}` : '';
const withFilters = (filters: AuditFilters | AdminUserFilters | AdminConnectFilters = {}) => {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) if (value !== undefined && value !== '') params.set(key, String(value));
  return params.size ? `?${params.toString()}` : '';
};

export const api = {
  session: (signal?: AbortSignal) => request<SessionResponse>('/session', { signal }),
  logout: () => request<void>('/logout', body({})),
  login: {
    context: (opaque?: string, signal?: AbortSignal) => request<LoginContext>(`/login-context${withRequest(opaque)}`, { signal }),
    official: (opaque?: string) => request<RedirectResponse>('/login/official', body(opaque ? { request: opaque } : {})),
    lite: (input: LiteLoginInput) => request<RedirectResponse>('/login/lite', body(input)),
  },
  credentials: {
    get: (signal?: AbortSignal) => request<CredentialsResponse>('/credentials', { signal }),
    verify: (input: CredentialInput) => request<RedirectResponse>('/credentials/verify', body(input)),
    delete: () => request<void>('/credentials', { method: 'DELETE' }),
  },
  apps: {
    list: (signal?: AbortSignal) => request<AppsResponse>('/apps', { signal }),
    get: (id: string, signal?: AbortSignal) => request<AppResponse>(`/apps/${idPath(id)}`, { signal }),
    create: (input: AppInput) => request<AppResponse>('/apps', body(input)),
    update: (id: string, input: AppInput) => request<AppResponse>(`/apps/${idPath(id)}`, { method: 'PATCH', body: JSON.stringify(input) }),
    delete: (id: string) => request<void>(`/apps/${idPath(id)}`, { method: 'DELETE' }),
    rotateSecret: (id: string) => request<{ client_secret: string }>(`/apps/${idPath(id)}/rotate-secret`, body({})),
    secret: (id: string, signal?: AbortSignal) => request<AppSecretResponse>(`/apps/${idPath(id)}/secret`, { signal }),
    loginRecords: (id: string, filters: AuditFilters = {}, signal?: AbortSignal) => request<AuditPage>(`/apps/${idPath(id)}/login-records${withFilters(filters)}`, { signal }),
  },
  consent: {
    get: (opaque: string, signal?: AbortSignal) => request<ConsentContext>(`/consent${withRequest(opaque)}`, { signal }),
    respond: (opaque: string, accept: boolean) => request<RedirectResponse>('/consent', body({ request: opaque, accept })),
  },
  admin: {
    users: (filters: AdminUserFilters = {}, signal?: AbortSignal) => request<AdminUsersPage>(`/admin/users${withFilters(filters)}`, { signal }),
    user: (id: string, signal?: AbortSignal) => request<AdminUserDetail>(`/admin/users/${idPath(id)}`, { signal }),
    userApps: (id: string, filters: Pick<AdminUserFilters, 'cursor' | 'limit'> = {}, signal?: AbortSignal) => request<AdminAppsPage>(`/admin/users/${idPath(id)}/apps${withFilters(filters)}`, { signal }),
    connectRecords: (id: string, filters: AdminConnectFilters = {}, signal?: AbortSignal) => request<ConnectRecordsPage>(`/admin/users/${idPath(id)}/connect-records${withFilters(filters)}`, { signal }),
    apps: (signal?: AbortSignal) => request<{ apps: App[] }>('/admin/apps', { signal }),
    audit: (filters: AuditFilters = {}, signal?: AbortSignal) => request<AuditPage>(`/admin/audit${withFilters(filters)}`, { signal }),
    disableUser: (id: string, disabled: boolean) => request<void>(`/admin/users/${idPath(id)}/disable`, body({ disabled })),
    disableApp: (id: string, disabled: boolean) => request<void>(`/admin/apps/${idPath(id)}/disable`, body({ disabled })),
  },
};

export function followRedirect(response: RedirectResponse) {
  const url = new URL(response.redirect_url, window.location.origin);
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && local)) {
    throw new ApiFailure('invalid_redirect', '无法打开登录页面，请重试', 400);
  }
  window.location.assign(url.href);
}

export function errorMessage(error: unknown): string {
  if (error instanceof ApiFailure && error.code === 'official_login_required') return '此账号已完成非 Lite 验证，请使用非 Lite 用户登录。';
  return error instanceof ApiFailure ? error.message : '操作失败，请重试';
}

export const queryKeys = {
  session: ['session'] as const,
  login: (opaque?: string) => ['login-context', opaque ?? null] as const,
  credentials: ['credentials'] as const,
  apps: ['apps'] as const,
  app: (id: string) => ['app', id] as const,
  appSecret: (id: string) => ['app-secret', id] as const,
  appRecords: (id: string, filters: AuditFilters) => ['app-records', id, filters] as const,
  consent: (opaque: string) => ['consent', opaque] as const,
  adminUsers: (filters: AdminUserFilters) => ['admin', 'users', filters] as const,
  adminUser: (id: string) => ['admin', 'user', id] as const,
  adminUserApps: (id: string) => ['admin', 'user-apps', id] as const,
  adminConnectRecords: (id: string, filters: AdminConnectFilters) => ['admin', 'connect-records', id, filters] as const,
  adminApps: ['admin', 'apps'] as const,
  adminAudit: (filters: AuditFilters) => ['admin', 'audit', filters] as const,
};
