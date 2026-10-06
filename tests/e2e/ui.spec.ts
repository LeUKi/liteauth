import { expect, test } from '@playwright/test';
import type { Page, Route } from '@playwright/test';
import type { AdminUserSummary, App, AppInput, AppSecretResponse, AuditEntry, ConnectRecord, CredentialsResponse, Eligibility, LiteLoginInput, LoginContext, SessionResponse } from '../../packages/contracts/src/index';

// These tests exercise the frontend with intercepted API responses.
// They do not establish upstream login, D1 behavior, or production integration.
const userSession: SessionResponse = {
  user: { id: 'la_test_user', linuxdo_id: 123, username: 'alice', name: 'Alice', is_admin: false },
  login_method: 'official_connect',
};
const fixtureApp: App = {
  id: 'app_test', client_id: 'la_client_test', name: '校友网站',
  redirect_uris: ['https://example.com/callback'], lite_only: false, min_trust_level: 0,
  client_type: 'confidential', pkce_required: true, disabled: false,
  created_at: '2026-10-05T00:00:00Z',
};
const newSecret = 'la_test_secret_repeatable_abcdef123456';
const fixtureAudit: AuditEntry = {
  id: 'audit_test', action: 'authorization.issued', actor_id: userSession.user!.id, actor_type: 'user',
  actor_linuxdo_id: 123, actor_username: 'alice', actor_name: 'Alice',
  target_id: fixtureApp.id, target_type: 'app', target_name: fixtureApp.name, client_id: fixtureApp.client_id,
  app_name: fixtureApp.name, login_method: 'lite_self_app', trust_level: 1, result: 'success',
  reason: null, request_id: 'request_test', changes: null, created_at: '2026-10-05T00:00:01Z',
};
const fixtureAdminUser: AdminUserSummary = {
  ...userSession.user!, connect_client_id: 'connect_current_client', last_login_method: 'lite_self_app',
  last_trust_level: 2, last_authenticated_at: '2026-10-05T00:00:01Z', created_at: '2026-10-01T00:00:00Z',
};
const fixtureConnectRecord: ConnectRecord = {
  ...fixtureAudit, id: 'connect_record_confirmed', action: 'connect.verification', client_id: null, app_name: null,
  subject_user_id: userSession.user!.id, subject_linuxdo_id: 123, subject_username: 'alice',
  upstream_client_id: 'connect_current_client', connect_transaction_id: 'connect_transaction_test',
  identity_confirmed: true, verification_purpose: 'login',
};

type MockState = {
  session: SessionResponse;
  app: App;
  apps: App[];
  credentials: CredentialsResponse;
  context?: LoginContext;
  createInput?: AppInput;
  updateInput?: AppInput;
  officialRequests: number;
  appListReads: number;
  secret: AppSecretResponse;
  secretReads: number;
  adminUser: AdminUserSummary;
};
type Intercept = (route: Route, url: URL, state: MockState) => Promise<boolean>;

async function json(route: Route, value: unknown, status = 200) {
  await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(value) });
}

async function mockApi(page: Page, initial: Partial<MockState> = {}, intercept?: Intercept): Promise<MockState> {
  const state: MockState = {
    session: { user: null, login_method: null }, app: structuredClone(fixtureApp), apps: [],
    credentials: { credential: null }, officialRequests: 0, appListReads: 0,
    secret: { status: 'available', client_secret: newSecret }, secretReads: 0, adminUser: structuredClone(fixtureAdminUser), ...initial,
  };
  await page.route('**/api/**', async (route) => {
    const url = new URL(route.request().url());
    if (intercept && await intercept(route, url, state)) return;
    const method = route.request().method();
    const eligibility: Eligibility = state.session.user
      ? state.app.lite_only && state.session.login_method !== 'lite_self_app'
        ? { allowed: false, reason: 'lite_required', trust_level: 1 }
        : { allowed: true, reason: null, trust_level: 1 }
      : { allowed: false, reason: 'login_required', trust_level: null };
    switch (url.pathname) {
      case '/api/session': return json(route, state.session);
      case '/api/logout': state.session = { user: null, login_method: null }; return route.fulfill({ status: 204 });
      case '/api/login-context': return json(route, state.context ?? {
        request: url.searchParams.get('request'),
        application: url.searchParams.has('request') ? { id: state.app.id, name: state.app.name, lite_only: state.app.lite_only, min_trust_level: state.app.min_trust_level } : null,
        official_available: !state.app.lite_only,
        eligibility,
      });
      case '/api/login/official':
        state.officialRequests++;
        return json(route, { error: { code: 'test_stop', message: '测试停止跳转' } }, 400);
      case '/api/credentials': return json(route, state.credentials);
      case '/api/apps':
        if (method === 'GET') { state.appListReads++; return json(route, { apps: state.apps }); }
        if (method === 'POST') {
          state.createInput = route.request().postDataJSON() as AppInput;
          state.app = { ...fixtureApp, ...state.createInput, id: 'app_created', client_id: 'la_created_client' };
          state.apps = [state.app];
          return json(route, { app: state.app, ...(state.app.client_type === 'confidential' ? { client_secret: newSecret } : {}) });
        }
        break;
      case '/api/consent':
        return json(route, { request: url.searchParams.get('request') ?? 'request_test', application: { id: state.app.id, name: state.app.name, lite_only: state.app.lite_only, min_trust_level: state.app.min_trust_level }, scopes: ['openid', 'profile'], login_method: state.session.login_method, eligibility });
      case '/api/admin/users': return json(route, { users: [state.adminUser], next_cursor: null });
      case '/api/admin/apps': return json(route, { apps: state.apps });
      case '/api/admin/audit': return json(route, { entries: [fixtureAudit], next_cursor: null });
      default:
        if (url.pathname === `/api/admin/users/${state.adminUser.id}`) return json(route, { user: state.adminUser, credentials: [{ client_id: state.adminUser.connect_client_id, status: 'active', created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-05T00:00:00Z' }] });
        if (url.pathname === `/api/admin/users/${state.adminUser.id}/apps`) return json(route, { apps: state.apps, next_cursor: null });
        if (url.pathname === `/api/admin/users/${state.adminUser.id}/connect-records`) return json(route, { entries: [fixtureConnectRecord], next_cursor: null });
        if (url.pathname === `/api/apps/${state.app.id}/secret`) { state.secretReads++; return json(route, state.secret); }
        if (url.pathname === `/api/apps/${state.app.id}/rotate-secret`) { state.secret = { status: 'available', client_secret: `${newSecret}_rotated` }; return json(route, { client_secret: state.secret.client_secret }); }
        if (url.pathname === `/api/apps/${state.app.id}/login-records`) return json(route, { entries: [], next_cursor: null });
        if (url.pathname === `/api/apps/${state.app.id}`) {
          if (method === 'PATCH') {
            state.updateInput = route.request().postDataJSON() as AppInput;
            state.app = { ...state.app, ...state.updateInput };
            state.apps = [state.app];
          }
          return json(route, { app: state.app });
        }
    }
    await json(route, { error: { code: 'mock_unhandled', message: '测试未提供此响应' } }, 400);
  });
  return state;
}

test('official login is natively disabled while policy is pending and after failure', async ({ page }) => {
  let release!: () => void;
  const pending = new Promise<void>((resolve) => { release = resolve; });
  let fail = true;
  const state = await mockApi(page, {}, async (route, url) => {
    if (url.pathname !== '/api/login-context') return false;
    await pending;
    if (fail) await json(route, { error: { code: 'context_unavailable', message: '登录方式暂不可用' } }, 400);
    else await json(route, { request: null, application: null, official_available: true, eligibility: { allowed: false, reason: 'login_required', trust_level: null } });
    return true;
  });
  await page.goto('/login');
  const official = page.getByRole('button', { name: /非 Lite 用户登录/ });
  await expect(official).toBeDisabled();
  await official.focus();
  await expect(official).not.toBeFocused();
  await page.keyboard.press('Enter');
  expect(state.officialRequests).toBe(0);
  release();
  await expect(page.getByRole('alert')).toContainText('登录方式暂不可用');
  await expect(official).toBeDisabled();
  fail = false;
  await page.getByRole('button', { name: '重新加载' }).click();
  await expect(official).toBeEnabled();
});

test('global footer shows repository link, plain author credit, version and stable build timestamp', async ({ page }) => {
  await mockApi(page);
  await page.goto('/login');
  const footer = page.getByRole('contentinfo', { name: '站点信息' });
  await expect(footer).toContainText(/LiteAuth\s*·\s*Made with ❤️ by lafish\s*·\s*v0\.1\.0\s*·\s*build @ \d{10}/);
  await expect(footer.getByRole('link', { name: 'LiteAuth' })).toHaveAttribute('href', 'https://github.com/LeUKi/liteauth');
  await expect(footer.getByRole('link')).toHaveCount(1);
  await expect(footer.getByRole('link', { name: /lafish/ })).toHaveCount(0);
  await expect(footer).toHaveCSS('color', 'rgb(168, 173, 165)');
  const buildText = await footer.textContent();
  await page.clock.setFixedTime(new Date('2035-01-01T00:00:00Z'));
  await page.reload();
  await expect(footer).toHaveText(buildText ?? '');
  await page.goto('/missing-route');
  await expect(page.getByRole('heading', { name: '页面不存在' })).toBeVisible();
  await expect(footer).toHaveText(buildText ?? '');
  await page.goto('/login?request=');
  await expect(page.getByRole('heading', { name: '页面暂不可用' })).toBeVisible();
  await expect(footer).toHaveCount(1);
  await expect(footer).toHaveText(buildText ?? '');
  await footer.getByRole('link', { name: 'LiteAuth' }).focus();
  await expect(footer.getByRole('link', { name: 'LiteAuth' })).toBeFocused();
  await expect(footer.getByRole('link', { name: 'LiteAuth' })).toHaveCSS('outline-style', 'solid');
  await page.setViewportSize({ width: 320, height: 740 });
  await expect(footer).toBeVisible();
  expect(await footer.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});

test('Lite-only policy cannot be overridden by search parameters or an official session', async ({ page }) => {
  const state = await mockApi(page, { session: userSession, app: { ...fixtureApp, lite_only: true } });
  await page.goto('/login?request=request_test&lite_only=false&official_available=true');
  await expect(page.getByRole('heading', { name: '校友网站' })).toBeVisible();
  const official = page.getByRole('button', { name: /非 Lite 用户登录/ });
  await expect(official).toBeDisabled();
  await expect(page.getByText('此应用仅允许 Lite 用户登录')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Lite 用户登录', exact: true })).toBeEnabled();
  await expect(page.getByRole('link', { name: '继续', exact: true })).toHaveCount(0);
  await page.getByLabel('Linux.do 用户名').focus();
  await page.keyboard.press('Shift+Tab');
  await expect(official).not.toBeFocused();
  expect(state.officialRequests).toBe(0);
});

test('missing Lite credentials opens a recoverable credential form', async ({ page }) => {
  await mockApi(page, {}, async (route, url) => {
    if (url.pathname !== '/api/login/lite') return false;
    await json(route, { error: { code: 'credentials_required', message: '请填写 Connect 密钥' } }, 400);
    return true;
  });
  await page.goto('/login');
  await page.getByLabel('Linux.do 用户名').fill('alice');
  await page.getByRole('button', { name: 'Lite 用户登录', exact: true }).click();
  await expect(page.getByLabel('Connect Client ID')).toBeVisible();
  await expect(page.getByLabel('Connect Client ID')).toBeFocused();
  await expect(page.getByLabel('Connect Client Secret')).toHaveAttribute('type', 'password');
  await expect(page.getByRole('button', { name: '验证并登录' })).toBeEnabled();
  await expect(page.getByLabel('Linux.do 用户名')).toHaveValue('alice');
});

test('manual Lite credentials validate only missing fields and hosted mode discards candidate secrets', async ({ page }) => {
  const inputs: LiteLoginInput[] = [];
  await mockApi(page, {}, async (route, url) => {
    if (url.pathname !== '/api/login/lite') return false;
    inputs.push(route.request().postDataJSON() as LiteLoginInput);
    await json(route, { error: { code: 'test_stop', message: '测试停止跳转' } }, 400);
    return true;
  });
  await page.goto('/login');
  const username = page.getByLabel('Linux.do 用户名');
  await username.fill('@alice');
  await expect(username).toHaveValue('alice');
  await expect(page.locator('.input-prefix > span')).toHaveText('@');
  const official = page.getByRole('button', { name: '非 Lite 用户登录', exact: true });
  const lite = page.getByRole('button', { name: 'Lite 用户登录', exact: true });
  const appearance = (element: HTMLElement) => { const style = getComputedStyle(element); return { width: style.width, height: style.height, align: style.justifyContent }; };
  expect(await official.evaluate(appearance)).toEqual(await lite.evaluate(appearance));
  await expect(official).toHaveCSS('justify-content', 'center');
  await expect(official).toHaveCSS('background-color', 'rgb(255, 255, 255)');
  await expect(lite).toHaveCSS('background-color', 'rgb(22, 120, 75)');
  await page.getByRole('button', { name: '填写 / 更新 Connect 密钥' }).click();
  const client = page.getByLabel('Connect Client ID');
  const secret = page.getByLabel('Connect Client Secret');
  await client.fill('connect_candidate_id');
  await page.getByRole('button', { name: '验证并登录' }).click();
  await expect(client).toHaveAttribute('aria-invalid', 'false');
  await expect(secret).toHaveAttribute('aria-invalid', 'true');
  await expect(page.getByRole('alert')).toHaveText('请填写 Client Secret');
  expect(inputs).toHaveLength(0);
  await secret.fill('candidate_secret');
  await expect(page.getByRole('alert')).toHaveCount(0);
  await client.clear();
  await page.getByRole('button', { name: '验证并登录' }).click();
  await expect(page.getByRole('alert')).toHaveText('请填写 Client ID');
  await expect(secret).toHaveAttribute('aria-invalid', 'false');
  await client.fill('connect_candidate_id');
  await expect(page.getByRole('alert')).toHaveCount(0);
  await page.getByRole('button', { name: '验证并登录' }).click();
  await expect(page.getByRole('alert')).toHaveText('测试停止跳转');
  expect(inputs[0]).toMatchObject({ username: 'alice', client_id: 'connect_candidate_id', client_secret: 'candidate_secret' });
  await page.getByRole('button', { name: '使用已托管的密钥' }).click();
  await expect(page.getByRole('alert')).toHaveCount(0);
  await expect(secret).toHaveCount(0);
  await page.getByRole('button', { name: 'Lite 用户登录', exact: true }).click();
  await expect.poll(() => inputs.length).toBe(2);
  expect(inputs[1]).toEqual({ username: 'alice' });
});

test('Connect setup guidance includes fixed and freely chosen fields', async ({ page }) => {
  await mockApi(page);
  await page.goto('/login');
  await page.getByRole('button', { name: '填写 / 更新 Connect 密钥' }).click();
  const guide = page.locator('.connect-setup');
  for (const label of ['应用名称', '应用主页', '应用描述', 'LOGO', '最低等级', '回调地址']) await expect(guide.locator('dt', { hasText: label })).toBeVisible();
  await expect(guide.getByText('自行填写', { exact: true })).toHaveCount(2);
  await expect(guide.getByRole('button', { name: '复制Connect 回调地址' })).toBeVisible();
  await expect(guide.getByText('http://127.0.0.1:5188/auth/connect/callback', { exact: true })).toBeVisible();
});

test('application policy saves to the server, refetches, and changes subsequent login', async ({ page }) => {
  const state = await mockApi(page, { session: userSession, apps: [fixtureApp] });
  await page.goto(`/apps/${fixtureApp.id}`);
  const liteOnly = page.getByRole('switch', { name: '仅允许 Lite 用户登录' });
  await expect(liteOnly).not.toBeChecked();
  await liteOnly.click();
  await expect(page.getByText('阻止新的非 Lite 授权；已有授权按原有效期继续。')).toBeVisible();
  await page.getByRole('button', { name: '保存', exact: true }).click();
  await expect(page.getByText('已保存', { exact: true })).toBeVisible();
  expect(state.updateInput?.lite_only).toBe(true);
  expect(state.updateInput?.redirect_uris).toEqual(['https://example.com/callback']);
  await page.getByRole('link', { name: 'LiteAuth 应用', exact: true }).first().click();
  await expect(page.getByText('仅 Lite', { exact: true })).toBeVisible();
  expect(state.appListReads).toBeGreaterThan(0);
  await page.goto(`/apps/${fixtureApp.id}`);
  await expect(page.getByRole('switch', { name: '仅允许 Lite 用户登录' })).toBeChecked();
  await page.goto('/login?request=request_test');
  await expect(page.getByRole('button', { name: /非 Lite 用户登录/ })).toBeDisabled();
});

test('minimum level persists and server eligibility blocks session reuse and consent', async ({ page }) => {
  const state = await mockApi(page, { session: userSession, apps: [fixtureApp] });
  await page.goto(`/apps/${fixtureApp.id}`);
  const level = page.getByLabel('最低等级', { exact: true });
  await expect(level).toHaveValue('0');
  await expect(level.locator('option')).toHaveCount(5);
  await level.selectOption('3');
  await page.getByRole('button', { name: '保存', exact: true }).click();
  await expect(page.getByText('已保存', { exact: true })).toBeVisible();
  expect(state.updateInput?.min_trust_level).toBe(3);
  await page.reload();
  await expect(level).toHaveValue('3');
  state.context = { request: 'request_test', application: { id: state.app.id, name: state.app.name, lite_only: false, min_trust_level: 3 }, official_available: true, eligibility: { allowed: false, reason: 'trust_level_required', trust_level: 1 } };
  await page.goto('/login?request=request_test&trust_level=4');
  await expect(page.getByText('此应用要求等级达到 3 级；当前已验证等级：1 级')).toBeVisible();
  await expect(page.getByRole('link', { name: '继续', exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: '重新验证', exact: true }).click();
  await expect.poll(() => state.officialRequests).toBe(1);
  await page.route('**/api/consent?**', (route) => json(route, { request: 'request_test', application: state.context!.application, scopes: ['openid', 'profile'], login_method: 'official_connect', eligibility: state.context!.eligibility }));
  await page.goto('/consent?request=request_test');
  await expect(page.getByRole('link', { name: '重新验证' })).toBeVisible();
  await expect(page.getByRole('button', { name: '允许', exact: true })).toHaveCount(0);
});

test('public applications force PKCE and do not expose a client secret', async ({ page }) => {
  const state = await mockApi(page, { session: userSession });
  await page.goto('/apps');
  await page.getByRole('button', { name: '创建应用' }).first().click();
  const dialog = page.getByRole('dialog', { name: '创建 LiteAuth 应用' });
  await dialog.getByLabel('应用名称', { exact: true }).fill('浏览器应用');
  await dialog.getByLabel('回调地址（每行一个）').fill('https://example.com/callback');
  await dialog.getByLabel('应用类型').selectOption('public');
  const pkce = dialog.getByRole('switch', { name: '启用 PKCE' });
  await expect(pkce).toBeChecked();
  await expect(pkce).toBeDisabled();
  await dialog.getByRole('button', { name: '创建应用', exact: true }).click();
  await expect(page).toHaveURL(/\/apps\/app_created$/);
  expect(state.createInput?.client_type).toBe('public');
  expect(state.createInput?.pkce_required).toBe(true);
  expect(state.createInput?.min_trust_level).toBe(0);
  await expect(page.getByText('浏览器 / 原生应用', { exact: true })).toBeVisible();
  await expect(page.getByRole('dialog', { name: '保存应用密钥' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: '轮换密钥' })).toHaveCount(0);
});

test('legacy secrets require explicit rotation while access by another administrator remains unavailable', async ({ page }) => {
  const state = await mockApi(page, { session: userSession, secret: { status: 'legacy_unavailable', client_secret: null } });
  await page.goto(`/apps/${fixtureApp.id}`);
  await expect(page.getByText('轮换后可查看密钥')).toBeVisible();
  await expect(page.getByLabel('Client Secret', { exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: '轮换密钥', exact: true }).click();
  await page.getByRole('alertdialog').getByRole('button', { name: '轮换密钥', exact: true }).click();
  await expect(page.getByLabel('Client Secret', { exact: true })).toHaveText(`${newSecret}_rotated`);
  await expect(page.getByRole('alertdialog')).toHaveCount(0);
  state.session = { ...userSession, user: { ...userSession.user!, id: 'other_admin', username: 'other_admin', is_admin: true } };
  await page.route(`**/api/apps/${fixtureApp.id}/secret`, (route) => json(route, { error: { code: 'forbidden', message: '无权查看' } }, 403));
  await page.reload();
  await expect(page.getByText('仅应用所有者可查看密钥')).toBeVisible();
  await expect(page.getByLabel('Client Secret', { exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: '轮换密钥', exact: true })).toHaveCount(0);
});

test('application history has independent navigation, identity snapshots and cursor filtering', async ({ page }) => {
  const requested: URL[] = [];
  const older = { ...fixtureAudit, id: 'audit_older', result: 'denied', reason: 'access_denied', created_at: '2026-10-05T00:00:00Z' };
  await mockApi(page, { session: userSession, apps: [fixtureApp] }, async (route, url) => {
    if (url.pathname !== `/api/apps/${fixtureApp.id}/login-records`) return false;
    requested.push(url);
    await json(route, url.searchParams.has('cursor') || url.searchParams.has('result') ? { entries: [older], next_cursor: null } : { entries: [fixtureAudit], next_cursor: 'next_test' });
    return true;
  });
  await page.goto('/apps');
  await expect(page.getByText('面向全部老友')).toBeVisible();
  const historyLink = page.getByRole('link', { name: '登录记录', exact: true });
  expect(await historyLink.evaluate((element) => element.parentElement?.closest('a'))).toBeNull();
  await historyLink.click();
  await expect(page).toHaveURL(/#login-records$/);
  await expect(page.getByRole('heading', { name: '登录记录', exact: true })).toBeInViewport();
  const table = page.getByRole('region', { name: '应用登录记录' });
  await expect(table.getByText('@alice', { exact: true })).toBeVisible();
  await expect(table.getByText('Linux.do ID 123')).toBeVisible();
  await expect(table.getByText('2026/10/05 08:00:01')).toBeVisible();
  await page.getByRole('button', { name: '加载更多' }).click();
  await expect(table.getByText('用户拒绝')).toBeVisible();
  expect(requested.some((url) => url.searchParams.get('cursor') === 'next_test')).toBe(true);
  await page.getByLabel('用户', { exact: true }).fill('alice');
  await page.getByLabel('结果', { exact: true }).selectOption('denied');
  await page.getByRole('button', { name: '筛选', exact: true }).click();
  await expect(table.locator('tbody tr')).toHaveCount(1);
  expect(requested.at(-1)?.searchParams.get('result')).toBe('denied');
  expect(requested.at(-1)?.searchParams.get('user')).toBe('alice');
  expect(requested.at(-1)?.searchParams.has('cursor')).toBe(false);
});

test('admin audit exposes actor, target, changes and a traceable request with filters', async ({ page }) => {
  const reads: URL[] = [];
  const entry = { ...fixtureAudit, action: 'app.updated', changes: { min_trust_level: { before: 0, after: 3 } } };
  await mockApi(page, { session: { ...userSession, user: { ...userSession.user!, is_admin: true } } }, async (route, url) => {
    if (url.pathname !== '/api/admin/audit') return false;
    reads.push(url);
    await json(route, { entries: [entry], next_cursor: null });
    return true;
  });
  await page.goto('/admin');
  await page.getByRole('tab', { name: '操作记录' }).click();
  const table = page.getByRole('region', { name: '全站操作记录' });
  await expect(table.getByText('@alice', { exact: true })).toBeVisible();
  await expect(table.getByText('Linux.do ID 123')).toBeVisible();
  await expect(table.getByText('最低等级：0 → 3')).toBeVisible();
  await table.getByText('关联请求', { exact: true }).click();
  await expect(table.getByText('request_test', { exact: true })).toBeVisible();
  await page.getByLabel('操作人', { exact: true }).fill('123');
  await page.getByLabel('应用', { exact: true }).fill(fixtureApp.client_id);
  await page.getByLabel('操作', { exact: true }).selectOption('app.updated');
  await page.getByLabel('结果', { exact: true }).selectOption('success');
  await page.getByLabel('开始时间', { exact: true }).fill('2026-10-05T08:00');
  await page.getByLabel('结束时间', { exact: true }).fill('2026-10-05T09:00');
  await page.getByRole('button', { name: '筛选', exact: true }).click();
  await expect.poll(() => reads.at(-1)?.searchParams.get('from')).toBe('2026-10-05T00:00:00.000Z');
  expect(reads.at(-1)?.searchParams.get('user')).toBe('123');
  expect(reads.at(-1)?.searchParams.get('client_id')).toBe(fixtureApp.client_id);
  expect(reads.at(-1)?.searchParams.get('action')).toBe('app.updated');
  expect(reads.at(-1)?.searchParams.get('to')).toBe('2026-10-05T01:00:00.000Z');
});

test('admin accounts search and paginate while detail URLs remain stable across username changes', async ({ page }) => {
  const reads: URL[] = [];
  const otherUser = { ...fixtureAdminUser, id: 'la_other', linuxdo_id: 456, username: 'bob', connect_client_id: null, last_login_method: null, last_trust_level: null, last_authenticated_at: null };
  const state = await mockApi(page, { session: { ...userSession, user: { ...userSession.user!, id: 'la_admin', is_admin: true } } }, async (route, url, current) => {
    if (url.pathname !== '/api/admin/users') return false;
    reads.push(url);
    if (url.searchParams.has('q')) await json(route, { users: [current.adminUser], next_cursor: null });
    else if (url.searchParams.has('cursor')) await json(route, { users: [otherUser], next_cursor: null });
    else await json(route, { users: [current.adminUser], next_cursor: 'users_next_test' });
    return true;
  });
  await page.goto('/admin');
  const table = page.getByRole('region', { name: '管理员账号列表' });
  await expect(table.getByRole('link', { name: '@alice', exact: true })).toHaveAttribute('href', '/admin/users/la_test_user');
  await expect(table.getByText('connect_current_client', { exact: true })).toBeVisible();
  await expect(table.getByRole('button', { name: '复制 alice 的 Connect Client ID' })).toBeVisible();
  await expect(table.getByText('2 级', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: '加载更多', exact: true }).click();
  await expect(table.getByRole('link', { name: '@bob' })).toBeVisible();
  await expect(table.getByText('未绑定', { exact: true })).toBeVisible();
  expect(reads.some((url) => url.searchParams.get('cursor') === 'users_next_test')).toBe(true);
  await page.getByLabel('搜索账号', { exact: true }).fill('connect_current_client');
  await page.getByLabel('状态', { exact: true }).selectOption('active');
  await page.getByRole('button', { name: '搜索', exact: true }).click();
  await expect.poll(() => reads.at(-1)?.searchParams.get('q')).toBe('connect_current_client');
  expect(reads.at(-1)?.searchParams.get('disabled')).toBe('false');
  expect(reads.at(-1)?.searchParams.has('cursor')).toBe(false);
  await expect(table.locator('tbody tr')).toHaveCount(1);
  state.adminUser.username = 'renamed_alice';
  await table.getByRole('link', { name: '@alice', exact: true }).click();
  await expect(page).toHaveURL(/\/admin\/users\/la_test_user$/);
  await expect(page.getByRole('heading', { name: '@renamed_alice', exact: true })).toBeVisible();
  await page.reload();
  await expect(page.getByRole('heading', { name: '@renamed_alice', exact: true })).toBeVisible();
  expect(state.secretReads).toBe(0);
});

test('global verification audit keeps an unconfirmed target separate from a verified mismatched actor', async ({ page }) => {
  const unknown: ConnectRecord = { ...fixtureConnectRecord, id: 'global_unknown', actor_id: null, actor_username: null, actor_linuxdo_id: null, actor_type: 'unknown', identity_confirmed: false, result: 'failed', reason: 'credential_invalid' };
  const mismatch: ConnectRecord = { ...fixtureConnectRecord, id: 'global_mismatch', actor_id: 'la_bob', actor_username: 'returned_bob', actor_linuxdo_id: 456, result: 'failed', reason: 'identity_mismatch' };
  await mockApi(page, { session: { ...userSession, user: { ...userSession.user!, is_admin: true } } }, async (route, url) => {
    if (url.pathname !== '/api/admin/audit') return false;
    await json(route, { entries: [unknown, mismatch], next_cursor: null });
    return true;
  });
  await page.goto('/admin');
  await page.getByRole('tab', { name: '操作记录' }).click();
  const table = page.getByRole('region', { name: '全站操作记录' });
  const unconfirmed = table.locator('tbody tr').filter({ hasText: '身份未确认' });
  await expect(unconfirmed.locator('td').nth(2)).toHaveText('身份未确认');
  await expect(unconfirmed.locator('td').nth(5)).toContainText('目标账号：@alice · Linux.do ID 123');
  await expect(unconfirmed.locator('td').nth(5)).toContainText('connect_current_client');
  const mismatched = table.locator('tbody tr').filter({ hasText: '@returned_bob' });
  await expect(mismatched.locator('td').nth(2)).toContainText('Linux.do ID 456');
  await expect(mismatched.locator('td').nth(5)).toContainText('身份不一致');
  await expect(mismatched.locator('td').nth(5)).toContainText('目标账号：@alice · Linux.do ID 123');
});

test('admin user detail shows credential history and separates intended from verified identities', async ({ page }) => {
  const recordReads: URL[] = [];
  const unknown: ConnectRecord = { ...fixtureConnectRecord, id: 'unknown_identity', result: 'failed', reason: 'credential_invalid', actor_id: null, actor_username: null, actor_linuxdo_id: null, actor_type: 'unknown', identity_confirmed: false, verification_purpose: 'credential_validation' };
  const mismatch: ConnectRecord = { ...fixtureConnectRecord, id: 'mismatched_identity', result: 'failed', reason: 'identity_mismatch', actor_id: 'la_returned_bob', actor_username: 'returned_bob', actor_linuxdo_id: 456, verification_purpose: 'credential_validation' };
  const secondApp = { ...fixtureApp, id: 'second_user_app', name: '第二个应用', client_id: 'la_second_app' };
  const state = await mockApi(page, { session: { ...userSession, user: { ...userSession.user!, id: 'la_admin', is_admin: true } }, apps: [fixtureApp] }, async (route, url, current) => {
    const base = `/api/admin/users/${current.adminUser.id}`;
    if (url.pathname === base) {
      await json(route, { user: current.adminUser, credentials: [
        { client_id: 'connect_current_client', status: 'active', created_at: '2026-10-03T00:00:00Z', updated_at: '2026-10-05T00:00:00Z' },
        { client_id: 'connect_historical_client', status: 'revoked', created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-02T00:00:00Z' },
      ] }); return true;
    }
    if (url.pathname === `${base}/connect-records`) {
      recordReads.push(url);
      await json(route, url.searchParams.has('cursor') || url.searchParams.has('result') ? { entries: [mismatch], next_cursor: null } : { entries: [fixtureConnectRecord, unknown], next_cursor: 'connect_next' }); return true;
    }
    if (url.pathname === `${base}/apps`) {
      await json(route, url.searchParams.has('cursor') ? { apps: [secondApp], next_cursor: null } : { apps: [fixtureApp], next_cursor: 'apps_next' }); return true;
    }
    if (url.pathname === `/api/apps/${fixtureApp.id}/secret`) { await json(route, { error: { code: 'forbidden', message: '无权查看' } }, 403); return true; }
    return false;
  });
  await page.goto(`/admin/users/${fixtureAdminUser.id}`);
  await expect(page.getByRole('heading', { name: '账号资料', exact: true })).toBeVisible();
  const history = page.getByRole('region', { name: 'Connect 绑定历史' });
  await expect(history.getByText('connect_historical_client', { exact: true })).toBeVisible();
  await expect(history.getByText('已撤销', { exact: true })).toBeVisible();
  await expect(page.getByLabel('Client Secret', { exact: true })).toHaveCount(0);
  const records = page.getByRole('region', { name: 'Connect 验证记录' });
  await expect(records.locator('thead th').first()).toHaveText('时间');
  const failedUnknown = records.locator('tbody tr').filter({ hasText: '身份未确认' });
  await expect(failedUnknown.locator('td').nth(1)).toContainText('@alice');
  await expect(failedUnknown.locator('td').nth(2)).toHaveText('身份未确认');
  await page.getByRole('button', { name: '加载更多记录', exact: true }).click();
  const failedMismatch = records.locator('tbody tr').filter({ hasText: '@returned_bob' });
  await expect(failedMismatch.locator('td').nth(1)).toContainText('@alice');
  await expect(failedMismatch.locator('td').nth(2)).toContainText('Linux.do ID 456');
  await expect(failedMismatch.locator('td').nth(2)).toContainText('身份不一致');
  expect(recordReads.some((url) => url.searchParams.get('cursor') === 'connect_next')).toBe(true);
  await page.getByLabel('Connect Client ID', { exact: true }).fill('connect_current_client');
  await page.getByLabel('结果', { exact: true }).selectOption('failed');
  await page.getByLabel('开始时间', { exact: true }).fill('2026-10-05T08:00');
  await page.getByLabel('结束时间', { exact: true }).fill('2026-10-05T09:00');
  await page.getByRole('button', { name: '筛选', exact: true }).click();
  await expect.poll(() => recordReads.at(-1)?.searchParams.get('result')).toBe('failed');
  expect(recordReads.at(-1)?.searchParams.get('upstream_client_id')).toBe('connect_current_client');
  expect(recordReads.at(-1)?.searchParams.get('from')).toBe('2026-10-05T00:00:00.000Z');
  expect(recordReads.at(-1)?.searchParams.has('cursor')).toBe(false);
  await page.getByRole('button', { name: '加载更多应用', exact: true }).click();
  await expect(page.getByRole('link', { name: /第二个应用/ })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  expect(state.secretReads).toBe(0);
  await page.getByRole('link', { name: /校友网站/ }).click();
  await expect(page.getByText('仅应用所有者可查看密钥')).toBeVisible();
  await expect(page.getByLabel('Client Secret', { exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: '轮换密钥', exact: true })).toHaveCount(0);
});

test('non-admin users cannot open administrator details and stale credentials give a restart message', async ({ page }) => {
  const requestedDetails: string[] = [];
  await mockApi(page, { session: userSession }, async (_route, url) => {
    if (url.pathname.startsWith('/api/admin/users/')) requestedDetails.push(url.pathname);
    return false;
  });
  await page.goto(`/admin/users/${fixtureAdminUser.id}`);
  await expect(page).toHaveURL(/\/apps$/);
  expect(requestedDetails).toHaveLength(0);
  await page.goto('/login?error=credential_changed');
  await expect(page.getByRole('alert')).toHaveText('账号信息已更新，请重新开始登录');
  await expect(page.getByRole('button', { name: 'Lite 用户登录', exact: true })).toBeEnabled();
});

test('application return-field documentation separates callback, identity and token surfaces', async ({ page }) => {
  await mockApi(page, { session: userSession });
  await page.goto(`/apps/${fixtureApp.id}`);
  await expect(page.getByRole('heading', { name: '返回字段', exact: true })).toBeVisible();
  const identity = page.getByRole('region', { name: '用户信息', exact: true });
  await expect(identity.getByText('official_connect / lite_self_app')).toBeVisible();
  await expect(identity.getByText('0 / 1 / 2 / 3 / 4')).toBeVisible();
  await page.locator('summary', { hasText: '授权回调' }).click();
  const callback = page.getByRole('region', { name: '授权回调', exact: true });
  await expect(callback.getByText('code', { exact: true })).toBeVisible();
  await expect(callback.getByText('username', { exact: true })).toHaveCount(0);
  await page.locator('summary', { hasText: 'Token 响应' }).click();
  await expect(page.getByRole('region', { name: 'Token 响应', exact: true }).getByText('expires_at', { exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});

test('secrets remain visible after refresh and leave no browser storage or stale value after navigation', async ({ page }) => {
  const state = await mockApi(page, { session: userSession });
  await page.goto('/apps');
  await page.getByRole('button', { name: '创建应用' }).first().click();
  const create = page.getByRole('dialog', { name: '创建 LiteAuth 应用' });
  await create.getByLabel('应用名称', { exact: true }).fill('新应用');
  await create.getByLabel('回调地址（每行一个）').fill('https://example.com/callback');
  await create.getByRole('button', { name: '创建应用', exact: true }).click();
  await expect(page).toHaveURL(/\/apps\/app_created$/);
  const secret = page.getByLabel('Client Secret', { exact: true });
  await expect(secret).toHaveText(newSecret);
  await expect(page.getByRole('dialog', { name: '保存应用密钥' })).toHaveCount(0);
  await page.reload();
  await expect(secret).toHaveText(newSecret);
  const reads = state.secretReads;
  await page.getByRole('link', { name: 'LiteAuth 应用', exact: true }).first().click();
  await expect(secret).toHaveCount(0);
  state.secret = { status: 'available', client_secret: `${newSecret}_changed` };
  await page.getByRole('link', { name: /新应用/ }).click();
  await expect(secret).toHaveText(`${newSecret}_changed`);
  expect(state.secretReads).toBeGreaterThan(reads);
  await page.getByRole('button', { name: '退出登录' }).click();
  await expect(page).toHaveURL(/\/login$/);
  await expect(secret).toHaveCount(0);
  expect(await page.evaluate(() => ({ local: { ...localStorage }, session: { ...sessionStorage } }))).toEqual({ local: {}, session: {} });
});

test('credential loading and failed verification preserve recoverable inputs and existing binding', async ({ page }) => {
  let release!: () => void;
  const pending = new Promise<void>((resolve) => { release = resolve; });
  const state = await mockApi(page, { session: userSession, credentials: { credential: { client_id: 'existing_connect_id', status: 'active', updated_at: '2026-10-05T00:00:00Z' } } }, async (route, url, current) => {
    if (url.pathname === '/api/credentials') {
      await pending;
      await json(route, current.credentials);
      return true;
    }
    if (url.pathname === '/api/credentials/verify') {
      await json(route, { error: { code: 'credential_invalid', message: 'Connect 密钥无效' } }, 400);
      return true;
    }
    return false;
  });
  await page.goto('/credentials');
  await expect(page.getByRole('heading', { name: 'Connect 密钥', exact: true })).toBeVisible();
  await expect(page.getByRole('status')).toContainText('正在加载');
  release();
  await expect(page.getByText('existing_connect_id', { exact: true })).toBeVisible();
  await page.getByLabel('Connect Client ID').fill('candidate_connect_id');
  await page.getByLabel('Connect Client Secret').fill('invalid_candidate_secret');
  await page.getByRole('button', { name: '验证并更新' }).click();
  await expect(page.getByRole('alert')).toContainText('Connect 密钥无效');
  await expect(page.getByLabel('Connect Client ID')).toHaveValue('candidate_connect_id');
  await expect(page.getByLabel('Connect Client Secret')).toHaveValue('invalid_candidate_secret');
  expect(state.credentials.credential?.client_id).toBe('existing_connect_id');
  await expect(page.getByText('existing_connect_id', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: '验证并更新' })).toBeEnabled();
});

test('reduced motion and narrow screens keep login and long credentials usable', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.setViewportSize({ width: 320, height: 740 });
  const app = { ...fixtureApp, name: '较长名称的校友网站应用', client_id: `la_${'x'.repeat(180)}` };
  await mockApi(page, { session: userSession, app, apps: [app] });
  await page.goto(`/apps/${app.id}`);
  await expect(page.getByRole('heading', { name: app.name, exact: true })).toBeVisible();
  const motion = await page.locator('main').evaluate((element) => ({ opacity: getComputedStyle(element).opacity, transform: getComputedStyle(element).transform }));
  expect(motion.opacity).toBe('1');
  expect(motion.transform).toBe('none');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.goto('/login?request=request_test');
  await expect(page.getByRole('button', { name: 'Lite 用户登录', exact: true })).toBeEnabled();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});
