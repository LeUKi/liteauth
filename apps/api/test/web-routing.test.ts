import { env as apiEnv } from 'cloudflare:workers';
import { describe, expect, it, vi } from 'vitest';
import webWorker from '../../web/worker';
import { app } from '../src/index';

type WebEnv = { ASSETS: Fetcher; API?: Fetcher };
type ApiFetchInit = { redirect?: 'follow' | 'manual' | 'error' };
type ApiFetchHandler = (request: Request, init?: ApiFetchInit) => Response | Promise<Response>;

function assets(response = new Response('<!doctype html>', { headers: { 'Content-Type': 'text/html' } })) {
  return { fetch: vi.fn(async () => response.clone()) } as unknown as Fetcher & { fetch: ReturnType<typeof vi.fn> };
}

function api(fetch: ApiFetchHandler) {
  return { fetch: vi.fn((request: Request, init?: ApiFetchInit) => fetch(request, init)) } as unknown as Fetcher & { fetch: ReturnType<typeof vi.fn> };
}

function webEnv(overrides: { API?: Fetcher; ASSETS?: Fetcher }): WebEnv {
  return { ASSETS: overrides.ASSETS ?? assets(), API: overrides.API };
}

function dispatch(request: Request, env: WebEnv) {
  return (webWorker as { fetch(request: Request, env: WebEnv): Promise<Response> }).fetch(request, env);
}

describe('web worker same-zone API forwarding', () => {
  it.each(['/api', '/api/health', '/auth', '/auth/connect/callback', '/oauth2', '/oauth2/userinfo', '/.well-known', '/.well-known/openid-configuration'])('forwards reserved path %s through the API binding', async (path) => {
    const boundApi = api(async () => new Response('api-ok', { status: 202 }));
    const staticAssets = assets();
    const response = await dispatch(new Request(`https://liteauth.example${path}?q=1`), webEnv({ API: boundApi, ASSETS: staticAssets }));
    expect(response.status).toBe(202);
    expect(await response.text()).toBe('api-ok');
    expect(boundApi.fetch).toHaveBeenCalledTimes(1);
    expect(staticAssets.fetch).not.toHaveBeenCalled();
  });

  it.each(['/apiary', '/authenticate', '/oauth2callback', '/.well-knownish', '/apps/api'])('keeps similar non-reserved path %s on the SPA asset binding', async (path) => {
    const boundApi = api(async () => new Response('wrong'));
    const staticAssets = assets(new Response('<main>spa</main>', { headers: { 'Content-Type': 'text/html' } }));
    const response = await dispatch(new Request(`https://liteauth.example${path}`), webEnv({ API: boundApi, ASSETS: staticAssets }));
    expect(response.status).toBe(200);
    expect(await response.text()).toBe('<main>spa</main>');
    expect(boundApi.fetch).not.toHaveBeenCalled();
    expect(staticAssets.fetch).toHaveBeenCalledTimes(1);
    expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff');
  });

  it('passes the original request to the API once and returns the API response unchanged', async () => {
    const body = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('streamed-body'));
        controller.close();
      },
    });
    let forwardedRequest: Request | undefined;
    const seen: { url?: string; method?: string; authorization?: string | null; cookie?: string | null; origin?: string | null; body?: string; redirect?: ApiFetchInit['redirect'] } = {};
    const apiResponse = new Response(new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('api-stream'));
        controller.close();
      },
    }), {
      status: 302,
      headers: (() => {
        const headers = new Headers({ Location: 'https://rp.example/callback?code=abc', 'X-Api-Header': 'kept' });
        headers.append('Set-Cookie', 'a=1; Path=/; HttpOnly');
        headers.append('Set-Cookie', 'b=2; Path=/; Secure');
        return headers;
      })(),
    });
    const boundApi = api(async (request, init) => {
      forwardedRequest = request;
      seen.url = request.url;
      seen.method = request.method;
      seen.authorization = request.headers.get('Authorization');
      seen.cookie = request.headers.get('Cookie');
      seen.origin = request.headers.get('Origin');
      seen.body = await request.text();
      seen.redirect = init?.redirect;
      return apiResponse;
    });
    const staticAssets = assets();
    const request = new Request('https://liteauth.example/oauth2/token?debug=1', {
      method: 'POST',
      headers: { Authorization: 'Bearer test-token', Cookie: 'sid=123', Origin: 'https://rp.example', 'Content-Type': 'text/plain' },
      body,
    });
    const response = await dispatch(request, webEnv({ API: boundApi, ASSETS: staticAssets }));

    expect(boundApi.fetch).toHaveBeenCalledTimes(1);
    expect(staticAssets.fetch).not.toHaveBeenCalled();
    expect(forwardedRequest).toBe(request);
    expect(response).toBe(apiResponse);
    expect(seen).toEqual({
      url: 'https://liteauth.example/oauth2/token?debug=1',
      method: 'POST',
      authorization: 'Bearer test-token',
      cookie: 'sid=123',
      origin: 'https://rp.example',
      body: 'streamed-body',
      redirect: 'manual',
    });
    expect(response.status).toBe(302);
    expect(response.headers.get('Location')).toBe('https://rp.example/callback?code=abc');
    expect(response.headers.get('X-Api-Header')).toBe('kept');
    expect(response.headers.getSetCookie()).toEqual(['a=1; Path=/; HttpOnly', 'b=2; Path=/; Secure']);
    expect(response.headers.get('X-Content-Type-Options')).toBeNull();
    expect(await response.text()).toBe('api-stream');
  });

  it.each([404, 500])('passes through API %s responses without wrapping them', async (status) => {
    const apiResponse = Response.json({ from: 'api', status }, { status, headers: { 'X-Api-Error': 'kept' } });
    const boundApi = api(async () => apiResponse);
    const staticAssets = assets();
    const response = await dispatch(new Request('https://liteauth.example/api/not-found'), webEnv({ API: boundApi, ASSETS: staticAssets }));
    expect(response).toBe(apiResponse);
    expect(response.status).toBe(status);
    expect(response.headers.get('X-Api-Error')).toBe('kept');
    expect(await response.json()).toEqual({ from: 'api', status });
    expect(staticAssets.fetch).not.toHaveBeenCalled();
  });

  it('returns no-store 503 when the API binding is unavailable and does not fall back to static assets', async () => {
    const staticAssets = assets();
    const missing = await dispatch(new Request('https://liteauth.example/api/health'), webEnv({ ASSETS: staticAssets }));
    expect(missing.status).toBe(503);
    expect(missing.headers.get('Cache-Control')).toBe('no-store');
    expect(await missing.json()).toEqual({ error: { code: 'service_unavailable', message: '服务暂时不可用' } });
    expect(staticAssets.fetch).not.toHaveBeenCalled();

    const throwingApi = api(async () => { throw new Error('binding down'); });
    const thrown = await dispatch(new Request('https://liteauth.example/api/health'), webEnv({ API: throwingApi, ASSETS: staticAssets }));
    expect(thrown.status).toBe(503);
    expect(await thrown.json()).toEqual({ error: { code: 'service_unavailable', message: '服务暂时不可用' } });
    expect(throwingApi.fetch).toHaveBeenCalledTimes(1);
    expect(staticAssets.fetch).not.toHaveBeenCalled();
  });

  it('preserves API enforcement for forwarded public requests', async () => {
    const boundApi = api((request) => Promise.resolve(app.fetch(request, apiEnv)));
    const staticAssets = assets();
    const health = await dispatch(new Request(`${apiEnv.APP_ORIGIN}/api/health`), webEnv({ API: boundApi, ASSETS: staticAssets }));
    expect(health.status).toBe(200);
    expect(await health.json()).toEqual({ status: 'ok' });

    const preflight = await dispatch(new Request(`${apiEnv.APP_ORIGIN}/oauth2/token`, { method: 'OPTIONS', headers: { Origin: 'https://rp.example' } }), webEnv({ API: boundApi, ASSETS: staticAssets }));
    expect(preflight.status).toBe(204);
    expect(preflight.headers.get('Access-Control-Allow-Origin')).toBe('https://rp.example');
    expect(preflight.headers.get('Access-Control-Allow-Methods')).toContain('POST');

    const unknownApi = await dispatch(new Request(`${apiEnv.APP_ORIGIN}/api/does-not-exist`), webEnv({ API: boundApi, ASSETS: staticAssets }));
    expect(unknownApi.status).toBe(404);
    expect(await unknownApi.json()).toEqual({ error: { code: 'not_found', message: '页面不存在' } });

    const unauthenticated = await dispatch(new Request(`${apiEnv.APP_ORIGIN}/api/apps`, { headers: { Origin: apiEnv.APP_ORIGIN } }), webEnv({ API: boundApi, ASSETS: staticAssets }));
    expect(unauthenticated.status).toBe(401);
    expect(await unauthenticated.json()).toEqual({ error: { code: 'login_required', message: '请先登录' } });

    const badOrigin = await dispatch(new Request(`${apiEnv.APP_ORIGIN}/api/login/lite`, {
      method: 'POST',
      headers: { Origin: 'https://evil.example', 'Content-Type': 'application/json' },
      body: '{}',
    }), webEnv({ API: boundApi, ASSETS: staticAssets }));
    expect(badOrigin.status).toBe(403);
    expect(await badOrigin.json()).toEqual({ error: { code: 'invalid_origin', message: '请求无效，请刷新页面后重试' } });

    const oversized = await dispatch(new Request(`${apiEnv.APP_ORIGIN}/oauth2/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `grant_type=authorization_code&${'x'.repeat(64 * 1024)}`,
    }), webEnv({ API: boundApi, ASSETS: staticAssets }));
    expect(oversized.status).toBe(413);
    expect(await oversized.json()).toEqual({ error: 'invalid_request', error_description: 'Payload too large' });
    expect(staticAssets.fetch).not.toHaveBeenCalled();
  });
});
