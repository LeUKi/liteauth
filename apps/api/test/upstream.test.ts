import { afterEach, describe, expect, it, vi } from 'vitest';
import { finishUpstream, startUpstream, type ConnectProfile } from '../src/upstream';

const clientId = 'fixture-connect-app';
const secret = 'fixture-connect-secret';
const callbackUrl = 'https://auth.example.com/auth/connect/callback';
const profile: ConnectProfile = {
  id: 123,
  username: 'alice',
  name: 'Alice',
  avatar_url: 'https://linux.do/fixture-avatar.png',
  trust_level: 0,
  active: true,
  silenced: false,
};

function responseUrl(state: string): URL {
  const url = new URL(callbackUrl);
  url.searchParams.set('state', state);
  url.searchParams.set('code', 'fixture-authorization-code');
  return url;
}

function mockConnect(userInfo: unknown = profile, tokenResponse?: Response, profileResponse?: Response) {
  const requests: { url: string; method: string; headers: Headers; body: string }[] = [];
  const fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = new Request(input instanceof URL ? input.href : input, init);
    requests.push({ url: request.url, method: request.method, headers: request.headers, body: await request.text() });
    if (request.url === 'https://connect.linux.do/oauth2/token') {
      return tokenResponse ?? Response.json({
        access_token: 'fixture-upstream-access-token',
        refresh_token: 'fixture-upstream-refresh-token',
        token_type: 'Bearer',
        expires_in: 3600,
      });
    }
    if (request.url === 'https://connect.linux.do/api/user') return profileResponse ?? Response.json(userInfo);
    throw new Error('Unexpected upstream URL');
  });
  vi.stubGlobal('fetch', fetch);
  return { fetch, requests };
}

afterEach(() => { vi.unstubAllGlobals(); });

describe('Connect OAuth client', () => {
  it('starts a fixed-endpoint OAuth flow with fresh state and S256 without exposing the secret', async () => {
    const transport = mockConnect();
    const first = await startUpstream(clientId, secret, callbackUrl);
    const second = await startUpstream(clientId, secret, callbackUrl);
    const url = new URL(first.authorizationUrl);
    expect(url.origin + url.pathname).toBe('https://connect.linux.do/oauth2/authorize');
    expect(url.searchParams.get('client_id')).toBe(clientId);
    expect(url.searchParams.get('redirect_uri')).toBe(callbackUrl);
    expect(url.searchParams.get('response_type')).toBe('code');
    expect(url.searchParams.get('scope')).toBe('user');
    expect(url.searchParams.get('state')).toBe(first.state);
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('code_challenge')).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(first.codeVerifier).toMatch(/^[A-Za-z0-9._~-]{43,128}$/);
    expect(first.state).not.toBe(second.state);
    expect(first.codeVerifier).not.toBe(second.codeVerifier);
    expect(first.authorizationUrl).not.toContain(secret);
    expect(url.searchParams.has('client_secret')).toBe(false);
    expect(url.searchParams.has('nonce')).toBe(false);
    expect(transport.fetch).not.toHaveBeenCalled();
  });

  it('uses the actual library to exchange code and fetch a whitelisted profile', async () => {
    const transport = mockConnect({ ...profile, api_key: 'fixture-api-key', access_token: 'unexpected-token',
      client_secret: secret, external_ids: { upstream: 'private' }, email: 'private@example.test' });
    const flow = await startUpstream(clientId, secret, callbackUrl);
    const result = await finishUpstream(clientId, secret, callbackUrl, responseUrl(flow.state).href, flow.state, flow.codeVerifier);
    expect(result).toEqual(profile);
    expect(transport.requests).toHaveLength(2);
    const tokenRequest = transport.requests[0];
    expect(tokenRequest.method).toBe('POST');
    const body = new URLSearchParams(tokenRequest.body);
    expect(body.get('grant_type')).toBe('authorization_code');
    expect(body.get('client_id')).toBe(clientId);
    expect(body.get('client_secret')).toBe(secret);
    expect(body.get('code')).toBe('fixture-authorization-code');
    expect(body.get('redirect_uri')).toBe(callbackUrl);
    expect(body.get('code_verifier')).toBe(flow.codeVerifier);
    expect(transport.requests[1].method).toBe('GET');
    expect(transport.requests[1].headers.get('Authorization')).toBe('Bearer fixture-upstream-access-token');
    expect(JSON.stringify(result)).not.toContain('fixture-api-key');
    expect(JSON.stringify(result)).not.toContain('token');
    expect(JSON.stringify(result)).not.toContain(secret);
  });

  it.each(['mismatch', 'missing', 'duplicate'])('rejects %s state through library validation before contacting Connect', async (mode) => {
    const transport = mockConnect();
    const flow = await startUpstream(clientId, secret, callbackUrl);
    const url = responseUrl(flow.state);
    if (mode === 'mismatch') url.searchParams.set('state', 'other-state');
    if (mode === 'missing') url.searchParams.delete('state');
    if (mode === 'duplicate') url.searchParams.append('state', 'other-state');
    await expect(finishUpstream(clientId, secret, callbackUrl, url.href, flow.state, flow.codeVerifier)).rejects.toThrow('登录验证失败');
    expect(transport.fetch).not.toHaveBeenCalled();
  });

  it.each([
    'https://evil.example/auth/connect/callback',
    'https://auth.example.com/another-callback',
    'https://user:password@auth.example.com/auth/connect/callback',
    'https://auth.example.com/auth/connect/callback#fragment',
  ])('rejects a substituted callback before exchanging credentials', async (changedCallback) => {
    const transport = mockConnect();
    const flow = await startUpstream(clientId, secret, callbackUrl);
    await expect(finishUpstream(clientId, secret, callbackUrl, changedCallback, flow.state, flow.codeVerifier)).rejects.toThrow('回调地址无效');
    expect(transport.fetch).not.toHaveBeenCalled();
  });

  it.each([
    null,
    { ...profile, id: 0 },
    { ...profile, id: 1.5 },
    { ...profile, id: '123' },
    { ...profile, username: '' },
    { ...profile, trust_level: 5 },
    { ...profile, active: 'true' },
    { ...profile, silenced: null },
  ])('rejects malformed user identity and security fields', async (invalidProfile) => {
    mockConnect(invalidProfile);
    const flow = await startUpstream(clientId, secret, callbackUrl);
    await expect(finishUpstream(clientId, secret, callbackUrl, responseUrl(flow.state).href, flow.state, flow.codeVerifier)).rejects.toThrow('账号信息无效');
  });

  it('uses only safe display defaults without fabricating permissions or an email', async () => {
    const { name: _name, avatar_url: _avatar, ...withoutDisplayFields } = profile;
    mockConnect({ ...withoutDisplayFields, avatar_template: '/user_avatar/linux.do/alice/{size}/fixture.png',
      api_key: 'fixture-api-key' });
    const flow = await startUpstream(clientId, secret, callbackUrl);
    const result = await finishUpstream(clientId, secret, callbackUrl, responseUrl(flow.state).href, flow.state, flow.codeVerifier);
    expect(result).toEqual({ ...profile, name: 'alice', avatar_url: null });
  });

  it('sanitizes token exchange failures instead of returning upstream descriptions', async () => {
    mockConnect(profile, Response.json({ error: 'invalid_client', error_description: `${secret} fixture-api-key` }, { status: 400 }));
    const flow = await startUpstream(clientId, secret, callbackUrl);
    let failure: unknown;
    try { await finishUpstream(clientId, secret, callbackUrl, responseUrl(flow.state).href, flow.state, flow.codeVerifier); }
    catch (error) { failure = error; }
    expect(failure).toMatchObject({ status: 502, code: 'connect_login_failed' });
    expect(String(failure)).not.toContain(secret);
    expect(String(failure)).not.toContain('fixture-api-key');
  });

  it.each([
    () => Response.json({ error: 'unauthorized' }, { status: 401 }),
    () => new Response('<html>fixture-api-key</html>', { headers: { 'Content-Type': 'text/html' } }),
  ])('rejects unsuccessful or non-JSON profile responses', async (makeResponse) => {
    mockConnect(profile, undefined, makeResponse());
    const flow = await startUpstream(clientId, secret, callbackUrl);
    await expect(finishUpstream(clientId, secret, callbackUrl, responseUrl(flow.state).href, flow.state, flow.codeVerifier)).rejects.toThrow();
  });
});
