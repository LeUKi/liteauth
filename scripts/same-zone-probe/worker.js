const MAX_BODY_BYTES = 16 * 1024;
const FORBIDDEN_KEYS = new Set([
  'access_token',
  'authorization',
  'client_secret',
  'code',
  'id_token',
  'refresh_token',
  'session_cookie',
  'token',
]);

class ProbeError extends Error {
  constructor(code, details = null) {
    super(code);
    this.code = code;
    this.details = details;
  }
}

function fail(code) {
  throw new ProbeError(code);
}

function ensure(condition, code) {
  if (!condition) fail(code);
}

function json(body, status = 200) {
  return Response.json(body, {
    status,
    headers: {
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

function originFrom(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    fail('invalid_target_origin');
  }
  ensure(url.protocol === 'https:' && !url.username && !url.password && url.pathname === '/' && !url.search && !url.hash, 'invalid_target_origin');
  return url.origin;
}

function safeCompare(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string' || right.length < 24 || left.length !== right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i++) diff |= left.charCodeAt(i) ^ right.charCodeAt(i);
  return diff === 0;
}

function sanitize(value, depth = 0) {
  if (depth > 8) return '[truncated]';
  if (Array.isArray(value)) return value.map((item) => sanitize(item, depth + 1));
  if (!value || typeof value !== 'object') return value;
  const output = {};
  for (const [key, item] of Object.entries(value)) {
    if (FORBIDDEN_KEYS.has(key.toLowerCase())) {
      output[key] = '[redacted]';
    } else {
      output[key] = sanitize(item, depth + 1);
    }
  }
  return output;
}

async function inputFrom(request) {
  const length = Number(request.headers.get('content-length') ?? '0');
  ensure(Number.isFinite(length) && length <= MAX_BODY_BYTES, 'request_too_large');
  const text = await request.text();
  ensure(text.length <= MAX_BODY_BYTES, 'request_too_large');
  try {
    return JSON.parse(text);
  } catch {
    fail('invalid_json');
  }
}

function responseSummary(response) {
  const contentType = response.headers.get('content-type')?.split(';')[0]?.trim() ?? null;
  const location = response.headers.get('location');
  return {
    status: response.status,
    content_type: contentType,
    cache_control: response.headers.get('cache-control') ?? null,
    location: location ? locationShape(location) : null,
    set_cookie_count: response.headers.getSetCookie ? response.headers.getSetCookie().length : Number(response.headers.has('set-cookie')),
  };
}

function locationShape(value) {
  try {
    const url = new URL(value, 'https://relative.invalid');
    return {
      absolute: url.origin !== 'https://relative.invalid',
      origin: url.origin === 'https://relative.invalid' ? null : url.origin,
      pathname: url.pathname,
      has_code: url.searchParams.has('code'),
      has_error: url.searchParams.has('error'),
      has_state: url.searchParams.has('state'),
      has_iss: url.searchParams.has('iss'),
    };
  } catch {
    return { invalid: true };
  }
}

async function safeJson(response) {
  ensure((response.headers.get('content-type') ?? '').includes('application/json'), 'json_required');
  try {
    return await response.json();
  } catch {
    fail('invalid_json_response');
  }
}

function signalFor(deadline) {
  const remaining = deadline - Date.now();
  if (remaining <= 250) fail('probe_deadline_exceeded');
  return AbortSignal.timeout(Math.min(20_000, remaining));
}

async function request(targetOrigin, path, init = {}, deadline = Date.now() + 20_000) {
  const url = path.startsWith('http') ? path : `${targetOrigin}${path}`;
  return fetch(url, {
    ...init,
    redirect: 'manual',
    signal: init.signal ?? signalFor(deadline),
  });
}

async function check(checks, name, run) {
  try {
    const details = await run();
    checks.push({ name, passed: true, ...(details ? { details: sanitize(details) } : {}) });
  } catch (error) {
    checks.push({
      name,
      passed: false,
      error: error instanceof ProbeError ? error.code : 'probe_check_failed',
      ...(error instanceof ProbeError && error.details ? { details: sanitize(error.details) } : {}),
    });
  }
}

function assertStatus(response, expected, code) {
  if (Array.isArray(expected) ? expected.includes(response.status) : response.status === expected) return;
  throw new ProbeError(code, {
    status: response.status,
    expected,
    content_type: response.headers.get('content-type')?.split(';')[0]?.trim() ?? null,
    cache_control: response.headers.get('cache-control') ?? null,
  });
}

async function baseline(targetOrigin, deadline) {
  const checks = [];
  await check(checks, 'health', async () => {
    const response = await request(targetOrigin, '/api/health', {}, deadline);
    assertStatus(response, 200, 'health_status');
    const body = await safeJson(response);
    ensure(body.status === 'ok', 'health_body');
    return responseSummary(response);
  });
  await check(checks, 'discovery', async () => {
    const response = await request(targetOrigin, '/api/auth/.well-known/openid-configuration', {}, deadline);
    assertStatus(response, 200, 'discovery_status');
    const body = await safeJson(response);
    validateMetadata(body, targetOrigin);
    return { ...responseSummary(response), issuer: body.issuer };
  });
  await check(checks, 'well-known-alias', async () => {
    const response = await request(targetOrigin, '/.well-known/openid-configuration', {}, deadline);
    assertStatus(response, 200, 'well_known_alias_status');
    validateMetadata(await safeJson(response), targetOrigin);
    return responseSummary(response);
  });
  await check(checks, 'jwks', async () => {
    const response = await request(targetOrigin, '/api/auth/jwks', {}, deadline);
    assertStatus(response, 200, 'jwks_status');
    const body = await safeJson(response);
    ensure(Array.isArray(body.keys) && body.keys.length > 0, 'jwks_empty');
    ensure(body.keys.every((key) => !['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'].some((field) => field in key)), 'private_jwk_exposed');
    return { ...responseSummary(response), key_count: body.keys.length };
  });
  await check(checks, 'unknown-api-json', async () => {
    const response = await request(targetOrigin, '/api/__same-zone-probe-missing', {}, deadline);
    assertStatus(response, 404, 'unknown_status');
    const body = await safeJson(response);
    ensure(body.error !== undefined, 'unknown_error_shape');
    return responseSummary(response);
  });
  await check(checks, 'anonymous-userinfo-rejected', async () => {
    const summaries = [];
    for (const path of ['/api/auth/oauth2/userinfo', '/oauth2/userinfo', '/api/user']) {
      const response = await request(targetOrigin, path, {}, deadline);
      assertStatus(response, [401, 403], 'anonymous_userinfo_status');
      await safeJson(response);
      summaries.push({ path, ...responseSummary(response) });
    }
    return { paths: summaries };
  });
  await check(checks, 'auth-prefix-error-redirect', async () => {
    const response = await request(targetOrigin, '/auth/connect/callback', {}, deadline);
    assertStatus(response, 302, 'auth_prefix_status');
    const location = new URL(response.headers.get('location'), targetOrigin);
    ensure(location.origin === targetOrigin && location.pathname === '/login', 'auth_error_redirect');
    return responseSummary(response);
  });
  return { passed: checks.every((item) => item.passed), checks };
}

function validateMetadata(metadata, targetOrigin) {
  ensure(metadata.issuer === `${targetOrigin}/api/auth`, 'issuer_mismatch');
  for (const key of ['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri']) {
    ensure(typeof metadata[key] === 'string' && new URL(metadata[key]).origin === targetOrigin, 'metadata_endpoint_origin');
  }
}

function randomString(bytes = 32) {
  const data = new Uint8Array(bytes);
  crypto.getRandomValues(data);
  return base64url(data);
}

function base64url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

async function pkceChallenge(verifier) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return base64url(new Uint8Array(digest));
}

function authHeaders(sessionCookie, targetOrigin) {
  return {
    Accept: 'application/json',
    Cookie: sessionCookie,
    Origin: targetOrigin,
  };
}

async function discovery(targetOrigin, deadline) {
  const response = await request(targetOrigin, '/api/auth/.well-known/openid-configuration', {}, deadline);
  assertStatus(response, 200, 'discovery_status');
  const metadata = await safeJson(response);
  validateMetadata(metadata, targetOrigin);
  return metadata;
}

async function createApp(targetOrigin, sessionCookie, deadline) {
  const response = await request(targetOrigin, '/api/apps', {
    method: 'POST',
    headers: { ...authHeaders(sessionCookie, targetOrigin), 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name: 'Same-zone probe temporary',
      redirect_uris: ['https://same-zone-probe.invalid/callback'],
      client_type: 'public',
      pkce_required: true,
      lite_only: false,
      min_trust_level: 0,
    }),
  }, deadline);
  assertStatus(response, 201, 'create_app_status');
  const body = await safeJson(response);
  ensure(body.app?.client_id && body.app?.id, 'create_app_shape');
  return body.app;
}

function cookiePairsFrom(value) {
  return String(value)
    .split(';')[0]
    .trim();
}

function mergedCookie(base, response) {
  const pairs = new Map();
  for (const chunk of String(base).split(';')) {
    const pair = chunk.trim();
    if (!pair) continue;
    const index = pair.indexOf('=');
    if (index > 0) pairs.set(pair.slice(0, index), pair.slice(index + 1));
  }
  const cookies = response.headers.getSetCookie ? response.headers.getSetCookie() : [];
  for (const setCookie of cookies) {
    const pair = cookiePairsFrom(setCookie);
    const index = pair.indexOf('=');
    if (index > 0) pairs.set(pair.slice(0, index), pair.slice(index + 1));
  }
  return [...pairs].map(([key, value]) => `${key}=${value}`).join('; ');
}

async function authorizationFlow(targetOrigin, metadata, sessionCookie, clientId, scope, deadline) {
  const verifier = randomString(48);
  const state = randomString(24);
  const nonce = scope.includes('openid') ? randomString(24) : null;
  const url = new URL(metadata.authorization_endpoint);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('redirect_uri', 'https://same-zone-probe.invalid/callback');
  url.searchParams.set('scope', scope);
  url.searchParams.set('state', state);
  url.searchParams.set('code_challenge', await pkceChallenge(verifier));
  url.searchParams.set('code_challenge_method', 'S256');
  if (nonce) url.searchParams.set('nonce', nonce);

  const authorize = await request(targetOrigin, url.href, { headers: { Cookie: sessionCookie, Accept: 'application/json' } }, deadline);
  assertStatus(authorize, 302, 'authorize_redirect_status');
  const browserCookie = mergedCookie(sessionCookie, authorize);
  const firstLocation = authorize.headers.get('location');
  ensure(firstLocation, 'authorize_location_missing');
  const first = new URL(firstLocation, targetOrigin);
  let callback;
  let consentSummary = null;
  if (first.origin === targetOrigin && first.pathname === '/consent') {
    const requestId = first.searchParams.get('request');
    ensure(requestId, 'consent_request_missing');
    const consent = await request(targetOrigin, '/api/consent', {
      method: 'POST',
      headers: { ...authHeaders(browserCookie, targetOrigin), 'Content-Type': 'application/json' },
      body: JSON.stringify({ request: requestId, accept: true }),
    }, deadline);
    assertStatus(consent, 200, 'consent_status');
    const body = await safeJson(consent);
    ensure(body.redirect_url, 'consent_redirect_missing');
    callback = new URL(body.redirect_url);
    consentSummary = responseSummary(consent);
  } else {
    callback = first;
  }
  ensure(callback.origin === 'https://same-zone-probe.invalid', 'callback_origin');
  ensure(callback.searchParams.get('state') === state, 'callback_state');
  ensure(callback.searchParams.has('code'), 'callback_code_missing');
  return {
    callback,
    verifier,
    nonce,
    authorize: responseSummary(authorize),
    consent: consentSummary,
  };
}

async function tokenRequest(metadata, clientId, callback, verifier, deadline) {
  return request(metadata.token_endpoint, metadata.token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: clientId,
      redirect_uri: 'https://same-zone-probe.invalid/callback',
      code: callback.searchParams.get('code') ?? '',
      code_verifier: verifier,
    }),
  }, deadline);
}

async function patchAppPolicy(targetOrigin, sessionCookie, app, policy, deadline) {
  const response = await request(targetOrigin, `/api/apps/${app.id}`, {
    method: 'PATCH',
    headers: { ...authHeaders(sessionCookie, targetOrigin), 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name: app.name,
      redirect_uris: app.redirect_uris,
      client_type: app.client_type,
      pkce_required: app.pkce_required,
      lite_only: policy.lite_only,
      min_trust_level: policy.min_trust_level,
    }),
  }, deadline);
  assertStatus(response, 200, 'patch_app_status');
  const body = await safeJson(response);
  ensure(body.app?.client_id === app.client_id, 'patch_app_shape');
  return body.app;
}

async function policyDeniedFlow(targetOrigin, metadata, sessionCookie, app, deadline) {
  const verifier = randomString(48);
  const url = new URL(metadata.authorization_endpoint);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', app.client_id);
  url.searchParams.set('redirect_uri', 'https://same-zone-probe.invalid/callback');
  url.searchParams.set('scope', 'profile');
  url.searchParams.set('state', randomString(24));
  url.searchParams.set('code_challenge', await pkceChallenge(verifier));
  url.searchParams.set('code_challenge_method', 'S256');
  const authorize = await request(targetOrigin, url.href, { headers: { Cookie: sessionCookie, Accept: 'application/json' } }, deadline);
  assertStatus(authorize, 302, 'policy_authorize_redirect_status');
  const browserCookie = mergedCookie(sessionCookie, authorize);
  const location = authorize.headers.get('location');
  ensure(location, 'policy_location_missing');
  const first = new URL(location, targetOrigin);
  ensure(first.origin === targetOrigin, 'policy_unexpected_callback');
  if (first.pathname === '/consent') {
    const context = await request(targetOrigin, `/api/consent?request=${encodeURIComponent(first.searchParams.get('request') ?? '')}`, {
      headers: { Cookie: browserCookie, Accept: 'application/json' },
    }, deadline);
    assertStatus(context, 200, 'policy_consent_context_status');
    const body = await safeJson(context);
    ensure(body.eligibility?.reason === 'trust_level_required', 'policy_consent_reason');
    const accept = await request(targetOrigin, '/api/consent', {
      method: 'POST',
      headers: { ...authHeaders(browserCookie, targetOrigin), 'Content-Type': 'application/json' },
      body: JSON.stringify({ request: first.searchParams.get('request'), accept: true }),
    }, deadline);
    assertStatus(accept, 403, 'policy_accept_status');
    return { location: locationShape(location), context: responseSummary(context), accept: responseSummary(accept) };
  }
  if (first.pathname === '/login') {
    const context = await request(targetOrigin, `/api/login-context?request=${encodeURIComponent(first.searchParams.get('request') ?? '')}`, {
      headers: { Cookie: browserCookie, Accept: 'application/json' },
    }, deadline);
    assertStatus(context, 200, 'policy_login_context_status');
    const body = await safeJson(context);
    ensure(body.eligibility?.reason === 'trust_level_required', 'policy_login_reason');
    return { location: locationShape(location), context: responseSummary(context) };
  }
  fail('policy_redirect_shape');
}

function assertIdentity(body, expected) {
  ensure(body && typeof body === 'object', 'identity_shape');
  ensure(body.sub === expected.user_id, 'subject_mismatch');
  ensure(body.id === expected.linuxdo_id, 'linuxdo_id_mismatch');
  ensure(body.username === expected.username, 'username_mismatch');
  ensure(body.login_method === expected.login_method, 'login_method_mismatch');
  ensure(body.auth_source === 'linuxdo', 'auth_source_mismatch');
  ensure(body.access_token === undefined && body.id_token === undefined && body.refresh_token === undefined, 'identity_token_leak');
}

async function protocol(targetOrigin, input, deadline) {
  ensure(typeof input.session_cookie === 'string' && input.session_cookie.length > 20, 'session_cookie_required');
  ensure(input.expected && typeof input.expected === 'object', 'expected_required');
  const expected = input.expected;
  const checks = [];
  let app = null;
  let metadata = null;
  let issuedAccessToken = null;

  await check(checks, 'discovery-and-jwks', async () => {
    metadata = await discovery(targetOrigin, deadline);
    const jwks = await request(targetOrigin, new URL(metadata.jwks_uri).pathname, {}, deadline);
    assertStatus(jwks, 200, 'jwks_status');
    return { issuer: metadata.issuer, jwks: responseSummary(jwks) };
  });

  await check(checks, 'session-and-app-create', async () => {
    const session = await request(targetOrigin, '/api/session', { headers: { Cookie: input.session_cookie, Accept: 'application/json' } }, deadline);
    assertStatus(session, 200, 'session_status');
    const sessionBody = await safeJson(session);
    ensure(sessionBody.user?.id === expected.user_id, 'session_user_mismatch');
    app = await createApp(targetOrigin, input.session_cookie, deadline);
    return { client_id: app.client_id, session: responseSummary(session) };
  });

  await check(checks, 'oidc-code-token-userinfo-replay', async () => {
    ensure(metadata && app, 'protocol_prerequisite_missing');
    const flow = await authorizationFlow(targetOrigin, metadata, input.session_cookie, app.client_id, 'openid profile', deadline);
    const token = await tokenRequest(metadata, app.client_id, flow.callback, flow.verifier, deadline);
    assertStatus(token, 200, 'token_status');
    const tokenBody = await safeJson(token);
    ensure(typeof tokenBody.access_token === 'string' && tokenBody.access_token.length > 20, 'access_token_missing');
    ensure(typeof tokenBody.id_token === 'string' && tokenBody.id_token.length > 20, 'id_token_missing');
    const userinfo = await request(metadata.userinfo_endpoint, metadata.userinfo_endpoint, {
      headers: { Authorization: `Bearer ${tokenBody.access_token}`, Accept: 'application/json' },
    }, deadline);
    assertStatus(userinfo, 200, 'userinfo_status');
    assertIdentity(await safeJson(userinfo), expected);
    const replay = await tokenRequest(metadata, app.client_id, flow.callback, flow.verifier, deadline);
    assertStatus(replay, 400, 'replay_status');
    const replayBody = await safeJson(replay);
    ensure(replayBody.error === 'invalid_grant', 'replay_error');
    ensure(replayBody.access_token === undefined && replayBody.id_token === undefined, 'replay_token_leak');
    return { authorize: flow.authorize, consent: flow.consent, token: responseSummary(token), userinfo: responseSummary(userinfo), replay: responseSummary(replay) };
  });

  await check(checks, 'oauth-code-token-compat-userinfo', async () => {
    ensure(metadata && app, 'protocol_prerequisite_missing');
    const flow = await authorizationFlow(targetOrigin, metadata, input.session_cookie, app.client_id, 'profile', deadline);
    const token = await tokenRequest(metadata, app.client_id, flow.callback, flow.verifier, deadline);
    assertStatus(token, 200, 'oauth_token_status');
    const tokenBody = await safeJson(token);
    ensure(typeof tokenBody.access_token === 'string' && tokenBody.access_token.length > 20, 'oauth_access_token_missing');
    ensure(tokenBody.id_token === undefined, 'oauth_id_token_unexpected');
    // The earlier OIDC code is deliberately replayed; the provider revokes that
    // code's tokens. Use this independent, unreplayed grant for policy history.
    issuedAccessToken = tokenBody.access_token;
    const userinfo = await request(targetOrigin, '/api/user', {
      headers: { Authorization: `Bearer ${tokenBody.access_token}`, Accept: 'application/json' },
    }, deadline);
    assertStatus(userinfo, 200, 'compat_userinfo_status');
    assertIdentity(await safeJson(userinfo), expected);
    return { authorize: flow.authorize, token: responseSummary(token), userinfo: responseSummary(userinfo) };
  });

  await check(checks, 'wrong-code-rejected', async () => {
    ensure(metadata && app, 'protocol_prerequisite_missing');
    const response = await request(metadata.token_endpoint, metadata.token_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: app.client_id,
        redirect_uri: 'https://same-zone-probe.invalid/callback',
        code: `bad_${randomString(12)}`,
        code_verifier: randomString(48),
      }),
    }, deadline);
    assertStatus(response, 400, 'wrong_code_status');
    const body = await safeJson(response);
    ensure(body.error === 'invalid_grant', 'wrong_code_error');
    ensure(body.access_token === undefined && body.id_token === undefined, 'wrong_code_token_leak');
    return responseSummary(response);
  });

  await check(checks, 'lite-only-minlevel-policy', async () => {
    ensure(metadata && app, 'protocol_prerequisite_missing');
    app = await patchAppPolicy(targetOrigin, input.session_cookie, app, { lite_only: true, min_trust_level: 0 }, deadline);
    const allowed = await authorizationFlow(targetOrigin, metadata, input.session_cookie, app.client_id, 'profile', deadline);
    const allowedToken = await tokenRequest(metadata, app.client_id, allowed.callback, allowed.verifier, deadline);
    assertStatus(allowedToken, 200, 'lite_only_token_status');
    app = await patchAppPolicy(targetOrigin, input.session_cookie, app, { lite_only: true, min_trust_level: 4 }, deadline);
    const denied = await policyDeniedFlow(targetOrigin, metadata, input.session_cookie, app, deadline);
    ensure(issuedAccessToken, 'historical_token_missing');
    const historical = await request(targetOrigin, '/api/user', {
      headers: { Authorization: `Bearer ${issuedAccessToken}`, Accept: 'application/json' },
    }, deadline);
    assertStatus(historical, 200, 'historical_userinfo_status');
    assertIdentity(await safeJson(historical), expected);
    return { allowed: responseSummary(allowedToken), denied, historical_userinfo: responseSummary(historical) };
  });

  return { passed: checks.every((item) => item.passed), app_client_id: app?.client_id ?? null, checks };
}

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      if (request.method !== 'POST' || !url.pathname.endsWith('/run')) return json({ error: 'not_found' }, 404);
      ensure(Number(env.PROBE_EXPIRES_AT) > Math.floor(Date.now() / 1000), 'probe_expired');
      ensure(safeCompare(request.headers.get('X-Probe-Token'), env.PROBE_TOKEN), 'unauthorized');
      const targetOrigin = originFrom(env.TARGET_ORIGIN);
      const input = await inputFrom(request);
      ensure(input.mode === 'baseline' || input.mode === 'protocol', 'invalid_mode');
      const deadline = Date.now() + 45_000;
      const result = input.mode === 'baseline' ? await baseline(targetOrigin, deadline) : await protocol(targetOrigin, input, deadline);
      return json({ target_origin: targetOrigin, mode: input.mode, ...sanitize(result) }, result.passed ? 200 : 424);
    } catch (error) {
      return json({ passed: false, error: error instanceof ProbeError ? error.code : 'probe_failed' }, error instanceof ProbeError && error.code === 'unauthorized' ? 401 : 400);
    }
  },
};
