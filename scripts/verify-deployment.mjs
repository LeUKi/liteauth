const checks = [];
class CheckFailure extends Error {
  constructor(code) { super(code); this.code = code; }
}
function ensure(condition, code) { if (!condition) throw new CheckFailure(code); }
let origin;
try {
  const url = new URL(process.argv[2] ?? 'http://127.0.0.1:8798');
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  ensure(url.protocol === 'https:' || (url.protocol === 'http:' && local), 'https_or_loopback_required');
  ensure(!url.username && !url.password && url.pathname === '/' && !url.search && !url.hash, 'origin_required');
  origin = url.origin;
} catch {
  console.log(JSON.stringify({ passed: false, error: 'invalid_origin' }));
  process.exit(1);
}
const issuer = origin + '/api/auth';

async function request(path, init = {}) {
  return fetch(new URL(path, origin), { ...init, redirect: 'error', signal: AbortSignal.timeout(15_000) });
}
async function readJson(response) {
  ensure(/application\/json/i.test(response.headers.get('content-type') ?? ''), 'json_response_required');
  try { return await response.json(); } catch { throw new CheckFailure('invalid_json'); }
}
async function check(name, run) {
  try { await run(); checks.push({ name, passed: true }); }
  catch (error) {
    // Never serialize HTTP bodies, assertion values, tokens, JWK secrets, or arbitrary errors.
    checks.push({ name, passed: false, error: error instanceof CheckFailure ? error.code : 'network_or_check_failure' });
  }
}

await check('SPA deep link and security headers', async () => {
  const response = await request('/apps');
  ensure(response.status === 200, 'spa_status');
  ensure(/text\/html/i.test(response.headers.get('content-type') ?? ''), 'spa_content_type');
  ensure(response.headers.get('x-content-type-options') === 'nosniff', 'nosniff_missing');
  ensure(response.headers.get('x-frame-options') === 'DENY', 'frame_protection_missing');
  ensure(/frame-ancestors 'none'/.test(response.headers.get('content-security-policy') ?? ''), 'csp_missing');
  const html = await response.text();
  ensure(/id="root"/.test(html), 'spa_mount_missing');
  ensure(!/local-unconfigured|replace-with-a-random-secret/.test(html), 'placeholder_configuration');
});

await check('Unknown reserved routes stay JSON', async () => {
  for (const path of ['/api/does-not-exist', '/auth/does-not-exist', '/oauth2/does-not-exist', '/.well-known/does-not-exist']) {
    const response = await request(path);
    ensure(response.status === 404, 'reserved_route_status');
    const body = await readJson(response);
    ensure(body && typeof body === 'object' && body.error !== undefined, 'reserved_route_error_shape');
  }
});

await check('Anonymous session and protected management', async () => {
  const response = await request('/api/session');
  ensure(response.status === 200, 'anonymous_session_status');
  ensure(/no-store/.test(response.headers.get('cache-control') ?? ''), 'session_cache_protection');
  const session = await readJson(response);
  ensure(session.user === null && session.login_method === null, 'anonymous_session_shape');
  for (const path of ['/api/apps', '/api/credentials', '/api/admin/users', '/api/admin/users/verification-probe',
    '/api/admin/users/verification-probe/apps', '/api/admin/users/verification-probe/connect-records', '/api/admin/apps', '/api/admin/audit']) {
    const restricted = await request(path);
    ensure([401, 403].includes(restricted.status), 'management_requires_authentication');
    await readJson(restricted);
  }
});

await check('OIDC discovery, issuer and advertised profile', async () => {
  const response = await request('/api/auth/.well-known/openid-configuration');
  ensure(response.status === 200, 'discovery_status');
  const metadata = await readJson(response);
  ensure(metadata.issuer === issuer, 'issuer_mismatch');
  ensure(Array.isArray(metadata.grant_types_supported) && metadata.grant_types_supported.length === 1 && metadata.grant_types_supported[0] === 'authorization_code', 'grant_profile');
  ensure(Array.isArray(metadata.response_types_supported) && metadata.response_types_supported.length === 1 && metadata.response_types_supported[0] === 'code', 'response_profile');
  ensure(metadata.code_challenge_methods_supported?.includes('S256'), 's256_missing');
  ensure(!metadata.code_challenge_methods_supported?.includes('plain'), 'plain_pkce_advertised');
  ensure(metadata.scopes_supported?.includes('openid') && metadata.scopes_supported?.includes('profile'), 'required_scopes_missing');
  ensure(!metadata.scopes_supported?.includes('offline_access'), 'refresh_scope_advertised');
  ensure(Array.isArray(metadata.token_endpoint_auth_methods_supported) && metadata.token_endpoint_auth_methods_supported.length === 2 && metadata.token_endpoint_auth_methods_supported.includes('client_secret_post') && metadata.token_endpoint_auth_methods_supported.includes('none'), 'client_auth_profile');
  ensure(Array.isArray(metadata.revocation_endpoint_auth_methods_supported) && metadata.revocation_endpoint_auth_methods_supported.length === 2 && metadata.revocation_endpoint_auth_methods_supported.includes('client_secret_post') && metadata.revocation_endpoint_auth_methods_supported.includes('none'), 'revocation_auth_profile');
  ensure(Array.isArray(metadata.introspection_endpoint_auth_methods_supported) && metadata.introspection_endpoint_auth_methods_supported.length === 1 && metadata.introspection_endpoint_auth_methods_supported[0] === 'client_secret_post', 'introspection_auth_profile');
  ensure(metadata.end_session_endpoint === undefined, 'unsupported_logout_advertised');
  for (const claim of ['login_method', 'auth_source', 'upstream_client_id', 'liteauth_user_id']) ensure(metadata.claims_supported?.includes(claim), 'authentication_claims_missing');
  for (const key of ['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri']) ensure(typeof metadata[key] === 'string' && new URL(metadata[key]).origin === origin, 'endpoint_origin_mismatch');
  const keys = await request(metadata.jwks_uri);
  ensure(keys.status === 200, 'jwks_status');
  const jwks = await readJson(keys);
  ensure(Array.isArray(jwks.keys) && jwks.keys.length > 0, 'jwks_empty');
  for (const key of jwks.keys) {
    ensure(key && typeof key === 'object', 'jwk_shape');
    ensure(!['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'].some((field) => field in key), 'private_jwk_exposed');
  }
});

await check('Identity APIs reject anonymous requests', async () => {
  for (const path of ['/api/auth/oauth2/userinfo', '/api/user']) {
    const response = await request(path);
    ensure([401, 403].includes(response.status), 'anonymous_identity_response');
    await readJson(response);
  }
});

await check('Unauthenticated unsupported-grant requests return no tokens', async () => {
  for (const grant of ['client_credentials', 'password', 'refresh_token', 'urn:ietf:params:oauth:grant-type:device_code']) {
    const response = await request('/api/auth/oauth2/token', {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: grant, client_id: 'deployment-smoke-invalid-client' }),
    });
    ensure(response.status >= 400 && response.status < 500, 'unsupported_grant_status');
    const body = await readJson(response);
    ensure(!['access_token', 'refresh_token', 'id_token'].some((field) => body[field] !== undefined), 'unexpected_token_response');
  }
});

await check('Public dynamic registration is unavailable', async () => {
  const response = await request('/api/auth/oauth2/register', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ client_name: 'deployment-smoke', redirect_uris: ['https://invalid.example/callback'] }),
  });
  ensure([401, 403, 404, 405].includes(response.status), 'dynamic_registration_exposed');
  await readJson(response);
});

const passed = checks.every((result) => result.passed);
console.log(JSON.stringify({ origin, checked_at: new Date().toISOString(), passed, checks }, null, 2));
if (!passed) process.exitCode = 1;
