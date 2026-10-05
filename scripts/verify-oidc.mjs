import { createServer } from 'node:http';
import { constants } from 'node:fs';
import { open, mkdtemp, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';

class VerificationFailure extends Error {
  constructor(code) { super(code); this.code = code; }
}
function ensure(condition, code) { if (!condition) throw new VerificationFailure(code); }
let stage = 'configuration';
let lastResponse;

function errorDiagnostics(error) {
  const names = new Set(['ClientError', 'TypeError', 'ResponseBodyError', 'WWWAuthenticateChallengeError', 'AuthorizationResponseError', 'OperationProcessingError', 'TimeoutError', 'AbortError']);
  const codes = new Set(['OAUTH_RESPONSE_IS_NOT_CONFORM', 'OAUTH_RESPONSE_IS_NOT_JSON', 'OAUTH_PARSE_ERROR', 'OAUTH_INVALID_RESPONSE', 'OAUTH_JSON_ATTRIBUTE_COMPARISON', 'OAUTH_JWT_CLAIM_COMPARISON', 'OAUTH_JWT_TIMESTAMP_CHECK', 'OAUTH_JWT_USERINFO_EXPECTED', 'OAUTH_RESPONSE_BODY_ERROR', 'OAUTH_WWW_AUTHENTICATE_CHALLENGE', 'ERR_INVALID_ARG_TYPE', 'ERR_INVALID_ARG_VALUE', 'ECONNRESET', 'ECONNREFUSED', 'ETIMEDOUT', 'ENOTFOUND', 'UND_ERR_CONNECT_TIMEOUT']);
  const causes = [];
  for (let current = error; current && causes.length < 3; current = current.cause) {
    causes.push({
      type: names.has(current.name) ? current.name : 'unclassified',
      ...(codes.has(current.code) ? { code: current.code } : {}),
    });
  }
  return { causes, ...(lastResponse?.stage === stage ? { response: lastResponse } : {}) };
}

const help = [
  'Live LiteAuth OAuth/OIDC verifier. Node >=22; pnpm install first.',
  '',
  'node scripts/verify-oidc.mjs run --client-id ID [--origin HTTPS_ORIGIN]',
  '  [--mode both|oidc|oauth|concurrency] [--redirect-uri http://127.0.0.1:9444/callback]',
  '  [--expected-method official_connect|lite_self_app] [--expected-linuxdo-id NUMBER]',
  '  [--expected-upstream-client-id ID] [--credentials-file PROTECTED_JSON]',
  '  [--client-auth none|client_secret_post] [--report NEW_JSON_PATH]',
  '  [--timeout 600]',
  '',
  'Without a listener: prepare --mode oidc|oauth|concurrency --redirect-uri REGISTERED_URI',
  '  writes protected context + authorization URL files and prints their paths.',
  'complete --context PROTECTED_CONTEXT --callback-file PROTECTED_URL_FILE',
  '  [--credentials-file PROTECTED_JSON] [--report NEW_JSON_PATH]',
  '',
  'Credentials JSON: {"client_id":"...","client_secret":"..."}; mode 0600.',
  'LITEAUTH_TEST_CLIENT_SECRET is supported, but no secret command-line option.',
  'No authorization codes, secrets, tokens, or raw HTTP errors are printed.',
].join('\n');

function argumentsFrom(argv) {
  const values = {};
  const command = argv[0] && !argv[0].startsWith('--') ? argv.shift() : 'run';
  ensure(['run', 'prepare', 'complete'].includes(command), 'invalid_command');
  const allowed = new Set(['origin', 'client-id', 'mode', 'redirect-uri', 'expected-method', 'expected-linuxdo-id', 'expected-upstream-client-id', 'credentials-file', 'client-auth', 'context', 'callback-file', 'report', 'timeout', 'help']);
  for (let i = 0; i < argv.length; i++) {
    const key = argv[i].slice(2);
    ensure(argv[i].startsWith('--') && allowed.has(key) && !(key in values), 'invalid_option');
    if (key === 'help') { values.help = true; continue; }
    ensure(argv[i + 1] && !argv[i + 1].startsWith('--'), 'option_value_required');
    values[key] = argv[++i];
  }
  return { command, values };
}

async function protectedText(path) {
  const file = await open(resolve(path), constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const info = await file.stat();
    ensure(info.isFile() && info.size <= 64 * 1024, 'protected_file_shape');
    ensure((info.mode & 0o077) === 0, 'protected_file_permissions');
    ensure(!process.getuid || info.uid === process.getuid(), 'protected_file_owner');
    return await file.readFile('utf8');
  } finally { await file.close(); }
}
async function protectedJson(path) {
  try { return JSON.parse(await protectedText(path)); }
  catch (error) { if (error instanceof VerificationFailure) throw error; throw new VerificationFailure('protected_json_invalid'); }
}
function originFrom(value) {
  let url;
  try { url = new URL(value); } catch { throw new VerificationFailure('invalid_origin'); }
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  ensure(url.protocol === 'https:' || (url.protocol === 'http:' && local), 'https_or_loopback_required');
  ensure(!url.username && !url.password && url.pathname === '/' && !url.search && !url.hash, 'origin_required');
  return url.origin;
}
function redirectFrom(value, listener) {
  let url;
  try { url = new URL(value); } catch { throw new VerificationFailure('invalid_redirect_uri'); }
  const loopback = ['127.0.0.1', '[::1]'].includes(url.hostname);
  ensure(!url.username && !url.password && !url.search && !url.hash, 'redirect_uri_shape');
  ensure(url.protocol === 'https:' || (url.protocol === 'http:' && loopback), 'redirect_https_or_literal_loopback_required');
  if (listener) ensure(url.protocol === 'http:' && loopback && url.port && !['/start', '/'].includes(url.pathname), 'listener_requires_literal_loopback_callback');
  return url.href;
}
async function credentialsFrom(values, context) {
  const stored = values['credentials-file'] ? await protectedJson(values['credentials-file']) : {};
  const clientId = values['client-id'] ?? context?.client_id ?? stored.client_id;
  ensure(typeof clientId === 'string' && clientId.length > 0 && clientId.length <= 512, 'client_id_required');
  ensure(!stored.client_id || stored.client_id === clientId, 'client_id_mismatch');
  ensure(!context || context.client_id === clientId, 'context_client_mismatch');
  const secret = process.env.LITEAUTH_TEST_CLIENT_SECRET ?? stored.client_secret;
  ensure(secret === undefined || (typeof secret === 'string' && secret.length > 0), 'client_secret_shape');
  const method = values['client-auth'] ?? context?.client_auth ?? (secret ? 'client_secret_post' : 'none');
  ensure(['none', 'client_secret_post'].includes(method), 'client_auth_method');
  ensure(method === 'none' ? !secret : Boolean(secret), 'client_auth_credentials');
  ensure(!context || context.client_auth === method, 'context_auth_mismatch');
  return { clientId, secret, method };
}
async function libraries() {
  const dependency = createRequire(new URL('../apps/api/package.json', import.meta.url));
  try {
    const oidc = await import(pathToFileURL(dependency.resolve('openid-client')).href);
    const authDependency = createRequire(dependency.resolve('better-auth'));
    const jose = await import(pathToFileURL(authDependency.resolve('jose')).href);
    return { oidc, jose };
  } catch { throw new VerificationFailure('dependencies_unavailable_run_pnpm_install'); }
}
async function safeFetch(input, init = {}) {
  const requestStage = stage;
  const response = await fetch(input, { ...init, redirect: 'error', signal: init.signal ?? AbortSignal.timeout(15_000) });
  const contentType = response.headers.get('content-type')?.split(';')[0].trim();
  lastResponse = {
    stage: requestStage, status: response.status,
    content_type: ['application/json', 'application/jwt', 'text/html', 'text/plain'].includes(contentType) ? contentType : 'other',
  };
  return response;
}
async function responseJson(response) {
  ensure(response.ok, 'http_request_failed');
  ensure(/application\/json/i.test(response.headers.get('content-type') ?? ''), 'json_response_required');
  try { return await response.json(); } catch { throw new VerificationFailure('invalid_json_response'); }
}
async function configuration(oidc, origin, credentials) {
  stage = 'discovery';
  const auth = credentials.method === 'none' ? oidc.None() : oidc.ClientSecretPost(credentials.secret);
  const config = await oidc.discovery(new URL(origin + '/api/auth'), credentials.clientId, {
    token_endpoint_auth_method: credentials.method,
    id_token_signed_response_alg: 'RS256',
  }, auth, {
    timeout: 15,
    [oidc.customFetch]: safeFetch,
    ...(origin.startsWith('http:') ? { execute: [oidc.allowInsecureRequests] } : {}),
  });
  const metadata = config.serverMetadata();
  ensure(metadata.issuer === origin + '/api/auth', 'issuer_mismatch');
  for (const name of ['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri']) {
    ensure(typeof metadata[name] === 'string' && new URL(metadata[name]).origin === origin, 'endpoint_origin_mismatch');
  }
  ensure(metadata.code_challenge_methods_supported?.includes('S256'), 'pkce_s256_unavailable');
  ensure(metadata.token_endpoint_auth_methods_supported?.includes(credentials.method), 'client_auth_not_advertised');
  return config;
}

async function newContext(oidc, values, credentials, mode, origin, redirectUri) {
  const verifier = oidc.randomPKCECodeVerifier();
  return {
    version: 1, origin, client_id: credentials.clientId, client_auth: credentials.method,
    mode, redirect_uri: redirectUri, state: oidc.randomState(),
    nonce: mode === 'oidc' ? oidc.randomNonce() : null,
    code_verifier: verifier, code_challenge: await oidc.calculatePKCECodeChallenge(verifier),
    expected_method: values['expected-method'] ?? null,
    expected_linuxdo_id: values['expected-linuxdo-id'] ? Number(values['expected-linuxdo-id']) : null,
    expected_upstream_client_id: values['expected-upstream-client-id'] ?? null,
    expires_at: Date.now() + Number(values.timeout ?? 600) * 1000,
  };
}
function validateContext(context) {
  ensure(context && context.version === 1 && ['oidc', 'oauth', 'concurrency'].includes(context.mode), 'context_shape');
  ensure(typeof context.state === 'string' && context.state.length >= 32, 'context_state');
  ensure(typeof context.code_verifier === 'string' && context.code_verifier.length >= 43, 'context_pkce');
  ensure(context.mode !== 'oidc' || (typeof context.nonce === 'string' && context.nonce.length >= 32), 'context_nonce');
  ensure(Number.isFinite(context.expires_at) && context.expires_at > Date.now(), 'context_expired');
  ensure(context.expected_method === null || ['official_connect', 'lite_self_app'].includes(context.expected_method), 'expected_method_invalid');
  ensure(context.expected_linuxdo_id === null || (Number.isSafeInteger(context.expected_linuxdo_id) && context.expected_linuxdo_id > 0), 'expected_linuxdo_id_invalid');
}
function authorizationUrl(oidc, config, context) {
  return oidc.buildAuthorizationUrl(config, {
    response_type: 'code', redirect_uri: context.redirect_uri,
    scope: context.mode === 'oidc' ? 'openid profile' : 'profile',
    state: context.state, code_challenge: context.code_challenge,
    code_challenge_method: 'S256', ...(context.nonce ? { nonce: context.nonce } : {}),
  });
}
function callbackFrom(value, context) {
  const url = new URL(value);
  const registered = new URL(context.redirect_uri);
  ensure(url.origin === registered.origin && url.pathname === registered.pathname && !url.hash, 'callback_uri_mismatch');
  for (const key of ['state', 'code', 'error', 'iss']) ensure(url.searchParams.getAll(key).length <= 1, 'callback_parameter_duplicate');
  ensure(url.searchParams.get('state') === context.state, 'callback_state_mismatch');
  ensure(Boolean(url.searchParams.get('code')) !== Boolean(url.searchParams.get('error')), 'callback_result_shape');
  return url;
}
const forbidden = new Set(['client_secret', 'access_token', 'refresh_token', 'id_token', 'api_key', 'upstream_token', 'upstream_access_token', 'upstream_client_secret', 'liteauth_auth_event_id']);
function noSensitiveFields(value) {
  if (!value || typeof value !== 'object') return;
  for (const [key, item] of Object.entries(value)) {
    ensure(!forbidden.has(key), 'sensitive_profile_field');
    noSensitiveFields(item);
  }
}
function identityClaims(value, context) {
  ensure(value && typeof value === 'object', 'identity_response_shape');
  ensure(typeof value.sub === 'string' && value.sub.length > 0, 'subject_missing');
  ensure(Number.isSafeInteger(value.id) && value.id > 0, 'native_linuxdo_id_required');
  ensure(typeof value.username === 'string' && value.username.length > 0, 'username_missing');
  ensure(['official_connect', 'lite_self_app'].includes(value.login_method), 'login_method_invalid');
  ensure(value.auth_source === 'linuxdo', 'auth_source_invalid');
  ensure(typeof value.upstream_client_id === 'string' && value.upstream_client_id.length > 0, 'upstream_client_id_missing');
  ensure(value.liteauth_user_id === value.sub, 'liteauth_subject_mismatch');
  ensure(!context.expected_method || value.login_method === context.expected_method, 'unexpected_login_method');
  ensure(!context.expected_linuxdo_id || value.id === context.expected_linuxdo_id, 'unexpected_linuxdo_identity');
  ensure(!context.expected_upstream_client_id || value.upstream_client_id === context.expected_upstream_client_id, 'unexpected_upstream_client');
  noSensitiveFields(value);
  return { sub: value.sub, id: value.id, username: value.username, login_method: value.login_method, auth_source: value.auth_source, upstream_client_id: value.upstream_client_id, liteauth_user_id: value.liteauth_user_id };
}
function matchingClaims(first, second) {
  for (const key of Object.keys(first)) ensure(first[key] === second[key], 'authentication_context_changed');
}
async function verifyFlow(oidc, jose, config, context, callback) {
  validateContext(context);
  const currentUrl = callbackFrom(callback, context);
  stage = context.mode + ':token_exchange';
  const checks = { expectedState: context.state, pkceCodeVerifier: context.code_verifier, ...(context.mode === 'oidc' ? { expectedNonce: context.nonce, idTokenExpected: true } : {}) };
  // Reusing a code can revoke its issued token. Keep destructive concurrency
  // checks on a separate grant, after the normal identity checks have finished.
  if (context.mode === 'concurrency') {
    const exchanges = await Promise.allSettled([
      oidc.authorizationCodeGrant(config, new URL(currentUrl.href), checks),
      oidc.authorizationCodeGrant(config, new URL(currentUrl.href), checks),
    ]);
    const successes = exchanges.filter((result) => result.status === 'fulfilled');
    ensure(successes.length > 0, 'no_token_exchange_succeeded');
    ensure(successes.length === 1, 'concurrent_code_redemption_succeeded_twice');
    const deniedExchange = exchanges.find((result) => result.status === 'rejected');
    ensure(deniedExchange?.reason instanceof oidc.ResponseBodyError && deniedExchange.reason.error === 'invalid_grant', 'concurrent_denial_not_invalid_grant');
    ensure(typeof successes[0].value.access_token === 'string', 'access_token_missing');
    await verifyReplay(oidc, config, currentUrl, checks);
    return { report: { mode: context.mode, passed: true, concurrent_redemption_one_success: true, code_replay_invalid_grant: true } };
  }
  const tokens = await oidc.authorizationCodeGrant(config, currentUrl, checks);
  ensure(typeof tokens.access_token === 'string' && tokens.access_token.length > 0, 'access_token_missing');
  ensure(/^bearer$/i.test(tokens.token_type), 'token_type_invalid');
  ensure(tokens.refresh_token === undefined, 'refresh_token_issued');
  ensure(typeof tokens.expires_in === 'number' && tokens.expires_in > 0 && tokens.expires_in <= 3600, 'access_token_lifetime_invalid');
  let jwtAccess = false;
  try { jwtAccess = typeof jose.decodeProtectedHeader(tokens.access_token).alg === 'string'; } catch { /* opaque token */ }
  ensure(!jwtAccess, 'jwt_access_token_issued');
  let idIdentity;
  if (context.mode === 'oidc') {
    stage = 'oidc:id_token_signature';
    ensure(typeof tokens.id_token === 'string', 'id_token_missing');
    const jwks = await responseJson(await safeFetch(config.serverMetadata().jwks_uri));
    ensure(Array.isArray(jwks.keys) && jwks.keys.length > 0, 'jwks_empty');
    for (const key of jwks.keys) ensure(!['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'].some((name) => name in key), 'private_jwk_exposed');
    const verified = await jose.jwtVerify(tokens.id_token, jose.createLocalJWKSet(jwks), {
      issuer: context.origin + '/api/auth', audience: context.client_id, algorithms: ['RS256'],
      requiredClaims: ['sub', 'iat', 'exp', 'nonce'], clockTolerance: 10,
    });
    ensure(verified.payload.nonce === context.nonce, 'id_token_nonce_mismatch');
    ensure(typeof verified.payload.iat === 'number' && typeof verified.payload.exp === 'number' && verified.payload.exp - verified.payload.iat <= 600 && verified.payload.iat <= Date.now() / 1000 + 10, 'id_token_lifetime_invalid');
    idIdentity = identityClaims(verified.payload, context);
    stage = 'oidc:userinfo';
    const userinfo = await oidc.fetchUserInfo(config, tokens.access_token, verified.payload.sub);
    matchingClaims(idIdentity, identityClaims(userinfo, context));
  } else {
    ensure(tokens.id_token === undefined, 'plain_oauth_id_token_issued');
  }
  stage = context.mode + ':connect_user_api';
  const userResponse = await oidc.fetchProtectedResource(config, tokens.access_token, new URL('/api/user', context.origin), 'GET', undefined, new Headers({ Accept: 'application/json' }));
  const identity = identityClaims(await responseJson(userResponse), context);
  if (idIdentity) matchingClaims(idIdentity, identity);
  stage = context.mode + ':code_replay';
  await verifyReplay(oidc, config, currentUrl, checks);
  return {
    identity,
    report: {
      mode: context.mode, passed: true, state_verified: true, pkce_s256: true,
      access_token_opaque: true, refresh_token_absent: true,
      ...(context.mode === 'oidc' ? { id_token_signature_issuer_audience_nonce_verified: true, userinfo_matches_id_token: true } : { id_token_absent: true }),
      connect_user_api_verified: true, code_replay_invalid_grant: true, login_method: identity.login_method,
    },
  };
}
async function verifyReplay(oidc, config, currentUrl, checks) {
  let denied = false;
  try { await oidc.authorizationCodeGrant(config, currentUrl, checks); }
  catch (error) { denied = error instanceof oidc.ResponseBodyError && error.error === 'invalid_grant'; }
  ensure(denied, 'code_replay_not_proven_invalid_grant');
}
function listener(redirectUri) {
  const redirect = new URL(redirectUri);
  let active;
  let callbackResponse;
  const server = createServer((request, response) => {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Referrer-Policy', 'no-referrer');
    response.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
    response.setHeader('Content-Type', 'text/html; charset=utf-8');
    if (request.method !== 'GET' || request.headers.host !== redirect.host || !request.url.startsWith('/')) {
      response.writeHead(400); response.end('请求无效'); return;
    }
    const url = new URL(request.url, redirect.origin);
    if (url.pathname === '/start' && active) {
      response.writeHead(302, { Location: active.authorization.href }); response.end(); return;
    }
    if (url.pathname === redirect.pathname && active) {
      try {
        const valid = callbackFrom(url.href, active.context);
        const complete = active.complete;
        active = undefined;
        callbackResponse = response;
        complete(valid.href);
      } catch {
        response.writeHead(400); response.end('回调无效，请使用本次验证的授权入口。');
      }
      return;
    }
    response.writeHead(404); response.end('当前没有等待中的授权请求。');
  });
  return {
    async start() {
      await new Promise((resolveStart, rejectStart) => {
        server.once('error', rejectStart);
        server.listen(Number(redirect.port), redirect.hostname === '[::1]' ? '::1' : redirect.hostname, resolveStart);
      });
    },
    wait(context, authorization) {
      return new Promise((complete, fail) => {
        const timer = setTimeout(() => { active = undefined; fail(new VerificationFailure('browser_callback_timeout')); }, Math.max(1, context.expires_at - Date.now()));
        active = { context, authorization, complete: (value) => { clearTimeout(timer); complete(value); } };
        if (callbackResponse) {
          callbackResponse.writeHead(303, { Location: redirect.origin + '/start' });
          callbackResponse.end();
          callbackResponse = undefined;
        }
      });
    },
    finish(passed) {
      if (callbackResponse) {
        callbackResponse.writeHead(passed ? 200 : 400);
        callbackResponse.end(passed ? '验证已通过，可以关闭此页。' : '验证未完成，请回到验证终端。');
        callbackResponse = undefined;
      }
    },
    close() { server.close(); server.closeIdleConnections(); },
    startUrl: redirect.origin + '/start',
  };
}
async function outputReport(report, path) {
  const text = JSON.stringify(report, null, 2);
  if (path) await writeFile(resolve(path), text + '\n', { mode: 0o600, flag: 'wx' });
  console.log(text);
}

async function main() {
  const { command, values } = argumentsFrom(process.argv.slice(2));
  if (values.help) { console.log(help); return; }
  const context = command === 'complete' ? await protectedJson(values.context) : null;
  if (context) validateContext(context);
  const origin = originFrom(values.origin ?? context?.origin ?? 'http://127.0.0.1:8798');
  ensure(!context || context.origin === origin, 'context_origin_mismatch');
  const credentials = await credentialsFrom(values, context);
  const { oidc, jose } = await libraries();
  const config = await configuration(oidc, origin, credentials);
  if (command === 'complete') {
    ensure(typeof values['callback-file'] === 'string', 'callback_file_required');
    const callbackPath = resolve(values['callback-file']);
    const contextPath = resolve(values.context);
    const lockPath = contextPath + '.lock';
    const lock = await open(lockPath, 'wx', 0o600);
    try {
      stage = 'callback_file';
      const callback = (await protectedText(callbackPath)).trim();
      const result = await verifyFlow(oidc, jose, config, context, callback);
      await outputReport({ passed: true, origin, checked_at: new Date().toISOString(), flows: [result.report] }, values.report);
    } finally {
      await lock.close();
      await unlink(lockPath).catch(() => {});
      await unlink(contextPath).catch(() => {});
      await unlink(join(dirname(contextPath), 'authorization.url')).catch(() => {});
      await unlink(callbackPath).catch(() => {});
    }
    return;
  }
  const mode = values.mode ?? (command === 'prepare' ? 'oidc' : 'both');
  ensure(['both', 'oidc', 'oauth', 'concurrency'].includes(mode), 'mode_invalid');
  ensure(command !== 'prepare' || mode !== 'both', 'prepare_requires_single_flow');
  const timeout = Number(values.timeout ?? 600);
  ensure(Number.isInteger(timeout) && timeout >= 30 && timeout <= 1800, 'timeout_invalid');
  const redirectUri = redirectFrom(values['redirect-uri'] ?? 'http://127.0.0.1:9444/callback', command === 'run');
  if (command === 'prepare') {
    const prepared = await newContext(oidc, values, credentials, mode, origin, redirectUri);
    validateContext(prepared);
    const directory = await mkdtemp(join(tmpdir(), 'liteauth-verification-'));
    const contextPath = join(directory, 'context.json');
    const authorizationPath = join(directory, 'authorization.url');
    await writeFile(contextPath, JSON.stringify(prepared), { mode: 0o600, flag: 'wx' });
    await writeFile(authorizationPath, authorizationUrl(oidc, config, prepared).href, { mode: 0o600, flag: 'wx' });
    console.log(JSON.stringify({ action: 'browser_authorization_required', mode, context_file: contextPath, authorization_url_file: authorizationPath, instruction: 'Open the protected authorization URL in the parent browser; save the real callback URL to a protected file. Do not paste callback into chat.' }, null, 2));
    return;
  }
  const browser = listener(redirectUri);
  await browser.start();
  const flows = [];
  let previous;
  try {
    for (const currentMode of mode === 'both' ? ['oidc', 'oauth', 'concurrency'] : [mode]) {
      const current = await newContext(oidc, values, credentials, currentMode, origin, redirectUri);
      validateContext(current);
      stage = currentMode + ':waiting_for_browser';
      const callback = browser.wait(current, authorizationUrl(oidc, config, current));
      console.log(JSON.stringify({ action: 'browser_authorization_required', mode: currentMode, start_url: browser.startUrl }));
      const result = await verifyFlow(oidc, jose, config, current, await callback);
      if (previous && result.identity) {
        for (const name of ['sub', 'id', 'liteauth_user_id']) ensure(previous[name] === result.identity[name], 'cross_flow_identity_mismatch');
      }
      if (result.identity) previous = result.identity;
      flows.push(result.report);
      console.log(JSON.stringify({ action: 'flow_verified', ...result.report }));
    }
    await outputReport({ passed: true, origin, checked_at: new Date().toISOString(), cross_flow_identity_verified: mode === 'both', flows }, values.report);
    browser.finish(true);
  } finally { browser.finish(false); browser.close(); }
}

main().catch((error) => {
  console.log(JSON.stringify({ passed: false, stage, error: error instanceof VerificationFailure ? error.code : 'protocol_or_io_failure', diagnostics: errorDiagnostics(error) }));
  process.exitCode = 1;
});
