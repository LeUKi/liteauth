import { constants } from 'node:fs';
import { chmodSync, mkdirSync, unlinkSync, writeFileSync } from 'node:fs';
import { open } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';

const root = process.cwd();
const help = [
  'Same-zone LiteAuth probe runner.',
  '',
  'node scripts/same-zone-probe/runner.mjs --env staging|production --probe-url URL',
  '  --credentials-file PROTECTED_JSON --mode baseline|protocol [--allow-failures]',
  '',
  'Protected JSON: {"probe_token":"..."}; file must be owned by the current user and mode 0600.',
  'The runner reads apps/api/wrangler.local.jsonc and .secrets/<env>.json locally.',
  'It does not print secrets, OAuth codes, access tokens, ID tokens or raw response bodies.',
].join('\n');

class RunnerError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

function ensure(condition, code) {
  if (!condition) throw new RunnerError(code);
}

function parseArgs(argv) {
  const values = {};
  const allowed = new Set(['env', 'probe-url', 'credentials-file', 'mode', 'allow-failures', 'help']);
  for (let i = 0; i < argv.length; i++) {
    ensure(argv[i].startsWith('--'), 'invalid_option');
    const key = argv[i].slice(2);
    ensure(allowed.has(key) && !(key in values), 'invalid_option');
    if (key === 'allow-failures' || key === 'help') {
      values[key] = true;
      continue;
    }
    ensure(argv[i + 1] && !argv[i + 1].startsWith('--'), 'option_value_required');
    values[key] = argv[++i];
  }
  return values;
}

async function protectedText(path) {
  const file = await open(resolve(path), constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const info = await file.stat();
    ensure(info.isFile() && info.size <= 64 * 1024, 'protected_file_shape');
    ensure((info.mode & 0o077) === 0, 'protected_file_permissions');
    ensure(!process.getuid || info.uid === process.getuid(), 'protected_file_owner');
    return await file.readFile('utf8');
  } finally {
    await file.close();
  }
}

async function protectedJson(path) {
  try {
    return JSON.parse(await protectedText(path));
  } catch (error) {
    if (error instanceof RunnerError) throw error;
    throw new RunnerError('protected_json_invalid');
  }
}

function q(value) {
  if (value === null) return 'NULL';
  if (typeof value === 'number') return String(value);
  return `'${String(value).replaceAll("'", "''")}'`;
}

function originFrom(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new RunnerError('invalid_origin');
  }
  ensure(url.protocol === 'https:' && !url.username && !url.password && url.pathname === '/' && !url.search && !url.hash, 'invalid_origin');
  return url.origin;
}

function probeUrlFrom(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new RunnerError('invalid_probe_url');
  }
  ensure(url.protocol === 'https:' && url.pathname.endsWith('/run') && !url.username && !url.password && !url.hash, 'invalid_probe_url');
  return url.href;
}

function runWranglerSql(environment, path) {
  const result = spawnSync('pnpm', [
    'exec',
    'wrangler',
    'd1',
    'execute',
    'DB',
    '--remote',
    '--config',
    'apps/api/wrangler.local.jsonc',
    '--env',
    environment,
    '--file',
    path,
    '--json',
  ], { cwd: root, encoding: 'utf8', maxBuffer: 1024 * 1024 });
  if (result.status !== 0) throw new RunnerError('remote_d1_sql_failed');
  // Remote file imports print progress and aggregate results even with --json.
  // They do not return the rows of SELECT statements inside the file.
}

function queryCleanup(environment, sql) {
  const result = spawnSync('pnpm', [
    'exec', 'wrangler', 'd1', 'execute', 'DB', '--remote',
    '--config', 'apps/api/wrangler.local.jsonc', '--env', environment,
    '--command', sql, '--json',
  ], { cwd: root, encoding: 'utf8', maxBuffer: 1024 * 1024 });
  if (result.status !== 0) throw new RunnerError('cleanup_query_failed');
  try {
    return JSON.parse(result.stdout);
  } catch {
    throw new RunnerError('remote_d1_json_failed');
  }
}

function writeSql(path, text) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, text, { mode: 0o600 });
  chmodSync(path, 0o600);
}

async function signedSessionCookie(origin, betterAuthSecret, f) {
  const dependency = createRequire(resolve(root, 'apps/api/package.json'));
  const { makeSignature } = await import(pathToFileURL(dependency.resolve('better-auth/crypto')).href);
  const cookieName = origin.startsWith('https:') ? '__Host-liteauth.session' : 'liteauth.session';
  const signed = `${f.token}.${await makeSignature(f.token, betterAuthSecret)}`;
  return `${cookieName}=${encodeURIComponent(signed)}`;
}

function planFixture(environment) {
  const prefix = `szp_${randomUUID().replaceAll('-', '').slice(0, 20)}`;
  const userId = `${prefix}_user`;
  const eventId = `${prefix}_event`;
  const sessionId = `${prefix}_session`;
  const token = `${randomUUID()}${randomUUID()}`;
  const username = prefix;
  const linuxdoId = 2_120_000_000 + Math.floor(Math.random() * 1_000_000);
  const now = Date.now();
  const profile = {
    id: linuxdoId,
    username,
    name: 'Same-zone Probe',
    avatar_url: null,
    trust_level: 3,
    active: true,
    silenced: false,
  };
  const sqlPath = resolve(`.omx/${environment}-${prefix}-same-zone-probe.sql`);
  return {
    sqlPath,
    userId,
    eventId,
    sessionId,
    token,
    username,
    linuxdoId,
    now,
    profile,
    expected: {
      user_id: userId,
      linuxdo_id: linuxdoId,
      username,
      login_method: 'lite_self_app',
    },
  };
}

function seedFixture(environment, f) {
  const insert = `INSERT INTO user (id,name,email,email_verified,created_at,updated_at,linuxdo_id,username,is_admin,disabled,credential_epoch,official_verified_at)
VALUES (${q(f.userId)},'Same-zone Probe',${q(`${f.username}@example.invalid`)},0,${f.now},${f.now},${f.linuxdoId},${q(f.username)},0,0,0,NULL);
INSERT INTO auth_event (id,user_id,login_method,upstream_client_id,credential_version,profile,created_at,trust_level)
VALUES (${q(f.eventId)},${q(f.userId)},'lite_self_app','same-zone-probe-upstream',NULL,${q(JSON.stringify(f.profile))},${f.now},3);
INSERT INTO session (id,token,user_id,expires_at,created_at,updated_at,auth_event_id)
VALUES (${q(f.sessionId)},${q(f.token)},${q(f.userId)},${f.now + 3600_000},${f.now},${f.now},${q(f.eventId)});`;
  writeSql(f.sqlPath, insert);
  runWranglerSql(environment, f.sqlPath);
}

function cleanup(environment, f) {
  if (!f?.sqlPath) return { cleanup: null, reason: 'not_applicable' };
  const user = q(f.userId);
  const sql = `DELETE FROM verification WHERE identifier IN (SELECT code_id FROM grant_ledger WHERE client_id IN (SELECT client_id FROM oauth_client WHERE user_id = ${user}));
DELETE FROM oauth_access_token WHERE user_id = ${user};
DELETE FROM oauth_refresh_token WHERE user_id = ${user};
DELETE FROM oauth_consent WHERE user_id = ${user} OR client_id IN (SELECT client_id FROM oauth_client WHERE user_id = ${user});
DELETE FROM grant_ledger WHERE client_id IN (SELECT client_id FROM oauth_client WHERE user_id = ${user}) OR auth_event_id IN (SELECT id FROM auth_event WHERE user_id = ${user});
DELETE FROM authorization_request WHERE client_id IN (SELECT client_id FROM oauth_client WHERE user_id = ${user}) OR auth_event_id IN (SELECT id FROM auth_event WHERE user_id = ${user});
DELETE FROM app_settings WHERE client_id IN (SELECT client_id FROM oauth_client WHERE user_id = ${user});
DELETE FROM oauth_client WHERE user_id = ${user};
DELETE FROM session WHERE user_id = ${user};
DELETE FROM auth_event WHERE user_id = ${user};
DELETE FROM audit WHERE actor_id = ${user} OR target_id = ${user};
DELETE FROM rate_limit WHERE key = ${q(`app-create:${f.userId}`)};
DELETE FROM user WHERE id = ${user};`;
  writeSql(f.sqlPath, sql);
  runWranglerSql(environment, f.sqlPath);
  const result = queryCleanup(environment, `SELECT
  (SELECT count(*) FROM user WHERE id = ${user}) +
  (SELECT count(*) FROM auth_event WHERE user_id = ${user}) +
  (SELECT count(*) FROM session WHERE user_id = ${user}) +
  (SELECT count(*) FROM oauth_client WHERE user_id = ${user}) +
  (SELECT count(*) FROM oauth_access_token WHERE user_id = ${user}) +
  (SELECT count(*) FROM oauth_refresh_token WHERE user_id = ${user}) +
  (SELECT count(*) FROM oauth_consent WHERE user_id = ${user}) +
  (SELECT count(*) FROM grant_ledger WHERE auth_event_id = ${q(f.eventId)}) +
  (SELECT count(*) FROM authorization_request WHERE auth_event_id = ${q(f.eventId)}) +
  (SELECT count(*) FROM audit WHERE actor_id = ${user} OR target_id = ${user}) AS remaining;`);
  try {
    unlinkSync(f.sqlPath);
  } catch {
    // The SQL file contains only synthetic IDs, but leave the path in the report if deletion fails.
  }
  const statement = Array.isArray(result) ? result.at(-1) : result?.result?.at?.(-1);
  const pages = statement?.results ?? [];
  const last = Array.isArray(pages) ? pages.at(-1) : null;
  if (!last || last.remaining === undefined) return { cleanup: false, reason: 'cleanup_result_unreadable' };
  const remaining = Number(last.remaining);
  if (!Number.isFinite(remaining)) return { cleanup: false, reason: 'cleanup_result_invalid' };
  return { cleanup: remaining === 0, remaining };
}

function safeCleanup(environment, f) {
  try {
    return cleanup(environment, f);
  } catch {
    return recovery(environment, f, 'cleanup_failed');
  }
}

function recovery(environment, f, reason) {
  return {
    cleanup: false,
    reason,
    recovery: f ? {
      environment,
      user_id: f.userId,
      auth_event_id: f.eventId,
      session_id: f.sessionId,
      sql_path: f.sqlPath,
    } : null,
  };
}

async function callProbe(probeUrl, token, body) {
  const response = await fetch(probeUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      'X-Probe-Token': token,
    },
    body: JSON.stringify(body),
    redirect: 'manual',
    signal: AbortSignal.timeout(90_000),
  });
  ensure((response.headers.get('content-type') ?? '').includes('application/json'), 'probe_json_required');
  const result = await response.json();
  return { response, result };
}

async function probeHandshake(probeUrl, token, expectedOrigin) {
  const { response, result } = await callProbe(probeUrl, token, { mode: 'baseline' });
  ensure(result.target_origin === expectedOrigin, 'probe_target_origin_mismatch');
  return { response, result };
}

function validateProbeRoute(probeUrl, apiConfig, environment) {
  const url = new URL(probeUrl);
  const selectedHost = new URL(apiConfig.env?.[environment]?.vars?.APP_ORIGIN).hostname;
  const stagingHost = new URL(apiConfig.env?.staging?.vars?.APP_ORIGIN).hostname;
  ensure(url.hostname === selectedHost || url.hostname === stagingHost, 'probe_host_mismatch');
  ensure(/^\/__routing-proof-[A-Za-z0-9_-]+\/(private|public)\/run$/.test(url.pathname), 'probe_path_shape');
}

function safeReport(value) {
  return JSON.stringify(value, null, 2);
}

const args = parseArgs(process.argv.slice(2));
if (args.help) {
  console.log(help);
  process.exit(0);
}

let fixtureData = null;
let exitCode = 0;
try {
  ensure(['staging', 'production'].includes(args.env), 'env_required');
  ensure(['baseline', 'protocol'].includes(args.mode), 'mode_required');
  ensure(args['credentials-file'], 'credentials_file_required');
  const probeUrl = probeUrlFrom(args['probe-url']);
  const credentials = await protectedJson(args['credentials-file']);
  ensure(typeof credentials.probe_token === 'string' && credentials.probe_token.length >= 24, 'probe_token_required');

  const apiConfig = JSON.parse(await protectedText('apps/api/wrangler.local.jsonc'));
  const origin = originFrom(apiConfig.env?.[args.env]?.vars?.APP_ORIGIN);
  validateProbeRoute(probeUrl, apiConfig, args.env);

  const handshake = await probeHandshake(probeUrl, credentials.probe_token, origin);
  let probe = handshake;
  if (args.mode === 'protocol') {
    const secrets = JSON.parse(await protectedText(`.secrets/${args.env}.json`));
    ensure(typeof secrets.BETTER_AUTH_SECRET === 'string' && secrets.BETTER_AUTH_SECRET.length > 0, 'better_auth_secret_required');
    fixtureData = planFixture(args.env);
    seedFixture(args.env, fixtureData);
    fixtureData.sessionCookie = await signedSessionCookie(origin, secrets.BETTER_AUTH_SECRET, fixtureData);
    probe = await callProbe(probeUrl, credentials.probe_token, {
      mode: 'protocol',
      session_cookie: fixtureData.sessionCookie,
      expected: fixtureData.expected,
    });
    ensure(probe.result.target_origin === origin, 'probe_target_origin_mismatch');
  }
  const cleanupResult = safeCleanup(args.env, fixtureData);
  const report = {
    checked_at: new Date().toISOString(),
    environment: args.env,
    probe_url_path: new URL(probeUrl).pathname,
    expected_origin: origin,
    http_status: probe.response.status,
    passed: Boolean(probe.result.passed),
    ...(args.mode === 'protocol' ? { handshake: handshake.result } : {}),
    result: probe.result,
    cleanup: cleanupResult,
  };
  console.log(safeReport(report));
  if (!probe.result.passed && !args['allow-failures']) exitCode = 1;
  if (fixtureData && !cleanupResult.cleanup) exitCode = 1;
} catch (error) {
  const timedOut = error?.name === 'TimeoutError' || error?.name === 'AbortError';
  const bestEffort = safeCleanup(args.env, fixtureData);
  const cleanupResult = timedOut && fixtureData
    ? { ...recovery(args.env, fixtureData, 'probe_timeout_cleanup_not_proven'), best_effort_cleanup: bestEffort.cleanup === true }
    : bestEffort;
  console.log(safeReport({
    checked_at: new Date().toISOString(),
    environment: args.env ?? null,
    passed: false,
    error: error instanceof RunnerError ? error.code : 'runner_failed',
    cleanup: cleanupResult,
  }));
  exitCode = 1;
}

process.exitCode = exitCode;
