import { readFileSync, existsSync, readdirSync, lstatSync, mkdirSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import ts from 'typescript';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const environments = ['staging', 'production'];
const paths = Object.fromEntries(['api', 'web'].map(app => [app, resolve(root, `apps/${app}/wrangler.local.jsonc`)]));
const artifactDirectory = resolve(root, 'apps/web/dist');
const manifestPath = resolve(root, '.wrangler/staging-artifact.json');
// Keep this list in sync if the Web Worker entry starts importing local runtime modules.
const deploymentSourceFiles = ['apps/web/worker.ts', 'pnpm-lock.yaml'];
function ensure(condition, message) { if (!condition) throw new Error(message); }
function readConfig(path) {
  ensure(existsSync(path), `Missing local configuration: ${path}`);
  const result = ts.parseConfigFileTextToJson(path, readFileSync(path, 'utf8'));
  ensure(!result.error && result.config && typeof result.config === 'object', 'Invalid JSONC configuration');
  return result.config;
}

export function validateDeployment(api, web, environment) {
  ensure(environments.includes(environment), 'Environment must be staging or production');
  const apiEnv = api.env?.[environment];
  const webEnv = web.env?.[environment];
  ensure(apiEnv && webEnv, `Missing ${environment} configuration`);
  ensure(/^[a-f\d]{32}$/i.test(api.account_id) && api.account_id === web.account_id, 'Configure matching Cloudflare Account IDs');
  const adminId = apiEnv.vars?.ADMIN_LINUXDO_ID;
  ensure(typeof adminId === 'string' && /^[1-9]\d*$/.test(adminId) && Number.isSafeInteger(Number(adminId)), 'Configure a positive, safe-integer ADMIN_LINUXDO_ID');
  ensure(apiEnv.vars?.ENVIRONMENT === environment, 'ENVIRONMENT does not match deployment target');
  let origin;
  try { origin = new URL(apiEnv.vars?.APP_ORIGIN); } catch { throw new Error('Configure APP_ORIGIN'); }
  ensure(origin.protocol === 'https:' && origin.pathname === '/' && !origin.search && !origin.hash && !origin.username && !origin.password && !origin.port, 'APP_ORIGIN must be a bare HTTPS origin');
  ensure(!/(^|\.)(example\.(com|org|net)|invalid|localhost|example)$/.test(origin.hostname) && origin.hostname.includes('.'), 'Replace the example APP_ORIGIN');
  const database = apiEnv.d1_databases?.find(db => db.binding === 'DB');
  ensure(database && /^[a-f\d]{8}(-[a-f\d]{4}){3}-[a-f\d]{12}$/i.test(database.database_id) && !database.database_id.startsWith('00000000-'), 'Configure the environment D1 database ID');
  ensure(database.database_name && database.migrations_dir === 'migrations', 'Configure the D1 database name and migrations directory');
  const prefixes = ['/api/*', '/auth/*', '/oauth2/*', '/.well-known/*'];
  ensure(apiEnv.routes?.length === prefixes.length && prefixes.every(prefix => apiEnv.routes.some(route => route.pattern === origin.hostname + prefix && !route.custom_domain && route.zone_name && (origin.hostname === route.zone_name || origin.hostname.endsWith('.' + route.zone_name)))), 'API routes must cover the four reserved prefixes of APP_ORIGIN');
  ensure(webEnv.routes?.length === 1 && webEnv.routes[0].pattern === origin.hostname && webEnv.routes[0].custom_domain === true, 'Web Custom Domain must match APP_ORIGIN');
  ensure(web.main === 'worker.ts' && !webEnv.main, 'Web Worker entrypoint must be worker.ts without environment overrides');
  ensure((webEnv.assets ?? web.assets)?.run_worker_first === true, 'Web assets must run the Worker before static asset handling');
  for (const [kind, config, selected] of [['API', api, apiEnv], ['Web', web, webEnv]]) {
    ensure(typeof selected.name === 'string' && /^[a-z0-9][a-z0-9-]*$/.test(selected.name), `Configure a valid ${kind} Worker name`);
    ensure((selected.workers_dev ?? config.workers_dev) === false && (selected.preview_urls ?? config.preview_urls) === false, `${kind} public preview URLs must be disabled`);
    ensure((selected.observability ?? config.observability)?.enabled === false, `${kind} automatic request logging must be disabled`);
  }
  ensure(apiEnv.name !== webEnv.name, 'API and Web Worker names must differ');
  const apiBindings = webEnv.services?.filter(binding => binding?.binding === 'API') ?? [];
  ensure(apiBindings.length === 1, 'Configure exactly one Web Service Binding named API');
  const apiBinding = apiBindings[0];
  ensure(apiBinding.service !== webEnv.name, 'Web API Service Binding must not target the Web Worker');
  ensure(apiBinding.service === apiEnv.name, 'Web API Service Binding must target the selected API Worker');
  ensure(!apiBinding.environment && !apiBinding.entrypoint, 'Web API Service Binding must not use environment or entrypoint overrides');
  const other = environment === 'staging' ? 'production' : 'staging';
  if (api.env?.[other]) {
    ensure(api.env[other].vars?.APP_ORIGIN !== origin.origin, 'Staging and production must use different origins');
    ensure(!api.env[other].d1_databases?.some(db => db.database_id === database.database_id), 'Staging and production must use different D1 databases');
  }
  for (const config of [api, web]) ensure(!config.env?.[other] || config.env[other].name !== config.env[environment].name, 'Staging and production must use different Worker names');
  const names = [api, web].flatMap(config => environments.flatMap(name => config.env?.[name]?.name ? [config.env[name].name] : []));
  ensure(new Set(names).size === names.length, 'Worker names must be unique across all environments');
  return { environment, origin: origin.origin, apiWorker: apiEnv.name, webWorker: webEnv.name };
}

export function deploymentSourceHashes() {
  return deploymentSourceFiles.map(path => {
    const absolute = resolve(root, path);
    ensure(existsSync(absolute), `Missing deployment source file: ${path}`);
    return { path, sha256: createHash('sha256').update(readFileSync(absolute)).digest('hex') };
  });
}

export function artifactHashes(directory) {
  ensure(existsSync(resolve(directory, 'index.html')), 'Build the Web application before deploying');
  const files = [];
  function visit(relative = '') {
    for (const name of readdirSync(resolve(directory, relative)).sort()) {
      const path = relative ? `${relative}/${name}` : name;
      const absolute = resolve(directory, path);
      const stat = lstatSync(absolute);
      ensure(!stat.isSymbolicLink(), 'Web artifacts must not contain symlinks');
      if (stat.isDirectory()) visit(path);
      else {
        ensure(stat.isFile(), 'Web artifacts must contain regular files');
        files.push({ path, sha256: createHash('sha256').update(readFileSync(absolute)).digest('hex') });
      }
    }
  }
  visit();
  return files;
}

export function verifyStagedArtifact(directory, manifest, origin, version, sourceFiles = deploymentSourceHashes()) {
  ensure(manifest?.environment === 'staging' && manifest.origin === origin && manifest.version === version, 'Missing or incompatible staging artifact manifest; deploy and verify staging first');
  ensure(JSON.stringify(artifactHashes(directory)) === JSON.stringify(manifest.files), 'Web artifact differs from the staging deployment; redeploy and verify staging first');
  ensure(JSON.stringify(sourceFiles) === JSON.stringify(manifest.sourceFiles), 'Deployment source differs from the staging deployment; redeploy and verify staging first');
}

function run(args, cwd = root) {
  const result = spawnSync('pnpm', args, { cwd, stdio: 'inherit', env: process.env });
  ensure(!result.error && result.status === 0, `Command failed: pnpm ${args.join(' ')}`);
}
export function main(argv) {
  let selected;
  const flags = new Set();
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--env') { ensure(!selected, 'Duplicate environment'); selected = argv[++i]; ensure(environments.includes(selected), 'Environment must be staging or production'); }
    else { ensure(['--check', '--dry-run', '--skip-build'].includes(argv[i]) && !flags.has(argv[i]), 'Unknown or duplicate option'); flags.add(argv[i]); }
  }
  ensure(selected || flags.has('--check'), 'Select --env staging or --env production');
  const api = readConfig(paths.api), web = readConfig(paths.web);
  for (const environment of selected ? [selected] : environments) console.log(JSON.stringify(validateDeployment(api, web, environment)));
  if (flags.has('--check')) return;
  const version = JSON.parse(readFileSync(resolve(root, 'apps/web/package.json'), 'utf8')).version;
  const sourceFiles = deploymentSourceHashes();
  if (selected === 'production') {
    ensure(flags.has('--skip-build'), 'Production requires --skip-build to promote the staged Web artifact');
    ensure(existsSync(manifestPath), 'Deploy and verify staging before production');
    verifyStagedArtifact(artifactDirectory, JSON.parse(readFileSync(manifestPath, 'utf8')), api.env.staging?.vars?.APP_ORIGIN, version, sourceFiles);
  }
  if (!flags.has('--skip-build')) run(['--filter', '@liteauth/web', 'build']);
  ensure(JSON.stringify(deploymentSourceHashes()) === JSON.stringify(sourceFiles), 'Deployment source changed during deployment; redeploy and verify staging again');
  const files = artifactHashes(artifactDirectory);
  for (const kind of ['api', 'web']) {
    ensure(JSON.stringify(artifactHashes(artifactDirectory)) === JSON.stringify(files), 'Web artifacts changed during deployment; rebuild and verify staging again');
    ensure(JSON.stringify(deploymentSourceHashes()) === JSON.stringify(sourceFiles), 'Deployment source changed during deployment; redeploy and verify staging again');
    run(['exec', 'wrangler', 'deploy', '--config', paths[kind], '--env', selected, ...(flags.has('--dry-run') ? ['--dry-run'] : [])], resolve(root, `apps/${kind}`));
  }
  ensure(JSON.stringify(artifactHashes(artifactDirectory)) === JSON.stringify(files), 'Web artifacts changed during deployment; rebuild and verify staging again');
  ensure(JSON.stringify(deploymentSourceHashes()) === JSON.stringify(sourceFiles), 'Deployment source changed during deployment; redeploy and verify staging again');
  if (selected === 'staging' && !flags.has('--dry-run')) {
    mkdirSync(dirname(manifestPath), { recursive: true });
    writeFileSync(manifestPath, JSON.stringify({ environment: 'staging', origin: api.env.staging.vars.APP_ORIGIN, version, deployedAt: Math.floor(Date.now() / 1000), files, sourceFiles }, null, 2) + '\n', { mode: 0o600 });
  }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(process.argv.slice(2)); }
  catch (error) { console.error(error instanceof Error ? error.message : 'Deployment failed'); process.exitCode = 1; }
}
