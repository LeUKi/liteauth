import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, rmSync, openSync, closeSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';
import ts from 'typescript';
import { validateDeployment } from './deploy.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
function config(name) {
  const path = resolve(root, `apps/${name}/wrangler.local.jsonc`);
  const result = ts.parseConfigFileTextToJson(path, readFileSync(path, 'utf8'));
  if (result.error) throw new Error('Invalid local deployment configuration');
  return result.config;
}
function ensure(condition, message) { if (!condition) throw new Error(message); }
async function unusedPort() {
  const server = createServer();
  await new Promise((accept, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', accept); });
  const port = server.address().port;
  await new Promise((accept, reject) => server.close(error => error ? reject(error) : accept()));
  return port;
}

async function main(args) {
  ensure(args.length === 2 && args[0] === '--env' && ['staging', 'production'].includes(args[1]), 'Usage: node scripts/backfill-official-locks.mjs --env staging|production');
  const environment = args[1];
  const api = config('api'), web = config('web');
  const target = validateDeployment(api, web, environment);
  const contextResponse = await fetch(`${target.origin}/api/login-context`, { signal: AbortSignal.timeout(15_000) });
  ensure(contextResponse.ok && typeof (await contextResponse.json()).lite_available === 'boolean', 'Deploy the API enforcing account locks before running this backfill');
  const database = api.env[environment].d1_databases.find(item => item.binding === 'DB');
  const directory = resolve(root, '.wrangler');
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const working = mkdtempSync(resolve(directory, `official-lock-${environment}-`));
  const token = randomBytes(32).toString('hex');
  const port = await unusedPort(), inspectorPort = await unusedPort();
  const localConfig = resolve(working, 'wrangler.json');
  writeFileSync(localConfig, JSON.stringify({
    name: 'liteauth-local-account-maintenance',
    main: resolve(root, 'apps/api/src/maintenance/backfill-official-locks.ts'),
    account_id: api.account_id, compatibility_date: api.compatibility_date,
    compatibility_flags: api.compatibility_flags, workers_dev: false, preview_urls: false,
    observability: { enabled: false },
    // Copy only the exact target binding. In particular preview_database_id must not override it.
    d1_databases: [{ binding: 'DB', database_name: database.database_name, database_id: database.database_id, remote: true }],
  }), { mode: 0o600 });
  const localSecrets = resolve(working, '.dev.vars');
  writeFileSync(localSecrets, `MAINTENANCE_TOKEN=${token}\n`, { mode: 0o600 });
  const logPath = resolve(working, 'maintenance.log');
  const log = openSync(logPath, 'w', 0o600);
  const child = spawn('pnpm', ['exec', 'wrangler', 'dev', '--config', localConfig, '--ip', '127.0.0.1', '--port', String(port),
    '--inspector-ip', '127.0.0.1', '--inspector-port', String(inspectorPort), '--show-interactive-dev-session', 'false'], {
    cwd: root, stdio: ['ignore', log, log], detached: true, env: { ...process.env, CI: 'true' },
  });
  let childError;
  child.on('error', error => { childError = error; });
  let exit;
  child.on('exit', code => { exit = code; });
  const headers = { Authorization: `Bearer ${token}` };
  const interrupted = new AbortController();
  const stop = () => interrupted.abort(new Error('Maintenance interrupted; rerun safely to finish any remaining accounts'));
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
  const bounded = milliseconds => AbortSignal.any([interrupted.signal, AbortSignal.timeout(milliseconds)]);
  try {
    let ready = false;
    for (let attempt = 0; attempt < 120; attempt++) {
      interrupted.signal.throwIfAborted();
      ensure(!childError && exit === undefined, `Local maintenance runtime stopped; inspect private log ${logPath}`);
      try {
        const response = await fetch(`http://127.0.0.1:${port}/ready`, { headers, signal: bounded(1000) });
        ready = response.ok && (await response.json()).ready === true;
      } catch { /* Runtime or remote D1 binding is still starting. */ }
      if (ready) break;
      await delay(500, undefined, { signal: interrupted.signal });
    }
    ensure(ready, `Maintenance runtime unavailable or migration missing; inspect private log ${logPath}`);
    let inspected = 0, locked = 0;
    for (let batch = 0; batch < 10_000; batch++) {
      const response = await fetch(`http://127.0.0.1:${port}/backfill`, { method: 'POST', headers, signal: bounded(60_000) });
      ensure(response.ok, 'Backfill failed; existing batches remain valid and this command can be safely rerun');
      const result = await response.json();
      ensure(['inspected', 'locked', 'remaining'].every(key => Number.isSafeInteger(result[key]) && result[key] >= 0), 'Invalid maintenance response');
      inspected += result.inspected; locked += result.locked;
      if (result.remaining === 0) {
        const evidence = { environment, sweep_completed: true, inspected, locked, remaining: 0, completed_at: new Date().toISOString() };
        writeFileSync(resolve(working, 'result.json'), JSON.stringify(evidence, null, 2) + '\n', { mode: 0o600 });
        console.log(JSON.stringify(evidence));
        return;
      }
      ensure(result.inspected > 0, 'Backfill made no progress');
    }
    throw new Error('Backfill batch limit reached; rerun to continue');
  } finally {
    if (child.pid) { try { process.kill(-child.pid, 'SIGTERM'); } catch { /* Already exited. */ } }
    closeSync(log);
    rmSync(localConfig, { force: true });
    rmSync(localSecrets, { force: true });
    process.removeListener('SIGINT', stop);
    process.removeListener('SIGTERM', stop);
  }
}
main(process.argv.slice(2)).catch(error => { console.error(error instanceof Error ? error.message : 'Backfill failed'); process.exitCode = 1; });
