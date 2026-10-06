import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { validateDeployment, artifactHashes, verifyStagedArtifact, deploymentSourceHashes } from './deploy.mjs';

function configurations() {
  const api = JSON.parse(readFileSync(new URL('../apps/api/wrangler.example.jsonc', import.meta.url)));
  const web = JSON.parse(readFileSync(new URL('../apps/web/wrangler.example.jsonc', import.meta.url)));
  api.account_id = web.account_id = 'a'.repeat(32);
  for (const [index, environment] of ['staging', 'production'].entries()) {
    const hostname = `${environment}.auth.test`;
    const entry = api.env[environment];
    entry.vars.APP_ORIGIN = `https://${hostname}`;
    entry.vars.ADMIN_LINUXDO_ID = '900001';
    entry.d1_databases[0].database_id = `${index ? 'bbbbbbbb' : 'aaaaaaaa'}-aaaa-aaaa-aaaa-aaaaaaaaaaaa`;
    for (const route of entry.routes) { route.pattern = hostname + '/' + route.pattern.split('/').slice(1).join('/'); route.zone_name = 'auth.test'; }
    web.env[environment].routes[0].pattern = hostname;
    web.env[environment].services = [{ binding: 'API', service: entry.name }];
  }
  return { api, web };
}
test('accepts explicitly configured isolated environments', () => {
  const { api, web } = configurations();
  for (const environment of ['staging', 'production']) assert.equal(validateDeployment(api, web, environment).environment, environment);
});
for (const invalid of [undefined, '', ' 900001', '+900001', '9e5', '0', '9007199254740992']) {
  test(`rejects unsafe administrator configuration ${JSON.stringify(invalid)}`, () => {
    const { api, web } = configurations(); api.env.production.vars.ADMIN_LINUXDO_ID = invalid;
    assert.throws(() => validateDeployment(api, web, 'production'), /ADMIN_LINUXDO_ID/);
  });
}
for (const [name, mutate] of [
  ['example domain', ({ api }) => { api.env.production.vars.APP_ORIGIN = 'https://liteauth.example.com'; }],
  ['database sharing', ({ api }) => { api.env.production.d1_databases[0].database_id = api.env.staging.d1_databases[0].database_id; }],
  ['missing backend route', ({ api }) => { api.env.production.routes.pop(); }],
  ['incorrect frontend domain', ({ web }) => { web.env.production.routes[0].pattern = 'other.auth.test'; }],
  ['static assets before Worker routing', ({ web }) => { web.assets.run_worker_first = false; }],
  ['environment static assets before Worker routing', ({ web }) => { web.env.production.assets = { ...web.assets, run_worker_first: false }; }],
  ['incorrect Web Worker entrypoint', ({ web }) => { web.main = 'other-worker.ts'; }],
  ['environment Web Worker entrypoint override', ({ web }) => { web.env.production.main = 'other-worker.ts'; }],
  ['public preview URL', ({ api }) => { api.env.production.preview_urls = true; }],
  ['automatic request logging', ({ api }) => { api.env.production.observability = { enabled: true }; }],
  ['cross-environment Worker collision', ({ api, web }) => { api.env.production.name = web.env.staging.name; }],
]) {
  test(`rejects ${name}`, () => {
    const configs = configurations(); mutate(configs);
    assert.throws(() => validateDeployment(configs.api, configs.web, 'production'));
  });
}

for (const [name, mutate, message] of [
  ['missing API Service Binding', ({ web }) => { web.env.production.services = []; }, /exactly one/],
  ['duplicate API Service Binding', ({ web, api }) => { web.env.production.services.push({ binding: 'API', service: api.env.production.name }); }, /exactly one/],
  ['wrong API Service Binding target', ({ web }) => { web.env.production.services[0].service = 'other-worker'; }, /selected API Worker/],
  ['cross-environment API Service Binding target', ({ web, api }) => { web.env.production.services[0].service = api.env.staging.name; }, /selected API Worker/],
  ['self API Service Binding target', ({ web }) => { web.env.production.services[0].service = web.env.production.name; }, /Web Worker/],
  ['API Service Binding environment override', ({ web }) => { web.env.production.services[0].environment = 'production'; }, /environment or entrypoint/],
  ['API Service Binding entrypoint override', ({ web }) => { web.env.production.services[0].entrypoint = 'Admin'; }, /environment or entrypoint/],
]) {
  test(`rejects ${name}`, () => {
    const configs = configurations(); mutate(configs);
    assert.throws(() => validateDeployment(configs.api, configs.web, 'production'), message);
  });
}

test('production promotion requires the same files, version and staging target', () => {
  const directory = mkdtempSync(join(tmpdir(), 'liteauth-artifact-test-'));
  try {
    writeFileSync(join(directory, 'index.html'), '<div>staged</div>');
    writeFileSync(join(directory, 'app.js'), 'const version="0.1.0";');
    const sourceFiles = deploymentSourceHashes();
    const manifest = { environment: 'staging', origin: 'https://staging.auth.test', version: '0.1.0', files: artifactHashes(directory), sourceFiles };
    assert.doesNotThrow(() => verifyStagedArtifact(directory, manifest, manifest.origin, manifest.version, sourceFiles));
    assert.throws(() => verifyStagedArtifact(directory, undefined, manifest.origin, manifest.version, sourceFiles));
    assert.throws(() => verifyStagedArtifact(directory, manifest, 'https://other.auth.test', manifest.version, sourceFiles));
    assert.throws(() => verifyStagedArtifact(directory, manifest, manifest.origin, '0.2.0', sourceFiles));
    assert.throws(() => verifyStagedArtifact(directory, { ...manifest, sourceFiles: undefined }, manifest.origin, manifest.version, sourceFiles), /source/);
    assert.throws(() => verifyStagedArtifact(directory, manifest, manifest.origin, manifest.version, [{ ...sourceFiles[0], sha256: '0'.repeat(64) }, ...sourceFiles.slice(1)]), /source/);
    writeFileSync(join(directory, 'app.js'), 'const version="changed";');
    assert.throws(() => verifyStagedArtifact(directory, manifest, manifest.origin, manifest.version, sourceFiles), /differs/);
  } finally { rmSync(directory, { recursive: true }); }
});
