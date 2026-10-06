import { test } from 'node:test';
import assert from 'node:assert/strict';
import probe from './worker.js';

const environment = {
  TARGET_ORIGIN: 'https://liteauth.example.com',
  PROBE_TOKEN: 'synthetic-probe-credential-for-tests',
  PROBE_EXPIRES_AT: String(Math.floor(Date.now() / 1000) + 3600),
};
function request(body, headers = {}) {
  return new Request('https://staging.liteauth.example.com/__routing-proof-test/private/run', {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
}

test('unauthenticated, expired and invalid-mode calls never make an outbound request', async (t) => {
  const outbound = t.mock.method(globalThis, 'fetch', () => { throw new Error('unexpected outbound request'); });
  const noCredential = await probe.fetch(request({ mode: 'protocol' }), environment);
  assert.equal(noCredential.status, 401);
  const expired = await probe.fetch(request({ mode: 'baseline' }, { 'X-Probe-Token': environment.PROBE_TOKEN }), {
    ...environment, PROBE_EXPIRES_AT: '1',
  });
  assert.equal(expired.status, 400);
  const invalidMode = await probe.fetch(request({ mode: 'proxy', url: 'https://other.example/' }, {
    'X-Probe-Token': environment.PROBE_TOKEN,
  }), environment);
  assert.equal(invalidMode.status, 400);
  assert.equal(outbound.mock.callCount(), 0);
  assert.equal(noCredential.headers.get('Cache-Control'), 'no-store');
});

test('baseline ignores a supplied target and only fetches the configured origin without credentials', async (t) => {
  const outbound = t.mock.method(globalThis, 'fetch', async (input, init) => {
    const url = new URL(input);
    assert.equal(url.origin, environment.TARGET_ORIGIN);
    assert.equal(init.redirect, 'manual');
    assert.equal(new Headers(init.headers).has('X-Probe-Token'), false);
    assert.equal(new Headers(init.headers).has('Cookie'), false);
    return Response.json({ error: 'not_found' }, { status: 404 });
  });
  const response = await probe.fetch(request({ mode: 'baseline', target_origin: 'https://other.example/' }, {
    'X-Probe-Token': environment.PROBE_TOKEN,
  }), environment);
  assert.equal(response.status, 424);
  assert.ok(outbound.mock.callCount() >= 5);
  const text = await response.text();
  assert.equal(text.includes(environment.PROBE_TOKEN), false);
  assert.equal(text.includes('https://other.example/'), false);
});
