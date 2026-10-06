import { env } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';
import maintenance from '../src/maintenance/backfill-official-locks';

describe('local account lock maintenance entry point', () => {
  const token = 'local-fixture-maintenance-token-at-least-32-characters';
  it('requires loopback host, a configured bearer token and the exact maintenance method/path', async () => {
    for (const [url, auth] of [['https://public.example/backfill', token], ['http://127.0.0.1/backfill', 'wrong']]) {
      const result = await maintenance.fetch(new Request(url, { method: 'POST', headers: { Authorization: `Bearer ${auth}` } }), { DB: env.DB, MAINTENANCE_TOKEN: token });
      expect(result.status).toBe(403);
    }
    const headers = { Authorization: `Bearer ${token}` };
    expect((await maintenance.fetch(new Request('http://127.0.0.1/backfill', { headers }), { DB: env.DB, MAINTENANCE_TOKEN: token })).status).toBe(404);
    expect((await maintenance.fetch(new Request('http://127.0.0.1/ready', { headers }), { DB: env.DB, MAINTENANCE_TOKEN: token })).status).toBe(200);
    const result = await maintenance.fetch(new Request('http://127.0.0.1/backfill', { method: 'POST', headers }), { DB: env.DB, MAINTENANCE_TOKEN: token });
    expect(await result.json()).toEqual({ inspected: 0, locked: 0, remaining: 0 });
    expect(result.headers.get('Cache-Control')).toBe('no-store');
  });
});
