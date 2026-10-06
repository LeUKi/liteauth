import { backfillOfficialLocks } from '../account-policy';

// This entry point is run only by the local maintenance runner. It is not imported by the API Worker.
export default {
  async fetch(request: Request, env: { DB: D1Database; MAINTENANCE_TOKEN: string }): Promise<Response> {
    const url = new URL(request.url);
    if (url.hostname !== '127.0.0.1' || !env.MAINTENANCE_TOKEN || env.MAINTENANCE_TOKEN.length < 32 ||
      request.headers.get('Authorization') !== `Bearer ${env.MAINTENANCE_TOKEN}`) return new Response(null, { status: 403 });
    try {
      if (request.method === 'GET' && url.pathname === '/ready') {
        await env.DB.prepare('SELECT official_verified_at FROM user LIMIT 0').all();
        return Response.json({ ready: true });
      }
      if (request.method === 'POST' && url.pathname === '/backfill') {
        return Response.json(await backfillOfficialLocks(env.DB), { headers: { 'Cache-Control': 'no-store' } });
      }
      return new Response(null, { status: 404 });
    } catch {
      // Database/provider errors can contain bound values. Keep them out of maintenance responses.
      return Response.json({ error: 'backfill_failed' }, { status: 500 });
    }
  },
};
