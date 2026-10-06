type WebEnvironment = { ASSETS: Fetcher; API?: Fetcher };

const RESERVED_PREFIXES = ['/api', '/auth', '/oauth2', '/.well-known'];

function isReservedPath(pathname: string) {
  return RESERVED_PREFIXES.some((prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`));
}

function unavailable() {
  return Response.json(
    { error: { code: 'service_unavailable', message: '服务暂时不可用' } },
    { status: 503, headers: { 'Cache-Control': 'no-store' } },
  );
}

export default {
  async fetch(request, env) {
    const pathname = new URL(request.url).pathname;
    if (isReservedPath(pathname)) {
      try {
        return await env.API?.fetch(request, { redirect: 'manual' }) ?? unavailable();
      } catch {
        return unavailable();
      }
    }
    const response = await env.ASSETS.fetch(request);
    const secured = new Response(response.body, response);
    secured.headers.set('X-Content-Type-Options', 'nosniff');
    secured.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    secured.headers.set('X-Frame-Options', 'DENY');
    secured.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    secured.headers.set('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' https: data:; connect-src 'self'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
    if (secured.headers.get('Content-Type')?.includes('text/html')) {
      secured.headers.set('Cache-Control', 'no-cache');
    }
    return secured;
  },
} satisfies ExportedHandler<WebEnvironment>;
