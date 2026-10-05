type WebEnvironment = { ASSETS: Fetcher };

export default {
  async fetch(request, env) {
    const pathname = new URL(request.url).pathname;
    const reserved = ['/api', '/auth', '/oauth2', '/.well-known'];
    if (reserved.some((prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`))) {
      return Response.json(
        { error: { code: 'not_found', message: '请求不存在' } },
        { status: 404, headers: { 'Cache-Control': 'no-store' } },
      );
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
