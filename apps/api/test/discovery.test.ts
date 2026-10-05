import { env } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';
import { app } from '../src/index';

describe('public discovery matches the exposed protocol', () => {
  it('allows browser clients to read public discovery and keys without granting cookie access', async () => {
    for (const path of ['/api/auth/.well-known/openid-configuration', '/api/auth/jwks', '/.well-known/openid-configuration']) {
      const response = await app.request(path, { headers: { Origin: 'https://rp.example' } }, env);
      expect(response.status).toBe(200);
      expect(response.headers.get('Access-Control-Allow-Origin')).toBe('https://rp.example');
      expect(response.headers.get('Access-Control-Allow-Credentials')).toBeNull();
    }
    const restricted = await app.request('/api/session', { headers: { Origin: 'https://rp.example' } }, env);
    expect(restricted.headers.get('Access-Control-Allow-Origin')).toBeNull();
  });
  it.each(['openid-configuration', 'oauth-authorization-server'])('describes supported %s capabilities', async (document) => {
    const response = await app.request(`/api/auth/.well-known/${document}`, {}, env);
    expect(response.status).toBe(200);
    const metadata = await response.json() as Record<string, unknown>;
    expect(metadata.issuer).toBe(`${env.APP_ORIGIN}/api/auth`);
    expect(metadata.grant_types_supported).toEqual(['authorization_code']);
    expect(metadata.response_types_supported).toEqual(['code']);
    expect(metadata.token_endpoint_auth_methods_supported).toEqual(['client_secret_post', 'none']);
    expect(metadata.introspection_endpoint_auth_methods_supported).toEqual(['client_secret_post']);
    expect(metadata).not.toHaveProperty('registration_endpoint');
    expect(metadata).not.toHaveProperty('end_session_endpoint');
    expect(metadata).not.toHaveProperty('backchannel_logout_supported');
    expect(metadata).not.toHaveProperty('backchannel_logout_session_supported');
    if (document === 'openid-configuration') expect(metadata.prompt_values_supported).toEqual(['none', 'login', 'consent']);
    const alias = await app.request(`/.well-known/${document}`, {}, env);
    expect(await alias.json()).toEqual(metadata);
    if (document === 'oauth-authorization-server') {
      const issuerPath = await app.request('/.well-known/oauth-authorization-server/api/auth', {}, env);
      expect(issuerPath.status).toBe(200);
      expect(await issuerPath.json()).toEqual(metadata);
    }
  });
});
