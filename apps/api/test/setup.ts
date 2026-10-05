import { applyD1Migrations, env } from 'cloudflare:test';
import { beforeAll, beforeEach } from 'vitest';
beforeAll(async () => { await applyD1Migrations(env.DB, env.TEST_MIGRATIONS); });
beforeEach(async () => {
  for (const table of ['oauth_access_token', 'oauth_refresh_token', 'oauth_consent', 'app_settings', 'oauth_client_resource', 'oauth_client', 'oauth_resource', 'account', 'session', 'verification', 'grant_ledger', 'auth_event', 'upstream_credential', 'connect_transaction', 'authorization_request', 'rate_limit', 'audit', 'mutation_guard', 'user', 'jwks']) {
    await env.DB.prepare(`DELETE FROM ${table}`).run();
  }
});
