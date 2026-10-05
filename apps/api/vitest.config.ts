import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-pool-workers';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [cloudflareTest(async () => ({
    wrangler: { configPath: './wrangler.jsonc' },
    miniflare: { bindings: {
      TEST_MIGRATIONS: await readD1Migrations('./migrations'),
      APP_ORIGIN: 'http://localhost:5173', ENVIRONMENT: 'development', ADMIN_LINUXDO_ID: '900001',
      BETTER_AUTH_SECRET: 'test-secret-at-least-thirty-two-characters',
      CREDENTIAL_ENCRYPTION_KEY: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
      CONNECT_CLIENT_ID: 'platform-test-client', CONNECT_CLIENT_SECRET: 'platform-test-secret',
    } },
  }))],
  test: { setupFiles: ['./test/setup.ts'], include: ['test/**/*.test.ts'] },
});
