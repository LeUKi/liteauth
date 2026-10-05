import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import { readFileSync } from 'node:fs';
import { defineConfig } from 'vite';

const packageJson = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8')) as { version: string };
const buildTimestamp = Math.floor(Date.now() / 1000);

export default defineConfig({
  plugins: [react(), tailwindcss()],
  define: {
    __LITEAUTH_VERSION__: JSON.stringify(packageJson.version),
    __LITEAUTH_BUILD_TIME__: JSON.stringify(buildTimestamp),
  },
  server: {
    port: 5188,
    strictPort: true,
    proxy: {
      '/api': 'http://127.0.0.1:8798',
      '/auth': 'http://127.0.0.1:8798',
      '/oauth2': 'http://127.0.0.1:8798',
      '/.well-known': 'http://127.0.0.1:8798',
    },
  },
  build: { target: 'es2022', sourcemap: false },
});
