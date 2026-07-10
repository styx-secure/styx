import { defineConfig } from '@playwright/test';

// PWA e2e needs the real service worker, which vite-plugin-pwa only emits in a
// production build. So this config builds then serves `dist/` via vite preview.
export default defineConfig({
  testDir: './e2e',
  testMatch: 'pwa.spec.js',
  timeout: 120_000,
  workers: 1,
  use: {
    baseURL: 'http://127.0.0.1:4180',
    headless: true,
    ...(process.env.PW_EXECUTABLE
      ? { launchOptions: { executablePath: process.env.PW_EXECUTABLE } }
      : {}),
  },
  webServer: {
    command: 'npm run build && npm run preview -- --port 4180 --host 127.0.0.1',
    url: 'http://127.0.0.1:4180',
    reuseExistingServer: false,
    timeout: 120_000,
  },
});
