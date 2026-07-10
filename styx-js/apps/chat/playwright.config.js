import { defineConfig } from '@playwright/test';

// Two-page E2E for Styx Chat over the real StyxChat library (MLS/OpenMLS) and
// the BroadcastChannel transport. Auto-starts the Vite dev server.
//
// In sandboxes where Playwright can't manage its own Chromium, point
// PW_EXECUTABLE at an installed chrome binary.
export default defineConfig({
  testDir: './e2e',
  testIgnore: 'pwa.spec.js',
  timeout: 60_000,
  fullyParallel: false,
  workers: 1,
  use: {
    baseURL: 'http://localhost:5175',
    headless: true,
    ...(process.env.PW_EXECUTABLE
      ? { launchOptions: { executablePath: process.env.PW_EXECUTABLE } }
      : {}),
  },
  webServer: {
    command: 'npm run dev',
    url: 'http://localhost:5175',
    reuseExistingServer: true,
    timeout: 60_000,
  },
});
