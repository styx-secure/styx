// Playwright config for the vault IndexedDB engine browser probes (US-005).
// Run from styx-js/:  npx playwright test -c playwright.vault-db.config.js
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { defineConfig } from '@playwright/test';

// Local-environment caveat (same as playwright.kdf.config.js): when the host
// OS has no matching Playwright Chromium build, reuse the newer cached build.
// In CI the browsers are installed normally and this fallback is inert.
const cachedChromium = `${homedir()}/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome`;
const chromiumLaunch = existsSync(cachedChromium)
  ? { launchOptions: { executablePath: cachedChromium } } : {};

export default defineConfig({
  testDir: './test/storage',
  testMatch: 'vault-db.browser.spec.js',
  timeout: 120000,
  fullyParallel: false,
  workers: 1,
  projects: [
    { name: 'chromium', use: { browserName: 'chromium', headless: true, ...chromiumLaunch } },
    { name: 'firefox', use: { browserName: 'firefox', headless: true } },
  ],
});
