// Playwright config for the vault lifecycle browser probes (US-006): vault.js
// over the real IndexedDB engine and a real Argon2id KEK.
// Run from styx-js/:  npx playwright test -c playwright.vault-lifecycle.config.js
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { defineConfig } from '@playwright/test';

const cachedChromium = `${homedir()}/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome`;
const chromiumLaunch = existsSync(cachedChromium)
  ? { launchOptions: { executablePath: cachedChromium } } : {};

export default defineConfig({
  testDir: './test/storage',
  testMatch: 'vault.browser.spec.js',
  timeout: 120000,
  fullyParallel: false,
  workers: 1,
  projects: [
    { name: 'chromium', use: { browserName: 'chromium', headless: true, ...chromiumLaunch } },
    { name: 'firefox', use: { browserName: 'firefox', headless: true } },
  ],
});
