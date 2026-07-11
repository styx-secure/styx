// Playwright config for the IndexedDB vault spike ONLY (STYX_SPIKE_PROTOTYPE).
// Run from styx-js/:  npx playwright test -c spikes/indexeddb-vault/playwright.spike.config.js
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { defineConfig } from '@playwright/test';

// Playwright 1.58 ships no Chromium build for this OS (ubuntu26.04): reuse the
// newer cached build when present. Harmless drift for a spike — recorded in the
// spike doc as an environment caveat.
const cachedChromium = `${homedir()}/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome`;
const chromiumLaunch = existsSync(cachedChromium)
  ? { launchOptions: { executablePath: cachedChromium } } : {};

export default defineConfig({
  testDir: '.',
  testMatch: 'vault-spike.spec.js',
  timeout: 60000,
  fullyParallel: false,
  workers: 1, // the spike measures real storage behavior — no cross-test interference
  projects: [
    { name: 'chromium', use: { browserName: 'chromium', headless: true, ...chromiumLaunch } },
    { name: 'firefox', use: { browserName: 'firefox', headless: true } },
  ],
});
