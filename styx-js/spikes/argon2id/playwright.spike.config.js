// Playwright config for the Argon2id spike ONLY (STYX_SPIKE_PROTOTYPE).
// Run from styx-js/:  npx playwright test -c spikes/argon2id/playwright.spike.config.js
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { defineConfig } from '@playwright/test';

// Same environment caveat as the other spikes: Playwright 1.58 ships no Chromium
// build for this OS; reuse the newer cached build when present.
const cachedChromium = `${homedir()}/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome`;
const chromiumLaunch = existsSync(cachedChromium)
  ? { launchOptions: { executablePath: cachedChromium } } : {};

export default defineConfig({
  testDir: '.',
  testMatch: 'argon2-spike.spec.js',
  timeout: 120000,
  fullyParallel: false,
  workers: 1, // benchmarks — no cross-test CPU interference
  projects: [
    { name: 'chromium', use: { browserName: 'chromium', headless: true, ...chromiumLaunch } },
    { name: 'firefox', use: { browserName: 'firefox', headless: true } },
  ],
});
