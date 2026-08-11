import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { defineConfig } from '@playwright/test';

const cachedChromium = `${homedir()}/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome`;
const chromiumLaunch = existsSync(cachedChromium)
  ? { launchOptions: { executablePath: cachedChromium } } : {};

export default defineConfig({
  testDir: '.',
  testMatch: 'journal.browser.spec.js',
  timeout: 300000,
  fullyParallel: false,
  workers: 1,
  webServer: {
    command: 'python3 -m http.server 18764 --bind 127.0.0.1',
    cwd: '../..',
    url: 'http://127.0.0.1:18764/spikes/marmot-phase-b2-3/harness.html',
    reuseExistingServer: false,
    timeout: 30000,
  },
  projects: [
    { name: 'chromium', use: { browserName: 'chromium', headless: true, ...chromiumLaunch } },
    { name: 'firefox', use: { browserName: 'firefox', headless: true } },
  ],
});
