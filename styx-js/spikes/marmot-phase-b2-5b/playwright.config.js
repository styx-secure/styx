import { accessSync, constants } from 'node:fs';
import { join } from 'node:path';
import { defineConfig } from '@playwright/test';

function localChromiumOverride() {
  const executablePath = join(process.env.HOME ?? '', '.cache', 'ms-playwright',
    'chromium-1228', 'chrome-linux64', 'chrome');
  try {
    accessSync(executablePath, constants.X_OK);
    return { launchOptions: { executablePath } };
  } catch { return {}; }
}

export default defineConfig({
  testDir: '.',
  testMatch: 'journal.browser.spec.js',
  timeout: 300_000,
  fullyParallel: false,
  workers: 1,
  webServer: {
    command: 'python3 -m http.server 18765 --bind 127.0.0.1',
    cwd: '../..',
    url: 'http://127.0.0.1:18765/spikes/marmot-phase-b2-5b/harness.html',
    reuseExistingServer: false,
    timeout: 30_000,
  },
  projects: [
    { name: 'chromium', use: { browserName: 'chromium', headless: true,
      ...localChromiumOverride() } },
    { name: 'firefox', use: { browserName: 'firefox', headless: true } },
  ],
});
