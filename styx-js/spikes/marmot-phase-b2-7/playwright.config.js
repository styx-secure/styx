import { accessSync, constants } from 'node:fs';
import { join } from 'node:path';
import { defineConfig } from '@playwright/test';

const HTTP_PORT = 18766;
const HARNESS_PATH = '/spikes/marmot-phase-b2-7/harness.html';

function chromiumProject() {
  const candidate = join(process.env.HOME ?? '', '.cache', 'ms-playwright',
    'chromium-1228', 'chrome-linux64', 'chrome');
  let launchOptions;
  try {
    accessSync(candidate, constants.X_OK);
    launchOptions = { executablePath: candidate };
  } catch {
    launchOptions = undefined;
  }
  return { name: 'chromium', use: { browserName: 'chromium', launchOptions } };
}

const browserProjects = Object.freeze([
  chromiumProject(),
  { name: 'firefox', use: { browserName: 'firefox' } },
]);

export default defineConfig({
  testDir: '.',
  testMatch: /journal\.browser\.spec\.js$/,
  forbidOnly: true,
  fullyParallel: false,
  retries: 0,
  workers: 1,
  timeout: 300_000,
  use: { headless: true, trace: 'retain-on-failure' },
  outputDir: 'test-results',
  webServer: {
    command: `python3 -m http.server ${HTTP_PORT} --bind 127.0.0.1`,
    cwd: '../..',
    url: `http://127.0.0.1:${HTTP_PORT}${HARNESS_PATH}`,
    reuseExistingServer: false,
    timeout: 30_000,
  },
  projects: browserProjects,
});
