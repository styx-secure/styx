import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { defineConfig } from '@playwright/test';

const localChromium = `${homedir()}/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome`;
const browserProject = (browserName) => {
  const use = { browserName, headless: true };
  if (browserName === 'chromium' && existsSync(localChromium)) {
    use.launchOptions = { executablePath: localChromium };
  }
  return { name: browserName, use };
};

export default defineConfig({
  testDir: './test/storage',
  testMatch: /vault-identity\.browser\.spec\.js/,
  forbidOnly: true,
  fullyParallel: false,
  workers: 1,
  timeout: 3 * 60 * 1000,
  projects: ['chromium', 'firefox'].map(browserProject),
});
