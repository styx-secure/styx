import { defineConfig } from '@playwright/test';
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';

const cachedChromium = `${homedir()}/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome`;
const localLaunch = process.env.PW_EXECUTABLE
  ? { launchOptions: { executablePath: process.env.PW_EXECUTABLE } }
  : existsSync(cachedChromium)
    ? { launchOptions: { executablePath: cachedChromium } }
    : {};

export default defineConfig({
  testDir: './e2e',
  testMatch: 'vault-settings.spec.js',
  timeout: 180_000,
  workers: 1,
  use: {
    baseURL: 'http://127.0.0.1:4182',
    headless: true,
    ...localLaunch,
  },
  webServer: {
    command: 'VITE_VAULT_STAGE=test-profile npm run build -- --outDir dist-vault-test && STYX_DIST=dist-vault-test STYX_PORT=4182 node static-server.mjs',
    url: 'http://127.0.0.1:4182',
    reuseExistingServer: false,
    timeout: 120_000,
  },
});
