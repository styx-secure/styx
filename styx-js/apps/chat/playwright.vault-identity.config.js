import { defineConfig } from '@playwright/test';
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';

const bundledChromium = `${homedir()}/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome`;
const requestedExecutable = process.env.PW_EXECUTABLE
  || (existsSync(bundledChromium) ? bundledChromium : undefined);
const use = {
  baseURL: 'http://127.0.0.1:4183',
  browserName: 'chromium',
  headless: true,
};
if (requestedExecutable) use.launchOptions = { executablePath: requestedExecutable };

export default defineConfig({
  testDir: './e2e',
  testMatch: /vault-identity\.spec\.js/,
  forbidOnly: true,
  timeout: 3 * 60 * 1000,
  workers: 1,
  use,
  webServer: {
    command: [
      'VITE_VAULT_STAGE=test-profile npm run build -- --outDir dist-vault-identity-e2e',
      'STYX_DIST=dist-vault-identity-e2e STYX_PORT=4183 node static-server.mjs',
    ].join(' && '),
    url: use.baseURL,
    reuseExistingServer: false,
    timeout: 2 * 60 * 1000,
  },
});
