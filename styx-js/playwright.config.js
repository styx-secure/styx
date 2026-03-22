import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './test/webrtc',
  timeout: 30000,
  projects: [
    {
      name: 'chromium',
      use: { browserName: 'chromium', headless: true },
      testMatch: 'webrtc.spec.js',
    },
    {
      name: 'firefox',
      use: { browserName: 'firefox', headless: true },
      testMatch: 'webrtc.spec.js',
    },
    {
      name: 'cross-browser',
      use: { browserName: 'chromium', headless: true },
      testMatch: 'webrtc-cross-browser.spec.js',
    },
  ],
});
