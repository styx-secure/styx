// @ts-check
/**
 * Cross-browser WebRTC tests: Peer A on one browser, Peer B on another.
 * Verifies that DataChannel works across different browser engines.
 *
 * Run: npx playwright test test/webrtc/webrtc-cross-browser.spec.js
 */

import { test, expect, chromium, firefox, webkit } from '@playwright/test';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PEER_HTML = 'file://' + join(__dirname, 'peer.html');

async function connectCrossBrowser(browserA, browserB) {
  const pageA = await browserA.newPage();
  const pageB = await browserB.newPage();

  await pageA.goto(PEER_HTML);
  await pageB.goto(PEER_HTML);
  await pageA.waitForFunction(() => window.__ready);
  await pageB.waitForFunction(() => window.__ready);

  const offer = await pageA.evaluate(() => window.__peer.createOffer());
  const answer = await pageB.evaluate((o) => window.__peer.handleOffer(o), offer);
  await pageA.evaluate((a) => window.__peer.handleAnswer(a), answer);

  for (let i = 0; i < 15; i++) {
    const cA = await pageA.evaluate(() => window.__peer.getCandidate());
    if (cA) await pageB.evaluate((c) => window.__peer.addCandidate(c), cA);

    const cB = await pageB.evaluate(() => window.__peer.getCandidate());
    if (cB) await pageA.evaluate((c) => window.__peer.addCandidate(c), cB);

    const sA = await pageA.evaluate(() => window.__peer.state);
    const sB = await pageB.evaluate(() => window.__peer.state);
    if (sA === 'connected' && sB === 'connected') break;
  }

  await pageA.waitForFunction(() => window.__peer.state === 'connected', { timeout: 15000 });
  await pageB.waitForFunction(() => window.__peer.state === 'connected', { timeout: 15000 });

  return { pageA, pageB };
}

test.describe('WebRTC Cross-Browser', () => {
  let browserChromium, browserFirefox, browserWebkit;

  test.beforeAll(async () => {
    browserChromium = await chromium.launch({ headless: true });
    try { browserFirefox = await firefox.launch({ headless: true }); } catch { browserFirefox = null; }
    try { browserWebkit = await webkit.launch({ headless: true }); } catch { browserWebkit = null; }
  });

  test.afterAll(async () => {
    if (browserChromium) await browserChromium.close();
    if (browserFirefox) await browserFirefox.close();
    if (browserWebkit) await browserWebkit.close();
  });

  test('Chromium ↔ Firefox: message round-trip', async () => {
    test.skip(!browserFirefox, 'Firefox not available');

    const { pageA, pageB } = await connectCrossBrowser(browserChromium, browserFirefox);

    // Chromium → Firefox
    await pageA.evaluate(() => window.__peer.send({ id: 'cf-1', from: 'chromium' }));
    await pageB.waitForFunction(() => window.__peer.received.length >= 1, { timeout: 5000 });
    let received = await pageB.evaluate(() => window.__peer.received);
    expect(received[0].from).toBe('chromium');

    // Firefox → Chromium
    await pageB.evaluate(() => window.__peer.send({ id: 'cf-2', from: 'firefox' }));
    await pageA.waitForFunction(() => window.__peer.received.length >= 1, { timeout: 5000 });
    received = await pageA.evaluate(() => window.__peer.received);
    expect(received[0].from).toBe('firefox');

    await pageA.close();
    await pageB.close();
  });

  test('Chromium ↔ WebKit: message round-trip', async () => {
    test.skip(!browserWebkit, 'WebKit not available');

    const { pageA, pageB } = await connectCrossBrowser(browserChromium, browserWebkit);

    await pageA.evaluate(() => window.__peer.send({ id: 'cw-1', from: 'chromium' }));
    await pageB.waitForFunction(() => window.__peer.received.length >= 1, { timeout: 5000 });
    let received = await pageB.evaluate(() => window.__peer.received);
    expect(received[0].from).toBe('chromium');

    await pageB.evaluate(() => window.__peer.send({ id: 'cw-2', from: 'webkit' }));
    await pageA.waitForFunction(() => window.__peer.received.length >= 1, { timeout: 5000 });
    received = await pageA.evaluate(() => window.__peer.received);
    expect(received[0].from).toBe('webkit');

    await pageA.close();
    await pageB.close();
  });

  test('Firefox ↔ WebKit: message round-trip', async () => {
    test.skip(!browserFirefox || !browserWebkit, 'Firefox or WebKit not available');

    const { pageA, pageB } = await connectCrossBrowser(browserFirefox, browserWebkit);

    await pageA.evaluate(() => window.__peer.send({ id: 'fw-1', from: 'firefox' }));
    await pageB.waitForFunction(() => window.__peer.received.length >= 1, { timeout: 5000 });
    let received = await pageB.evaluate(() => window.__peer.received);
    expect(received[0].from).toBe('firefox');

    await pageB.evaluate(() => window.__peer.send({ id: 'fw-2', from: 'webkit' }));
    await pageA.waitForFunction(() => window.__peer.received.length >= 1, { timeout: 5000 });
    received = await pageA.evaluate(() => window.__peer.received);
    expect(received[0].from).toBe('webkit');

    await pageA.close();
    await pageB.close();
  });
});
