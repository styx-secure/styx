// @ts-check
/**
 * WebRTC DataChannel tests using Playwright with real Chromium browsers.
 *
 * Two browser pages act as peers, performing the full WebRTC signaling dance
 * (offer → answer → ICE candidates) and exchanging messages via DataChannel.
 *
 * Run: npx playwright test test/webrtc/webrtc.spec.js
 */

import { test, expect } from '@playwright/test';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PEER_HTML = 'file://' + join(__dirname, 'peer.html');

test.describe('WebRTC DataChannel (real browser)', () => {

  test('two peers connect via offer/answer and exchange ICE candidates', async ({ browser }) => {
    const pageA = await browser.newPage();
    const pageB = await browser.newPage();

    await pageA.goto(PEER_HTML);
    await pageB.goto(PEER_HTML);

    // Wait for pages to initialize
    await pageA.waitForFunction(() => window.__ready);
    await pageB.waitForFunction(() => window.__ready);

    // A creates offer
    const offer = await pageA.evaluate(() => window.__peer.createOffer());

    // B handles offer, creates answer
    const answer = await pageB.evaluate((offer) => window.__peer.handleOffer(offer), offer);

    // A handles answer
    await pageA.evaluate((answer) => window.__peer.handleAnswer(answer), answer);

    // Exchange ICE candidates (both directions)
    // Collect candidates from A → B and B → A
    for (let i = 0; i < 10; i++) {
      const candA = await pageA.evaluate(() => window.__peer.getCandidate());
      if (candA) {
        await pageB.evaluate((c) => window.__peer.addCandidate(c), candA);
      }

      const candB = await pageB.evaluate(() => window.__peer.getCandidate());
      if (candB) {
        await pageA.evaluate((c) => window.__peer.addCandidate(c), candB);
      }

      // Check if both are connected
      const stateA = await pageA.evaluate(() => window.__peer.state);
      const stateB = await pageB.evaluate(() => window.__peer.state);
      if (stateA === 'connected' && stateB === 'connected') break;
    }

    // Wait for DataChannel to open
    await pageA.waitForFunction(() => window.__peer.state === 'connected', { timeout: 10000 });
    await pageB.waitForFunction(() => window.__peer.state === 'connected', { timeout: 10000 });

    const stateA = await pageA.evaluate(() => window.__peer.state);
    const stateB = await pageB.evaluate(() => window.__peer.state);
    expect(stateA).toBe('connected');
    expect(stateB).toBe('connected');

    await pageA.close();
    await pageB.close();
  });

  test('send message A → B via DataChannel', async ({ browser }) => {
    const { pageA, pageB } = await connectPeers(browser);

    // A sends message to B
    const sent = await pageA.evaluate(() =>
      window.__peer.send({ id: 'msg-1', payload: 'hello from A' })
    );
    expect(sent).toBe(true);

    // Wait for B to receive
    await pageB.waitForFunction(() => window.__peer.received.length >= 1, { timeout: 5000 });

    const received = await pageB.evaluate(() => window.__peer.received);
    expect(received).toHaveLength(1);
    expect(received[0].id).toBe('msg-1');
    expect(received[0].payload).toBe('hello from A');

    await pageA.close();
    await pageB.close();
  });

  test('send message B → A via DataChannel', async ({ browser }) => {
    const { pageA, pageB } = await connectPeers(browser);

    await pageB.evaluate(() =>
      window.__peer.send({ id: 'msg-2', payload: 'hello from B' })
    );

    await pageA.waitForFunction(() => window.__peer.received.length >= 1, { timeout: 5000 });

    const received = await pageA.evaluate(() => window.__peer.received);
    expect(received[0].id).toBe('msg-2');
    expect(received[0].payload).toBe('hello from B');

    await pageA.close();
    await pageB.close();
  });

  test('bidirectional message exchange', async ({ browser }) => {
    const { pageA, pageB } = await connectPeers(browser);

    // A → B
    await pageA.evaluate(() => window.__peer.send({ id: '1', from: 'A' }));
    // B → A
    await pageB.evaluate(() => window.__peer.send({ id: '2', from: 'B' }));
    // A → B again
    await pageA.evaluate(() => window.__peer.send({ id: '3', from: 'A' }));

    await pageB.waitForFunction(() => window.__peer.received.length >= 2, { timeout: 5000 });
    await pageA.waitForFunction(() => window.__peer.received.length >= 1, { timeout: 5000 });

    const bReceived = await pageB.evaluate(() => window.__peer.received);
    const aReceived = await pageA.evaluate(() => window.__peer.received);

    expect(bReceived).toHaveLength(2);
    expect(bReceived[0].id).toBe('1');
    expect(bReceived[1].id).toBe('3');
    expect(aReceived).toHaveLength(1);
    expect(aReceived[0].id).toBe('2');

    await pageA.close();
    await pageB.close();
  });

  test('disconnect closes DataChannel', async ({ browser }) => {
    const { pageA, pageB } = await connectPeers(browser);

    await pageA.evaluate(() => window.__peer.disconnect());

    const stateA = await pageA.evaluate(() => window.__peer.state);
    expect(stateA).toBe('disconnected');

    // B should detect disconnection
    await pageB.waitForFunction(
      () => window.__peer.state === 'disconnected',
      { timeout: 5000 }
    );
    const stateB = await pageB.evaluate(() => window.__peer.state);
    expect(stateB).toBe('disconnected');

    await pageA.close();
    await pageB.close();
  });

  test('send on closed channel returns false', async ({ browser }) => {
    const { pageA, pageB } = await connectPeers(browser);

    await pageA.evaluate(() => window.__peer.disconnect());

    const sent = await pageA.evaluate(() =>
      window.__peer.send({ id: 'x', payload: 'should fail' })
    );
    expect(sent).toBe(false);

    await pageA.close();
    await pageB.close();
  });

  test('large message transfer', async ({ browser }) => {
    const { pageA, pageB } = await connectPeers(browser);

    // Send a 50KB message
    const bigPayload = 'x'.repeat(50000);
    await pageA.evaluate((payload) =>
      window.__peer.send({ id: 'big', payload }),
      bigPayload
    );

    await pageB.waitForFunction(() => window.__peer.received.length >= 1, { timeout: 10000 });

    const received = await pageB.evaluate(() => window.__peer.received);
    expect(received[0].id).toBe('big');
    expect(received[0].payload.length).toBe(50000);

    await pageA.close();
    await pageB.close();
  });

  test('multiple sequential messages maintain order', async ({ browser }) => {
    const { pageA, pageB } = await connectPeers(browser);

    for (let i = 0; i < 20; i++) {
      await pageA.evaluate((i) =>
        window.__peer.send({ id: `seq-${i}`, index: i }),
        i
      );
    }

    await pageB.waitForFunction(() => window.__peer.received.length >= 20, { timeout: 10000 });

    const received = await pageB.evaluate(() => window.__peer.received);
    expect(received).toHaveLength(20);
    for (let i = 0; i < 20; i++) {
      expect(received[i].index).toBe(i);
    }

    await pageA.close();
    await pageB.close();
  });
});

/**
 * Helper: connect two peers and return both pages.
 */
async function connectPeers(browser) {
  const pageA = await browser.newPage();
  const pageB = await browser.newPage();

  await pageA.goto(PEER_HTML);
  await pageB.goto(PEER_HTML);
  await pageA.waitForFunction(() => window.__ready);
  await pageB.waitForFunction(() => window.__ready);

  const offer = await pageA.evaluate(() => window.__peer.createOffer());
  const answer = await pageB.evaluate((o) => window.__peer.handleOffer(o), offer);
  await pageA.evaluate((a) => window.__peer.handleAnswer(a), answer);

  for (let i = 0; i < 10; i++) {
    const cA = await pageA.evaluate(() => window.__peer.getCandidate());
    if (cA) await pageB.evaluate((c) => window.__peer.addCandidate(c), cA);

    const cB = await pageB.evaluate(() => window.__peer.getCandidate());
    if (cB) await pageA.evaluate((c) => window.__peer.addCandidate(c), cB);

    const sA = await pageA.evaluate(() => window.__peer.state);
    const sB = await pageB.evaluate(() => window.__peer.state);
    if (sA === 'connected' && sB === 'connected') break;
  }

  await pageA.waitForFunction(() => window.__peer.state === 'connected', { timeout: 10000 });
  await pageB.waitForFunction(() => window.__peer.state === 'connected', { timeout: 10000 });

  return { pageA, pageB };
}
