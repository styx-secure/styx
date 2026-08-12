import { test, expect } from '@playwright/test';

const HARNESS = 'http://127.0.0.1:18765/spikes/marmot-phase-b2-5b/harness.html';
const PAGE_ERRORS = new WeakMap();

async function ready(page) {
  const errors = [];
  PAGE_ERRORS.set(page, errors);
  page.on('pageerror', (error) => errors.push(`${error.name}: ${error.message}`));
  await page.goto(HARNESS);
  await page.waitForFunction(() => globalThis.B25BHarness !== undefined);
}

function expectNoPageErrors(...pages) {
  for (const page of pages) expect(PAGE_ERRORS.get(page)).toEqual([]);
}

async function twoConnections(browser, tag) {
  const context = await browser.newContext();
  const pageA = await context.newPage();
  const pageB = await context.newPage();
  await Promise.all([ready(pageA), ready(pageB)]);
  await pageA.evaluate((value) => B25BHarness.open('a', value), tag);
  await pageB.evaluate((value) => B25BHarness.open('b', value), tag);
  await pageA.evaluate(() => B25BHarness.initialize('a'));
  return { context, pageA, pageB };
}

async function cleanup({ context, pageA, pageB }) {
  await pageB.evaluate(() => B25BHarness.close('b'));
  await pageA.evaluate(() => B25BHarness.destroy('a'));
  await context.close();
}

test('two connections CAS one exact durable publication attempt', async ({ browser, browserName }) => {
  const pages = await twoConnections(browser, `publish-${browserName}-${Date.now()}`);
  const { pageA, pageB } = pages;
  try {
    await pageA.evaluate(() => B25BHarness.prepare('a'));
    const outcomes = await Promise.all([
      pageA.evaluate(() => B25BHarness.attempt('a')
        .then(() => ({ ok: true })).catch((error) => ({ ok: false, code: error.code }))),
      pageB.evaluate(() => B25BHarness.attempt('b')
        .then(() => ({ ok: true })).catch((error) => ({ ok: false, code: error.code }))),
    ]);
    expect(outcomes.filter((item) => item.ok)).toHaveLength(1);
    expect(outcomes.filter((item) => !item.ok)).toEqual([
      expect.objectContaining({ code: 'B25B_CAS_CONFLICT' }),
    ]);
    const durable = await pageA.evaluate(() => B25BHarness.read('a'));
    expect(durable.local.publishAttempts).toBe(1);
    expect(durable.publication).toHaveLength(1);
    expect(durable.publication[0].artifactBytes).toEqual(durable.local.commitBytes);
    expectNoPageErrors(pageA, pageB);
  } finally {
    await cleanup(pages);
  }
});

test('two connections CAS one final arbitration successor', async ({ browser, browserName }) => {
  const pages = await twoConnections(browser, `resolve-${browserName}-${Date.now()}`);
  const { pageA, pageB } = pages;
  try {
    await pageA.evaluate(() => B25BHarness.prepare('a'));
    await pageA.evaluate(() => B25BHarness.attempt('a'));
    await pageA.evaluate(() => B25BHarness.acknowledge('a'));
    const batch = await pageA.evaluate(() => B25BHarness.freeze('a'));
    await Promise.all([
      pageA.evaluate(() => B25BHarness.armResolution('a')),
      pageB.evaluate(() => B25BHarness.armResolution('b')),
    ]);
    await Promise.all([
      pageA.evaluate((digest) => B25BHarness.startResolution('a', digest),
        batch.protocolBatchDigestHex),
      pageB.evaluate((digest) => B25BHarness.startResolution('b', digest),
        batch.protocolBatchDigestHex),
    ]);
    await Promise.all([
      pageA.waitForFunction(() => B25BHarness.resolutionEntered('a')),
      pageB.waitForFunction(() => B25BHarness.resolutionEntered('b')),
    ]);
    await Promise.all([
      pageA.evaluate(() => B25BHarness.releaseResolution('a')),
      pageB.evaluate(() => B25BHarness.releaseResolution('b')),
    ]);
    const outcomes = await Promise.all([
      pageA.evaluate(() => B25BHarness.resolutionResult('a')),
      pageB.evaluate(() => B25BHarness.resolutionResult('b')),
    ]);
    expect(outcomes.filter((item) => item.ok)).toHaveLength(1);
    expect(outcomes.filter((item) => !item.ok)).toEqual([
      expect.objectContaining({ code: 'B25B_CAS_CONFLICT' }),
    ]);
    const durable = await pageA.evaluate(() => B25BHarness.read('a'));
    expect(durable.head.epochDec).toBe('2');
    expect(durable.local.state).toBe('CONFIRMED');
    expectNoPageErrors(pageA, pageB);
  } finally {
    await cleanup(pages);
  }
});
