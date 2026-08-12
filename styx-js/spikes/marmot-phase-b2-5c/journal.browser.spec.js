import { test, expect } from '@playwright/test';

const HARNESS = 'http://127.0.0.1:18766/spikes/marmot-phase-b2-5c/harness.html';
const PAGE_ERRORS = new WeakMap();

async function ready(page) {
  const errors = [];
  PAGE_ERRORS.set(page, errors);
  page.on('pageerror', (error) => errors.push(`${error.name}: ${error.message}`));
  await page.goto(HARNESS);
  await page.waitForFunction(() => globalThis.B25CHarness !== undefined);
}

async function twoConnections(browser, tag) {
  const context = await browser.newContext();
  const pageA = await context.newPage();
  const pageB = await context.newPage();
  await Promise.all([ready(pageA), ready(pageB)]);
  await pageA.evaluate((value) => B25CHarness.open('a', value), tag);
  await pageB.evaluate((value) => B25CHarness.open('b', value), tag);
  await pageA.evaluate(() => B25CHarness.initialize('a'));
  return { context, pageA, pageB };
}

async function cleanup({ context, pageA, pageB }) {
  await pageB.evaluate(() => B25CHarness.close('b'));
  await pageA.evaluate(() => B25CHarness.destroy('a'));
  await context.close();
}

function expectNoPageErrors(...pages) {
  for (const page of pages) expect(PAGE_ERRORS.get(page)).toEqual([]);
}

test('two connections CAS one complete settlement successor', async ({ browser, browserName }) => {
  const pages = await twoConnections(browser, `settle-${browserName}-${Date.now()}`);
  const { pageA, pageB } = pages;
  try {
    await pageA.evaluate(() => B25CHarness.prepare('a'));
    const pass = await pageA.evaluate(() => B25CHarness.freeze('a'));
    await Promise.all([
      pageA.evaluate(() => B25CHarness.arm('a')),
      pageB.evaluate(() => B25CHarness.arm('b')),
    ]);
    await Promise.all([
      pageA.evaluate((digest) => B25CHarness.startSettle('a', digest), pass.passDigestHex),
      pageB.evaluate((digest) => B25CHarness.startSettle('b', digest), pass.passDigestHex),
    ]);
    await Promise.all([
      pageA.waitForFunction(() => B25CHarness.entered('a')),
      pageB.waitForFunction(() => B25CHarness.entered('b')),
    ]);
    await Promise.all([
      pageA.evaluate(() => B25CHarness.release('a')),
      pageB.evaluate(() => B25CHarness.release('b')),
    ]);
    const outcomes = await Promise.all([
      pageA.evaluate(() => B25CHarness.result('a')),
      pageB.evaluate(() => B25CHarness.result('b')),
    ]);
    expect(outcomes.filter((item) => item.ok)).toHaveLength(1);
    expect(outcomes.filter((item) => !item.ok)).toEqual([
      expect.objectContaining({ code: 'B25C_CAS_CONFLICT' }),
    ]);
    expect((await pageA.evaluate(() => B25CHarness.read('a'))).head.epochDec).toBe('2');
    expectNoPageErrors(pageA, pageB);
  } finally { await cleanup(pages); }
});

test('two connections create exactly one durable probe reservation', async ({ browser, browserName }) => {
  const pages = await twoConnections(browser, `probe-${browserName}-${Date.now()}`);
  const { pageA, pageB } = pages;
  try {
    const outcomes = await Promise.all([
      pageA.evaluate(() => B25CHarness.probe('a')),
      pageB.evaluate(() => B25CHarness.probe('b')),
    ]);
    expect(outcomes.filter((item) => item.ok)).toHaveLength(1);
    expect(outcomes.filter((item) => !item.ok)).toEqual([
      expect.objectContaining({ code: 'B25C_PROBE_ALREADY_RESERVED' }),
    ]);
    expectNoPageErrors(pageA, pageB);
  } finally { await cleanup(pages); }
});
