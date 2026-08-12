import { test, expect } from '@playwright/test';

const HARNESS = 'http://127.0.0.1:18766/spikes/marmot-phase-b2-6/harness.html';
const PAGE_ERRORS = new WeakMap();

async function ready(page) {
  const errors = [];
  PAGE_ERRORS.set(page, errors);
  page.on('pageerror', (error) => errors.push(`${error.name}: ${error.message}`));
  await page.goto(HARNESS);
  await page.waitForFunction(() => globalThis.B26Harness !== undefined);
}

async function twoConnections(browser, tag) {
  const context = await browser.newContext();
  const pageA = await context.newPage();
  const pageB = await context.newPage();
  await Promise.all([ready(pageA), ready(pageB)]);
  await pageA.evaluate((value) => B26Harness.open('a', value), tag);
  await pageB.evaluate((value) => B26Harness.open('b', value), tag);
  await pageA.evaluate(() => B26Harness.initialize('a'));
  return { context, pageA, pageB };
}

async function cleanup({ context, pageA, pageB }) {
  await pageB.evaluate(() => B26Harness.close('b'));
  await pageA.evaluate(() => B26Harness.destroy('a'));
  await context.close();
}

function expectNoPageErrors(...pages) {
  for (const page of pages) expect(PAGE_ERRORS.get(page)).toEqual([]);
}

test('two connections CAS one complete settlement successor', async ({ browser, browserName }) => {
  const pages = await twoConnections(browser, `settle-${browserName}-${Date.now()}`);
  const { pageA, pageB } = pages;
  try {
    await pageA.evaluate(() => B26Harness.prepare('a'));
    const pass = await pageA.evaluate(() => B26Harness.freeze('a'));
    await Promise.all([
      pageA.evaluate(() => B26Harness.arm('a')),
      pageB.evaluate(() => B26Harness.arm('b')),
    ]);
    await Promise.all([
      pageA.evaluate((digest) => B26Harness.startSettle('a', digest), pass.passDigestHex),
      pageB.evaluate((digest) => B26Harness.startSettle('b', digest), pass.passDigestHex),
    ]);
    await Promise.all([
      pageA.waitForFunction(() => B26Harness.entered('a')),
      pageB.waitForFunction(() => B26Harness.entered('b')),
    ]);
    await Promise.all([
      pageA.evaluate(() => B26Harness.release('a')),
      pageB.evaluate(() => B26Harness.release('b')),
    ]);
    const outcomes = await Promise.all([
      pageA.evaluate(() => B26Harness.result('a')),
      pageB.evaluate(() => B26Harness.result('b')),
    ]);
    expect(outcomes.filter((item) => item.ok)).toHaveLength(1);
    expect(outcomes.filter((item) => !item.ok)).toEqual([
      expect.objectContaining({ code: 'B26_CAS_CONFLICT' }),
    ]);
    expect((await pageA.evaluate(() => B26Harness.read('a'))).head.epochDec).toBe('2');
    expectNoPageErrors(pageA, pageB);
  } finally { await cleanup(pages); }
});

test('two connections create exactly one durable probe reservation', async ({ browser, browserName }) => {
  const pages = await twoConnections(browser, `probe-${browserName}-${Date.now()}`);
  const { pageA, pageB } = pages;
  try {
    const outcomes = await Promise.all([
      pageA.evaluate(() => B26Harness.probe('a')),
      pageB.evaluate(() => B26Harness.probe('b')),
    ]);
    expect(outcomes.filter((item) => item.ok)).toHaveLength(1);
    expect(outcomes.filter((item) => !item.ok)).toEqual([
      expect.objectContaining({ code: 'B26_PROBE_ALREADY_RESERVED' }),
    ]);
    expectNoPageErrors(pageA, pageB);
  } finally { await cleanup(pages); }
});

test('two connections produce one durable message successor in 100 races',
  async ({ browser, browserName }) => {
    const pages = await twoConnections(browser, 'message-' + browserName + '-' + Date.now());
    const { pageA, pageB } = pages;
    try {
      for (let index = 0; index < 100; index += 1) {
        await Promise.all([
          pageA.evaluate(() => B26Harness.armMessage('a')),
          pageB.evaluate(() => B26Harness.armMessage('b')),
        ]);
        await Promise.all([
          pageA.evaluate((position) => B26Harness.startQueue(
            'a', 'race-a-' + position, 'payload-a-' + position), index),
          pageB.evaluate((position) => B26Harness.startQueue(
            'b', 'race-b-' + position, 'payload-b-' + position), index),
        ]);
        await Promise.all([
          pageA.waitForFunction(() => B26Harness.enteredMessage('a')),
          pageB.waitForFunction(() => B26Harness.enteredMessage('b')),
        ]);
        await Promise.all([
          pageA.evaluate(() => B26Harness.releaseMessage('a')),
          pageB.evaluate(() => B26Harness.releaseMessage('b')),
        ]);
        const outcomes = await Promise.all([
          pageA.evaluate(() => B26Harness.queueResult('a')),
          pageB.evaluate(() => B26Harness.queueResult('b')),
        ]);
        const winner = outcomes.find((item) => item.ok);
        expect(outcomes.filter((item) => item.ok)).toHaveLength(1);
        expect(outcomes.filter((item) => !item.ok)).toEqual([
          expect.objectContaining({ code: 'B26_CAS_CONFLICT' }),
        ]);
        await pageA.evaluate(({ instanceKeyHex, ordinal }) =>
          B26Harness.finishQueued('a', instanceKeyHex, ordinal), winner.value);
      }
      expectNoPageErrors(pageA, pageB);
    } finally { await cleanup(pages); }
  });
