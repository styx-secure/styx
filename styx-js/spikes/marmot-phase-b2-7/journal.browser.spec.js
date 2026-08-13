import { test, expect } from '@playwright/test';

const HARNESS = 'http://127.0.0.1:18766/spikes/marmot-phase-b2-7/harness.html';
const PAGE_ERRORS = new WeakMap();

async function ready(page) {
  const errors = [];
  PAGE_ERRORS.set(page, errors);
  page.on('pageerror', (error) => errors.push(`${error.name}: ${error.message}`));
  await page.goto(HARNESS);
  await page.waitForFunction(() => globalThis.B27Harness !== undefined);
}

async function twoConnections(browser, tag) {
  const context = await browser.newContext();
  const pageA = await context.newPage();
  const pageB = await context.newPage();
  await Promise.all([ready(pageA), ready(pageB)]);
  await pageA.evaluate((value) => B27Harness.open('a', value), tag);
  await pageB.evaluate((value) => B27Harness.open('b', value), tag);
  await pageA.evaluate(() => B27Harness.initialize('a'));
  return { context, pageA, pageB };
}

async function cleanup({ context, pageA, pageB }) {
  await pageB.evaluate(() => B27Harness.close('b'));
  await pageA.evaluate(() => B27Harness.destroy('a'));
  await context.close();
}

function expectNoPageErrors(...pages) {
  for (const page of pages) expect(PAGE_ERRORS.get(page)).toEqual([]);
}

test('two connections CAS one complete settlement successor', async ({ browser, browserName }) => {
  const pages = await twoConnections(browser, `settle-${browserName}-${Date.now()}`);
  const { pageA, pageB } = pages;
  try {
    await pageA.evaluate(() => B27Harness.prepare('a'));
    const pass = await pageA.evaluate(() => B27Harness.freeze('a'));
    await Promise.all([
      pageA.evaluate(() => B27Harness.arm('a')),
      pageB.evaluate(() => B27Harness.arm('b')),
    ]);
    await Promise.all([
      pageA.evaluate((digest) => B27Harness.startSettle('a', digest), pass.passDigestHex),
      pageB.evaluate((digest) => B27Harness.startSettle('b', digest), pass.passDigestHex),
    ]);
    await Promise.all([
      pageA.waitForFunction(() => B27Harness.entered('a')),
      pageB.waitForFunction(() => B27Harness.entered('b')),
    ]);
    await Promise.all([
      pageA.evaluate(() => B27Harness.release('a')),
      pageB.evaluate(() => B27Harness.release('b')),
    ]);
    const outcomes = await Promise.all([
      pageA.evaluate(() => B27Harness.result('a')),
      pageB.evaluate(() => B27Harness.result('b')),
    ]);
    expect(outcomes.filter((item) => item.ok)).toHaveLength(1);
    expect(outcomes.filter((item) => !item.ok)).toEqual([
      expect.objectContaining({ code: 'B27_CAS_CONFLICT' }),
    ]);
    expect((await pageA.evaluate(() => B27Harness.read('a'))).head.epochDec).toBe('2');
    expectNoPageErrors(pageA, pageB);
  } finally { await cleanup(pages); }
});

test('two connections CAS one branch-changing anchor and preserve its exact Commit binding',
  async ({ browser, browserName }) => {
    const pages = await twoConnections(browser, `branch-${browserName}-${Date.now()}`);
    const { pageA, pageB } = pages;
    try {
      const cDigests = await pageA.evaluate(() => B27Harness.prepareBranch('a', 'c', 7));
      await pageA.evaluate(() => B27Harness.prepareBranch('a', 'd', 2));
      await pageA.evaluate(() => B27Harness.settleBranch('a', 'd', [1, 0]));
      await pageA.evaluate(() => B27Harness.settleBranch('a', 'c', [0]));
      await pageA.evaluate(() => B27Harness.admitBranch('a', 'c', [5, 4, 3, 2, 1]));
      const pass = await pageA.evaluate(() => B27Harness.freeze('a'));
      await Promise.all([
        pageA.evaluate(() => B27Harness.arm('a')),
        pageB.evaluate(() => B27Harness.arm('b')),
      ]);
      await Promise.all([
        pageA.evaluate((digest) => B27Harness.startSettle('a', digest), pass.passDigestHex),
        pageB.evaluate((digest) => B27Harness.startSettle('b', digest), pass.passDigestHex),
      ]);
      await Promise.all([
        pageA.waitForFunction(() => B27Harness.entered('a')),
        pageB.waitForFunction(() => B27Harness.entered('b')),
      ]);
      await Promise.all([
        pageA.evaluate(() => B27Harness.release('a')),
        pageB.evaluate(() => B27Harness.release('b')),
      ]);
      const outcomes = await Promise.all([
        pageA.evaluate(() => B27Harness.result('a')),
        pageB.evaluate(() => B27Harness.result('b')),
      ]);
      expect(outcomes.filter((item) => item.ok)).toHaveLength(1);
      expect(outcomes.filter((item) => !item.ok)).toEqual([
        expect.objectContaining({ code: 'B27_CAS_CONFLICT' }),
      ]);
      const [headA, headB] = await Promise.all([
        pageA.evaluate(() => B27Harness.read('a')),
        pageB.evaluate(() => B27Harness.read('b')),
      ]);
      expect(headA.head.headDigestHex).toBe(headB.head.headDigestHex);
      expect(headA.head).toEqual(expect.objectContaining({
        epochDec: '7',
        anchorTipCommitDigestHex: cDigests[0],
      }));
      expectNoPageErrors(pageA, pageB);
    } finally { await cleanup(pages); }
  });

test('two connections create exactly one durable probe reservation', async ({ browser, browserName }) => {
  const pages = await twoConnections(browser, `probe-${browserName}-${Date.now()}`);
  const { pageA, pageB } = pages;
  try {
    const outcomes = await Promise.all([
      pageA.evaluate(() => B27Harness.probe('a')),
      pageB.evaluate(() => B27Harness.probe('b')),
    ]);
    expect(outcomes.filter((item) => item.ok)).toHaveLength(1);
    expect(outcomes.filter((item) => !item.ok)).toEqual([
      expect.objectContaining({ code: 'B27_PROBE_ALREADY_RESERVED' }),
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
          pageA.evaluate(() => B27Harness.armMessage('a')),
          pageB.evaluate(() => B27Harness.armMessage('b')),
        ]);
        await Promise.all([
          pageA.evaluate((position) => B27Harness.startQueue(
            'a', 'race-a-' + position, 'payload-a-' + position), index),
          pageB.evaluate((position) => B27Harness.startQueue(
            'b', 'race-b-' + position, 'payload-b-' + position), index),
        ]);
        await Promise.all([
          pageA.waitForFunction(() => B27Harness.enteredMessage('a')),
          pageB.waitForFunction(() => B27Harness.enteredMessage('b')),
        ]);
        await Promise.all([
          pageA.evaluate(() => B27Harness.releaseMessage('a')),
          pageB.evaluate(() => B27Harness.releaseMessage('b')),
        ]);
        const outcomes = await Promise.all([
          pageA.evaluate(() => B27Harness.queueResult('a')),
          pageB.evaluate(() => B27Harness.queueResult('b')),
        ]);
        const winner = outcomes.find((item) => item.ok);
        expect(outcomes.filter((item) => item.ok)).toHaveLength(1);
        expect(outcomes.filter((item) => !item.ok)).toEqual([
          expect.objectContaining({ code: 'B27_CAS_CONFLICT' }),
        ]);
        await pageA.evaluate(({ instanceKeyHex, ordinal }) =>
          B27Harness.finishQueued('a', instanceKeyHex, ordinal), winner.value);
      }
      expectNoPageErrors(pageA, pageB);
    } finally { await cleanup(pages); }
  });

test('two connections produce one durable attributed inbound winner in 100 races',
  async ({ browser, browserName }) => {
    const pages = await twoConnections(
      browser, 'inbound-attribution-' + browserName + '-' + Date.now());
    const { pageA, pageB } = pages;
    try {
      for (let index = 0; index < 100; index += 1) {
        const generated = await pageA.evaluate((position) =>
          B27Harness.createInbound('a', 'attributed-payload-' + position), index);
        await Promise.all([
          pageA.evaluate(() => B27Harness.armMessage('a')),
          pageB.evaluate(() => B27Harness.armMessage('b')),
        ]);
        await Promise.all([
          pageA.evaluate((ciphertext) =>
            B27Harness.startReceive('a', ciphertext), generated.ciphertext),
          pageB.evaluate((ciphertext) =>
            B27Harness.startReceive('b', ciphertext), generated.ciphertext),
        ]);
        await Promise.all([
          pageA.waitForFunction(() => B27Harness.enteredMessage('a')),
          pageB.waitForFunction(() => B27Harness.enteredMessage('b')),
        ]);
        await Promise.all([
          pageA.evaluate(() => B27Harness.releaseMessage('a')),
          pageB.evaluate(() => B27Harness.releaseMessage('b')),
        ]);
        const outcomes = await Promise.all([
          pageA.evaluate(() => B27Harness.receiveResult('a')),
          pageB.evaluate(() => B27Harness.receiveResult('b')),
        ]);
        const winners = outcomes.filter((item) => item.ok);
        const losers = outcomes.filter((item) => !item.ok);
        expect(winners).toHaveLength(1);
        expect(winners[0].value).toEqual(expect.objectContaining({
          status: 'accepted',
          ...generated.expected,
          epochDec: expect.stringMatching(/^\d+$/),
          groupContextDigestHex: expect.stringMatching(/^[0-9a-f]{64}$/),
          verifiedLeafDigestHex: expect.stringMatching(/^[0-9a-f]{64}$/),
        }));
        expect(losers).toEqual([expect.objectContaining({
          code: 'B27_CAS_CONFLICT',
        })]);
        expect(losers[0]).not.toHaveProperty('value');
        expect(losers[0]).not.toHaveProperty('plaintextBytes');
        expect(losers[0]).not.toHaveProperty('senderIdentityHex');
      }
      expectNoPageErrors(pageA, pageB);
    } finally { await cleanup(pages); }
  });

test('message commit and settlement serialize without selection starvation',
  async ({ browser, browserName }) => {
    const pages = await twoConnections(browser, 'send-settle-' + browserName + '-' + Date.now());
    const { pageA, pageB } = pages;
    try {
      await pageA.evaluate(() => B27Harness.prepare('a'));
      const pass = await pageA.evaluate(() => B27Harness.freeze('a'));
      await pageA.evaluate(() => B27Harness.arm('a'));
      await pageA.evaluate((digest) =>
        B27Harness.startSettle('a', digest), pass.passDigestHex);
      await pageA.waitForFunction(() => B27Harness.entered('a'));
      const queued = await pageB.evaluate(() =>
        B27Harness.queue('b', 'before-settlement', 'durable-before-settlement'));
      expect(queued.ok).toBe(true);
      await pageA.evaluate(() => B27Harness.release('a'));
      expect(await pageA.evaluate(() => B27Harness.result('a')))
        .toEqual(expect.objectContaining({ ok: true }));
      const outbox = await pageB.evaluate(({ instanceKeyHex, ordinal }) =>
        B27Harness.queueState('b', instanceKeyHex, ordinal), queued.value);
      expect(outbox.state).toBe('DURABLE');
      expect((await pageA.evaluate(() => B27Harness.read('a'))).head.epochDec).toBe('2');
      expectNoPageErrors(pageA, pageB);
    } finally { await cleanup(pages); }
  });
