import { test, expect } from '@playwright/test';

const HARNESS = 'http://127.0.0.1:18764/spikes/marmot-phase-b2-3/harness.html';
const RACE_COUNT = Number.parseInt(process.env.B23_RACES ?? '100', 10);
const PAGE_ERRORS = new WeakMap();

async function ready(page) {
  const errors = [];
  PAGE_ERRORS.set(page, errors);
  page.on('pageerror', (error) => errors.push(`${error.name}: ${error.message}`));
  await page.goto(HARNESS);
  await page.waitForFunction(() => globalThis.B23Harness !== undefined);
}

function expectNoPageErrors(...pages) {
  for (const page of pages) expect(PAGE_ERRORS.get(page)).toEqual([]);
}

test('100 two-connection CAS races have exactly one successor', async ({ browser, browserName }) => {
  const tag = `race-${browserName}-${Date.now()}`;
  const context = await browser.newContext();
  const pageA = await context.newPage();
  const pageB = await context.newPage();
  await Promise.all([ready(pageA), ready(pageB)]);
  await pageA.evaluate((value) => globalThis.B23Harness.open('a', value), tag);
  await pageB.evaluate((value) => globalThis.B23Harness.open('b', value), tag);
  await pageA.evaluate(() => globalThis.B23Harness.initialize('a'));
  try {
    for (let round = 0; round < RACE_COUNT; round += 1) {
      const [headA, headB] = await Promise.all([
        pageA.evaluate(() => globalThis.B23Harness.read('a').then((value) => value.head)),
        pageB.evaluate(() => globalThis.B23Harness.read('b').then((value) => value.head)),
      ]);
      expect(headA).toEqual(headB);
      const outcomes = await Promise.all([
        pageA.evaluate(({ head, byte }) => globalThis.B23Harness.advanceStable('a', head, byte)
          .then((value) => ({ ok: true, seq: value.head.seq }))
          .catch((error) => ({ ok: false, code: error.code })), { head: headA, byte: 0xa0 }),
        pageB.evaluate(({ head, byte }) => globalThis.B23Harness.advanceStable('b', head, byte)
          .then((value) => ({ ok: true, seq: value.head.seq }))
          .catch((error) => ({ ok: false, code: error.code })), { head: headB, byte: 0xb0 }),
      ]);
      expect(outcomes.filter((outcome) => outcome.ok)).toHaveLength(1);
      expect(outcomes.filter((outcome) => !outcome.ok)).toEqual([
        expect.objectContaining({ code: 'B23_CAS_CONFLICT' }),
      ]);
      const durable = await pageA.evaluate(() => globalThis.B23Harness.read('a').then((value) => value.head));
      expect(durable.seq).toBe(headA.seq + 1);
      expect(await pageA.evaluate(() => globalThis.B23Harness.snapshotKeys('a'))).toHaveLength(1);
    }
    expectNoPageErrors(pageA, pageB);
  } finally {
    await pageB.evaluate(() => globalThis.B23Harness.close('b'));
    await pageA.evaluate(() => globalThis.B23Harness.destroy('a'));
    await context.close();
  }
});

test('competing prepare and inbound-accept CAS choose one successor', async ({ browser, browserName }) => {
  const tag = `prepare-accept-${browserName}-${Date.now()}`;
  const context = await browser.newContext();
  const pageA = await context.newPage();
  const pageB = await context.newPage();
  await Promise.all([ready(pageA), ready(pageB)]);
  await pageA.evaluate((value) => globalThis.B23Harness.open('a', value), tag);
  await pageB.evaluate((value) => globalThis.B23Harness.open('b', value), tag);
  await pageA.evaluate(() => globalThis.B23Harness.initialize('a'));
  try {
    const [headA, headB] = await Promise.all([
      pageA.evaluate(() => globalThis.B23Harness.read('a').then((value) => value.head)),
      pageB.evaluate(() => globalThis.B23Harness.read('b').then((value) => value.head)),
    ]);
    const outcomes = await Promise.all([
      pageA.evaluate((head) => globalThis.B23Harness.prepare('a', head)
        .then((value) => ({ ok: true, state: value.head.state }))
        .catch((error) => ({ ok: false, code: error.code })), headA),
      pageB.evaluate((head) => globalThis.B23Harness.acceptInbound('b', head)
        .then((value) => ({ ok: true, state: value.head.state }))
        .catch((error) => ({ ok: false, code: error.code })), headB),
    ]);
    expect(outcomes.filter((outcome) => outcome.ok)).toHaveLength(1);
    expect(outcomes.filter((outcome) => !outcome.ok)).toEqual([
      expect.objectContaining({ code: 'B23_CAS_CONFLICT' }),
    ]);
    const durable = await pageA.evaluate(() => globalThis.B23Harness.read('a'));
    expect(durable.head.seq).toBe(2);
    expect(['PREPARED', 'STABLE']).toContain(durable.head.state);
    expect(await pageA.evaluate(() => globalThis.B23Harness.snapshotKeys('a'))).toHaveLength(1);
    expectNoPageErrors(pageA, pageB);
  } finally {
    await pageB.evaluate(() => globalThis.B23Harness.close('b'));
    await pageA.evaluate(() => globalThis.B23Harness.destroy('a'));
    await context.close();
  }
});

test('reload recovers only committed prepare and publication-intent heads', async ({ page, browserName }) => {
  const tag = `reload-${browserName}-${Date.now()}`;
  await ready(page);
  await page.evaluate((value) => B23Harness.open('owner', value), tag);
  const initial = await page.evaluate(() => B23Harness.initialize('owner'));
  const prepared = await page.evaluate((head) => B23Harness.prepare('owner', head), initial);
  expect(prepared.head.state).toBe('PREPARED');
  expect(prepared.head.publishAttempts).toBe(0);

  await page.reload();
  await page.waitForFunction(() => globalThis.B23Harness !== undefined);
  await page.evaluate((value) => B23Harness.open('owner', value), tag);
  const recoveredPrepared = await page.evaluate(() => B23Harness.read('owner'));
  expect(recoveredPrepared.head).toEqual(prepared.head);

  const attempted = await page.evaluate(() => B23Harness.publishIntent('owner'));
  expect(attempted.head.publishAttempts).toBe(1);
  expect(attempted.transition.artifactBytes).toEqual(Uint8Array.of(1, 2, 3, 4));
  await page.reload();
  await page.waitForFunction(() => globalThis.B23Harness !== undefined);
  await page.evaluate((value) => B23Harness.open('owner', value), tag);
  const recoveredAttempt = await page.evaluate(() => B23Harness.read('owner'));
  expect(recoveredAttempt.head).toEqual(attempted.head);
  expect(recoveredAttempt.transition.artifactBytes).toEqual(Uint8Array.of(1, 2, 3, 4));

  const abort = await page.evaluate(() => B23Harness.abortProbe('owner'));
  expect(abort.after).toEqual(abort.before);
  expectNoPageErrors(page);
  await page.evaluate(() => B23Harness.destroy('owner'));
});
