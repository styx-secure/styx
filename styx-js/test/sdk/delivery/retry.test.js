/**
 * I-RETRY -- tests of the retransmission backoff schedule of C-DLV section 4.3.
 *
 * Every value the module consumes is injected here: the clock is an object
 * with `now()` and the randomness an object with `nextUint32()`, both of
 * C-SDK section 8.4. The property tests are generative: they run the schedule
 * over every attempt number C-DLV section 3 admits (1..9) and over a large,
 * deterministic set of draws, and they re-derive the closed ranges of section
 * 4.3 from the ratified formula rather than restating them. A second property
 * walks the deadline branch itself, placing the injected clock reading one
 * millisecond either side of the exact stop condition.
 *
 * Three timelines of the O-SCEN3 scenario set carry a `retryDelay` timing,
 * that is, they exercise the `delay(n, u)` schedule or the retry-or-fail
 * decision of section 4.3: `hungRelay` (`twoHungRelaysExhaustion`), `relayLoss`
 * (`relayLossAndReplacement`) and `duplicateAndReordered`
 * (`outboundDuplicateAccepted`). One test per cited timeline replays the draws,
 * the clock readings and the expected delays those records state.
 *
 * No new dependency: this file imports the module under test, the test runner
 * and nothing else. The draw stream is a small deterministic generator kept
 * in the file, so "fixed seed" means exactly that.
 */
import { describe, expect, test } from '@jest/globals';

import * as retryModule from '../../../src/sdk/delivery/retry.js';
import {
  BACKOFF_BASE_MS,
  BACKOFF_CAP_MS,
  backoffBaseMs,
  planRetry,
  retryDelayMs,
} from '../../../src/sdk/delivery/retry.js';

/** The attempt numbers 1..9, which are the ones section 4.3 gives a delay; `maxAttempts` runs 1..10. */
const ATTEMPTS = [1, 2, 3, 4, 5, 6, 7, 8, 9];

/** The draw range of C-SDK section 8.4. */
const DRAW_RANGE = 2 ** 32;

/** A small deterministic generator (Mulberry32); same seed, same stream. */
function seededDraws(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return (t ^ (t >>> 14)) >>> 0;
  };
}

/** A clock port of C-SDK section 8.4 over a fixed reading. */
function clockAt(reading) {
  return { now: () => reading };
}

/** A random port of C-SDK section 8.4 over a queue of draws, counting its calls. */
function randomOf(draws) {
  const queue = [...draws];
  const port = {
    calls: 0,
    nextUint32: () => {
      port.calls += 1;
      if (queue.length === 0) {
        throw new Error('no draw left in this test');
      }
      return queue.shift();
    },
    remaining: () => queue.length,
  };
  return port;
}

/**
 * The ratified formula of C-DLV section 4.3, recomputed independently of the
 * module: an exact integer oracle in BigInt, so no float rounding of the
 * module and of the oracle can agree by accident.
 */
function ratified(n, u) {
  const base = BigInt(Math.min(BACKOFF_BASE_MS * 2 ** (n - 1), BACKOFF_CAP_MS));
  return Number(base / 2n + (BigInt(u) * base) / 2n ** 33n);
}

/** A deterministic, wide sample of draws: the boundaries and 4 096 more. */
function drawSample() {
  const next = seededDraws(0x5e7c13d9);
  const draws = [0, 1, 2, 2 ** 31 - 1, 2 ** 31, 2 ** 31 + 1, DRAW_RANGE - 2, DRAW_RANGE - 1];
  for (let i = 0; i < 4096; i += 1) {
    draws.push(next());
  }
  return draws;
}

const DRAWS = drawSample();

describe('C-DLV section 4.3 -- base, delay and the closed ranges', () => {
  test('the module exports exactly the five names the contract fixes', () => {
    expect(Object.keys(retryModule).sort()).toStrictEqual([
      'BACKOFF_BASE_MS',
      'BACKOFF_CAP_MS',
      'backoffBaseMs',
      'planRetry',
      'retryDelayMs',
    ]);
  });

  test('the fixed values of section 3 are 1 000 ms and 30 000 ms', () => {
    expect(BACKOFF_BASE_MS).toBe(1000);
    expect(BACKOFF_CAP_MS).toBe(30000);
  });

  test('base(n) is min(1000 * 2^(n-1), 30000) and never exceeds the cap', () => {
    const expected = [1000, 2000, 4000, 8000, 16000, 30000, 30000, 30000, 30000];
    ATTEMPTS.forEach((n, index) => {
      expect(backoffBaseMs(n)).toBe(expected[index]);
    });
  });

  test('base(n) is non-decreasing on 1..9 (the only monotonicity section 4.3 states)', () => {
    for (let n = 1; n < ATTEMPTS.length; n += 1) {
      expect(backoffBaseMs(n + 1)).toBeGreaterThanOrEqual(backoffBaseMs(n));
    }
  });

  test('delay(n, u) equals the ratified formula, recomputed with a BigInt oracle, for every sampled draw', () => {
    for (const n of ATTEMPTS) {
      for (const u of DRAWS) {
        expect(retryDelayMs(n, u)).toBe(ratified(n, u));
      }
    }
  });

  test('the exact values at u = 0 and u = 2^32 - 1 for every n of 1..9', () => {
    // C-DLV section 13 requires exactly these two boundaries at every n.
    const atZero = [500, 1000, 2000, 4000, 8000, 15000, 15000, 15000, 15000];
    const atLast = [999, 1999, 3999, 7999, 15999, 29999, 29999, 29999, 29999];
    ATTEMPTS.forEach((n, index) => {
      expect(retryDelayMs(n, 0)).toBe(atZero[index]);
      expect(retryDelayMs(n, DRAW_RANGE - 1)).toBe(atLast[index]);
    });
  });

  test('every delay lies in [base(n)/2, base(n)) -- the closed range of section 4.3', () => {
    for (const n of ATTEMPTS) {
      const base = backoffBaseMs(n);
      for (const u of DRAWS) {
        const delay = retryDelayMs(n, u);
        expect(delay).toBeGreaterThanOrEqual(base / 2);
        expect(delay).toBeLessThan(base);
        expect(Number.isInteger(delay)).toBe(true);
      }
    }
  });

  test('delay(n, u) is non-decreasing in u, and its range is exactly base(n)/2 .. base(n)-1', () => {
    for (const n of ATTEMPTS) {
      const base = backoffBaseMs(n);
      const sorted = [...DRAWS].sort((a, b) => a - b);
      let previous = -1;
      for (const u of sorted) {
        const delay = retryDelayMs(n, u);
        expect(delay).toBeGreaterThanOrEqual(previous);
        previous = delay;
      }
      expect(retryDelayMs(n, 0)).toBe(base / 2);
      expect(retryDelayMs(n, DRAW_RANGE - 1)).toBe(base - 1);
    }
  });

  test('the ranges of section 4.3 by attempt: 500-999, 1 000-1 999, 2 000-3 999, 4 000-7 999, 8 000-15 999, then 15 000-29 999', () => {
    const ranges = [
      [500, 999],
      [1000, 1999],
      [2000, 3999],
      [4000, 7999],
      [8000, 15999],
      [15000, 29999],
      [15000, 29999],
      [15000, 29999],
      [15000, 29999],
    ];
    ATTEMPTS.forEach((n, index) => {
      const [low, high] = ranges[index];
      expect(retryDelayMs(n, 0)).toBe(low);
      expect(retryDelayMs(n, DRAW_RANGE - 1)).toBe(high);
      for (const u of DRAWS) {
        const delay = retryDelayMs(n, u);
        expect(delay).toBeGreaterThanOrEqual(low);
        expect(delay).toBeLessThanOrEqual(high);
      }
    });
  });

  test('an attempt number or a draw outside the domain is a misuse and throws', () => {
    expect(() => backoffBaseMs(0)).toThrow(TypeError);
    expect(() => backoffBaseMs(1.5)).toThrow(TypeError);
    expect(() => retryDelayMs(1, -1)).toThrow(TypeError);
    expect(() => retryDelayMs(1, DRAW_RANGE)).toThrow(TypeError);
    expect(() => retryDelayMs(1, 1.5)).toThrow(TypeError);
    expect(() => retryDelayMs(1, Number.NaN)).toThrow(TypeError);
  });
});

describe('C-DLV section 4.3 -- the retry-or-fail decision', () => {
  test('exhaustion: attempts = maxAttempts fails with lastCode null and calls no random port', () => {
    for (let maxAttempts = 1; maxAttempts <= 10; maxAttempts += 1) {
      const random = randomOf([DRAW_RANGE - 1, 0, 1]);
      const decision = planRetry({
        attempts: maxAttempts,
        maxAttempts,
        clock: clockAt(0),
        deadlineAt: 10 ** 15,
        random,
      });
      expect(decision).toStrictEqual({ action: 'FAIL', lastCode: null });
      expect(random.calls).toBe(0);
      expect(random.remaining()).toBe(3);
      expect(Object.isFrozen(decision)).toBe(true);
    }
  });

  test('a retry below the deadline returns the delay and draws exactly once', () => {
    const random = randomOf([DRAW_RANGE - 1, 0]);
    const decision = planRetry({
      attempts: 1,
      maxAttempts: 5,
      clock: clockAt(24000),
      deadlineAt: 132000,
      random,
    });
    expect(decision).toStrictEqual({ action: 'RETRY', delayMs: 999 });
    expect(random.calls).toBe(1);
    expect(random.remaining()).toBe(1);
    expect(Object.isFrozen(decision)).toBe(true);
  });

  test('the stop condition is exact: a retry is refused at or past the deadline, and armed strictly before it', () => {
    // delay(1, 2^32-1) = 999, so now + 999 >= deadlineAt is the boundary.
    const deadlineAt = 132000;
    for (const now of [deadlineAt - 1000, deadlineAt - 999, deadlineAt - 998, deadlineAt, deadlineAt + 1]) {
      const decision = planRetry({
        attempts: 1,
        maxAttempts: 5,
        clock: clockAt(now),
        deadlineAt,
        random: randomOf([DRAW_RANGE - 1]),
      });
      const expected = now + 999 >= deadlineAt
        ? { action: 'FAIL', lastCode: null }
        : { action: 'RETRY', delayMs: 999 };
      expect(decision).toStrictEqual(expected);
    }
    // The same boundary read through the smallest delay of the schedule.
    expect(planRetry({
      attempts: 1,
      maxAttempts: 2,
      clock: clockAt(deadlineAt - 500),
      deadlineAt,
      random: randomOf([0]),
    })).toStrictEqual({ action: 'FAIL', lastCode: null });
    expect(planRetry({
      attempts: 1,
      maxAttempts: 2,
      clock: clockAt(deadlineAt - 501),
      deadlineAt,
      random: randomOf([0]),
    })).toStrictEqual({ action: 'RETRY', delayMs: 500 });
  });

  test('the deadline branch itself: RETRY exactly when now + delay < deadlineAt, for every attempt and many seeds', () => {
    const next = seededDraws(0x1f2e3d4c);
    for (const attempts of ATTEMPTS) {
      for (let i = 0; i < 256; i += 1) {
        const u = next();
        const delayMs = retryDelayMs(attempts, u);
        for (const fractional of [0, 0.5]) {
          const deadlineAt = 24000 + delayMs + fractional;
          for (const delta of [-1, 0, 1]) {
            const now = deadlineAt - delayMs + delta;
            const decision = planRetry({
              attempts,
              maxAttempts: 10,
              clock: clockAt(now),
              deadlineAt,
              random: randomOf([u]),
            });
            expect(decision).toStrictEqual(now + delayMs >= deadlineAt
              ? { action: 'FAIL', lastCode: null }
              : { action: 'RETRY', delayMs });
          }
        }
      }
    }
  });

  test('every decision of a full run is one of the three ratified results, over many seeds', () => {
    for (let seed = 1; seed <= 64; seed += 1) {
      const next = seededDraws(seed);
      let now = 12000;
      const deadlineAt = 132000;
      for (let attempts = 1; attempts <= 5; attempts += 1) {
        const decision = planRetry({
          attempts,
          maxAttempts: 5,
          clock: clockAt(now),
          deadlineAt,
          random: { nextUint32: next },
        });
        if (attempts === 5) {
          expect(decision).toStrictEqual({ action: 'FAIL', lastCode: null });
        } else if (decision.action === 'RETRY') {
          expect(Number.isInteger(decision.delayMs)).toBe(true);
          expect(decision.delayMs).toBeGreaterThanOrEqual(500);
          expect(decision.delayMs).toBeLessThan(30000);
          now += decision.delayMs;
        } else {
          expect(decision).toStrictEqual({ action: 'FAIL', lastCode: null });
        }
      }
    }
  });

  test('deterministic under a fixed seed: the same seed yields the same decisions', () => {
    const run = (seed) => {
      const next = seededDraws(seed);
      const decisions = [];
      let now = 12000;
      for (let attempts = 1; attempts <= 4; attempts += 1) {
        const decision = planRetry({
          attempts,
          maxAttempts: 5,
          clock: clockAt(now),
          deadlineAt: 132000,
          random: { nextUint32: next },
        });
        decisions.push(decision);
        if (decision.action === 'RETRY') {
          now += decision.delayMs;
        }
      }
      return decisions;
    };
    expect(run(20261003)).toStrictEqual(run(20261003));
    expect(run(20261003)).not.toStrictEqual(run(20261004));
  });

  test('an invalid random value is E_SDK_INTERNAL, in every invalid shape', () => {
    const invalid = [-1, 1.5, DRAW_RANGE, DRAW_RANGE + 1, Number.NaN, Infinity, '0', null, undefined];
    for (const value of invalid) {
      const decision = planRetry({
        attempts: 1,
        maxAttempts: 5,
        clock: clockAt(12000),
        deadlineAt: 132000,
        random: { nextUint32: () => value },
      });
      expect(decision).toStrictEqual({ action: 'FAIL', lastCode: 'E_SDK_INTERNAL' });
    }
  });

  test('a random port that throws is E_SDK_INTERNAL', () => {
    const decision = planRetry({
      attempts: 1,
      maxAttempts: 5,
      clock: clockAt(12000),
      deadlineAt: 132000,
      random: { nextUint32: () => { throw new Error('random fault'); } },
    });
    expect(decision).toStrictEqual({ action: 'FAIL', lastCode: 'E_SDK_INTERNAL' });
  });

  test('an invalid clock value is E_SDK_INTERNAL, in every invalid shape', () => {
    // C-SDK section 8.4: `now()` is a finite number of milliseconds, so a
    // value that is not a finite number is invalid. A Promise (an async port),
    // a string, null and undefined are invalid for the same reason.
    const invalid = [
      Number.NaN,
      Infinity,
      -Infinity,
      '12000',
      null,
      undefined,
      Promise.resolve(12000),
      () => 12000,
    ];
    for (const value of invalid) {
      const decision = planRetry({
        attempts: 1,
        maxAttempts: 5,
        clock: clockAt(value),
        deadlineAt: 132000,
        random: randomOf([DRAW_RANGE - 1]),
      });
      expect(decision).toStrictEqual({ action: 'FAIL', lastCode: 'E_SDK_INTERNAL' });
    }
  });

  test('a finite clock reading is valid even when it is negative or not an integer (C-DLV section 6.1: the domain is not narrowed)', () => {
    for (const now of [-1, 1.5, 0, 2 ** 53, 1e15]) {
      const decision = planRetry({
        attempts: 1,
        maxAttempts: 5,
        clock: clockAt(now),
        deadlineAt: 1e16,
        random: randomOf([DRAW_RANGE - 1]),
      });
      expect(decision).toStrictEqual({ action: 'RETRY', delayMs: 999 });
    }
    // And a negative reading can still be at or past a negative deadline.
    expect(planRetry({
      attempts: 1,
      maxAttempts: 5,
      clock: clockAt(-1),
      deadlineAt: 500,
      random: randomOf([0]),
    })).toStrictEqual({ action: 'RETRY', delayMs: 500 });
    expect(planRetry({
      attempts: 1,
      maxAttempts: 5,
      clock: clockAt(-1),
      deadlineAt: 499,
      random: randomOf([0]),
    })).toStrictEqual({ action: 'FAIL', lastCode: null });
  });

  test('a finite fractional deadline is lawful (C-SDK section 6.2), and the exhaustion branch still wins', () => {
    expect(planRetry({
      attempts: 1,
      maxAttempts: 5,
      clock: clockAt(12000.5),
      deadlineAt: 132000.5,
      random: randomOf([DRAW_RANGE - 1]),
    })).toStrictEqual({ action: 'RETRY', delayMs: 999 });
    expect(planRetry({
      attempts: 5,
      maxAttempts: 5,
      clock: clockAt(12000.5),
      deadlineAt: 132000.5,
      random: randomOf([]),
    })).toStrictEqual({ action: 'FAIL', lastCode: null });
  });

  test('a clock port that throws is E_SDK_INTERNAL', () => {
    const decision = planRetry({
      attempts: 1,
      maxAttempts: 5,
      clock: { now: () => { throw new Error('clock fault'); } },
      deadlineAt: 132000,
      random: randomOf([DRAW_RANGE - 1]),
    });
    expect(decision).toStrictEqual({ action: 'FAIL', lastCode: 'E_SDK_INTERNAL' });
  });

  test('a throwing getter on an injected port is E_SDK_INTERNAL, never a thrown value for the caller', () => {
    // C-SDK section 8.4: a clock or random function that throws is
    // E_SDK_INTERNAL for the affected operation (C-DLV section 4.5). A getter
    // that throws when the method is *read* is the same port fault, because
    // the read sits inside the same guarded path as the call. This is the
    // regression for the round-2 MEDIUM: the read used to happen while the
    // port shape was validated, before exhaustion, and the throw escaped.
    const hostileClock = {};
    Object.defineProperty(hostileClock, 'now', {
      get() { throw new Error('boom'); },
    });
    const hostileRandom = {};
    Object.defineProperty(hostileRandom, 'nextUint32', {
      get() { throw new Error('boom'); },
    });
    expect(planRetry({
      attempts: 1,
      maxAttempts: 5,
      clock: hostileClock,
      deadlineAt: 132000,
      random: randomOf([DRAW_RANGE - 1]),
    })).toStrictEqual({ action: 'FAIL', lastCode: 'E_SDK_INTERNAL' });
    expect(planRetry({
      attempts: 1,
      maxAttempts: 5,
      clock: clockAt(12000),
      deadlineAt: 132000,
      random: hostileRandom,
    })).toStrictEqual({ action: 'FAIL', lastCode: 'E_SDK_INTERNAL' });
  });

  test('an absent port, or a port whose method is not a function, is E_SDK_INTERNAL', () => {
    const base = { attempts: 1, maxAttempts: 5, deadlineAt: 132000 };
    for (const clock of [undefined, null, {}, { now: null }, { now: 42 }, { now: 'now' }, 0, 'clock']) {
      expect(planRetry({ ...base, clock, random: randomOf([DRAW_RANGE - 1]) }))
        .toStrictEqual({ action: 'FAIL', lastCode: 'E_SDK_INTERNAL' });
    }
    for (const random of [undefined, null, {}, { nextUint32: null }, { nextUint32: 0 }, { nextUint32: 'draw' }, 0]) {
      expect(planRetry({ ...base, clock: clockAt(12000), random }))
        .toStrictEqual({ action: 'FAIL', lastCode: 'E_SDK_INTERNAL' });
    }
  });

  test('an exhausted item fails with lastCode null without reading any port, present or absent', () => {
    // C-DLV section 4.3: `attempts = maxAttempts` fails the item at once,
    // without drawing a random value. No port is read on that path, so the
    // ports' shape cannot change the outcome and cannot raise: this is the
    // second half of the round-2 MEDIUM, which used to throw a `TypeError`.
    const hostileClock = {};
    Object.defineProperty(hostileClock, 'now', {
      get() { throw new Error('clock read'); },
    });
    const hostileRandom = {};
    Object.defineProperty(hostileRandom, 'nextUint32', {
      get() { throw new Error('random read'); },
    });
    const portVariants = [
      { clock: undefined, random: undefined },
      { clock: null, random: null },
      { clock: { now: 42 }, random: { nextUint32: 0 } },
      { clock: hostileClock, random: hostileRandom },
    ];
    for (let maxAttempts = 1; maxAttempts <= 10; maxAttempts += 1) {
      for (const ports of portVariants) {
        const decision = planRetry({
          attempts: maxAttempts,
          maxAttempts,
          clock: ports.clock,
          deadlineAt: 132000,
          random: ports.random,
        });
        expect(decision).toStrictEqual({ action: 'FAIL', lastCode: null });
        expect(Object.isFrozen(decision)).toBe(true);
      }
    }
    // Exhaustion also wins over a non-finite deadline and over absent ports.
    expect(planRetry({
      attempts: 5,
      maxAttempts: 5,
      clock: undefined,
      deadlineAt: Number.NaN,
      random: undefined,
    })).toStrictEqual({ action: 'FAIL', lastCode: null });
  });

  test('a non-integer, a zero or an over-max attempt count, or a non-finite deadline, is a misuse and throws', () => {
    const base = { maxAttempts: 5, clock: clockAt(12000), deadlineAt: 132000, random: randomOf([]) };
    expect(() => planRetry({ ...base, attempts: 0 })).toThrow(TypeError);
    expect(() => planRetry({ ...base, attempts: 1.5 })).toThrow(TypeError);
    expect(() => planRetry({ ...base, attempts: 6 })).toThrow(TypeError);
    expect(() => planRetry({ ...base, attempts: 1, maxAttempts: 0 })).toThrow(TypeError);
    // The deadline misuse is reached only where section 4.3 first uses the
    // deadline, so these cases carry a fresh valid draw and a valid clock.
    const live = () => ({ attempts: 1, maxAttempts: 5, clock: clockAt(12000), random: randomOf([DRAW_RANGE - 1]) });
    expect(() => planRetry({ ...live(), deadlineAt: Number.NaN })).toThrow(TypeError);
    expect(() => planRetry({ ...live(), deadlineAt: Infinity })).toThrow(TypeError);
    expect(() => planRetry({ ...live(), deadlineAt: '132000' })).toThrow(TypeError);
    // An exhausted item never reads the clock or the deadline.
    expect(() => planRetry({ ...base, attempts: 5, deadlineAt: Number.NaN })).not.toThrow();
  });
});

describe('O-SCEN3 cited timelines -- the draws and delays of the records', () => {
  test('hungRelay / twoHungRelaysExhaustion: delays 999, 1500, 3999, 4000 then exhaustion at maxAttempts 5', () => {
    // The record's config: maxAttempts 5, deadlineMs 120000, createdAt 12000,
    // so deadlineAt 132000; randomValues [4294967295, 2147483648, 4294967295,
    // 0] drawn in the order the retry delays are drawn; and the decision
    // instants the timeline states, 24000, 36999, 50499, 66498 and 82498
    // (each attempt timeout of perRelayTimeoutMs 12000 sits between them).
    const record = {
      maxAttempts: 5,
      deadlineAt: 132000,
      draws: [4294967295, 2147483648, 4294967295, 0],
      instants: [24000, 36999, 50499, 66498, 82498],
      expectedDelays: [999, 1500, 3999, 4000],
    };
    const random = randomOf(record.draws);
    const seen = [];
    for (let attempts = 1; attempts <= record.maxAttempts; attempts += 1) {
      const decision = planRetry({
        attempts,
        maxAttempts: record.maxAttempts,
        clock: clockAt(record.instants[attempts - 1]),
        deadlineAt: record.deadlineAt,
        random,
      });
      if (attempts < record.maxAttempts) {
        expect(decision).toStrictEqual({ action: 'RETRY', delayMs: record.expectedDelays[attempts - 1] });
        seen.push(decision.delayMs);
      } else {
        expect(decision).toStrictEqual({ action: 'FAIL', lastCode: null });
      }
    }
    expect(seen).toStrictEqual(record.expectedDelays);
    expect(random.remaining()).toBe(0);
    // Every retry was armed strictly before the deadline, as the record states.
    expect(record.instants[record.instants.length - 2] + seen[seen.length - 1])
      .toBeLessThan(record.deadlineAt);
  });

  test('relayLoss / relayLossAndReplacement: the retry after attempt 1 is 999 ms for the record draw', () => {
    // The record's randomValues [0, 4294967295]: the first draw is the
    // reconnection delay of the first consecutive loss, the second the retry
    // delay after attempt 1, decided at the record's instant 24000.
    const decision = planRetry({
      attempts: 1,
      maxAttempts: 5,
      clock: clockAt(24000),
      deadlineAt: 132000,
      random: randomOf([4294967295]),
    });
    expect(decision).toStrictEqual({ action: 'RETRY', delayMs: 999 });
    expect(retryDelayMs(1, 0)).toBe(500);
  });

  test('duplicateAndReordered / outboundDuplicateAccepted: the retry after attempt 1 is 999 ms for the record draw', () => {
    // The record's randomValues [0, 4294967295]: first the reconnection delay
    // of the k-th consecutive lost connection (500 ms), then the retry delay,
    // decided at the record's instant 24000.
    expect(retryDelayMs(1, 0)).toBe(500);
    const decision = planRetry({
      attempts: 1,
      maxAttempts: 5,
      clock: clockAt(24000),
      deadlineAt: 132000,
      random: randomOf([4294967295]),
    });
    expect(decision).toStrictEqual({ action: 'RETRY', delayMs: 999 });
  });
});
