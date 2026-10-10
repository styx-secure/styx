// test/writer-lock.test.js — the single-writer decision.
// Web Locks is not in the node test env, so we drive acquireWriterLock with a stub that
// models the outcomes: lock granted (this tab is the writer), already held, unavailable,
// rejected. Since owner act m2-rescope-c-reduced §3 (#317 comment 6091950328) every
// non-grant fails closed: there is no degraded writer mode.
import { describe, test, expect, jest } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { acquireWriterLock, WRITER_LOCK_REASONS } from '../src/lib/writer-lock.js';

/** A locks stub. If `taken`, the ifAvailable request is called back with null. */
function locksStub(taken) {
  const calls = [];
  return {
    calls,
    request(name, opts, cb) {
      calls.push({ name, opts: { ...opts } });
      const lock = taken ? null : { name };
      return Promise.resolve(cb(lock)); // when granted, cb returns a pending promise
    },
  };
}

describe('acquireWriterLock', () => {
  test('grants the writer role when the lock is free (one exclusive ifAvailable request, no steal)', async () => {
    const locks = locksStub(false);
    const { held, reason, release } = await acquireWriterLock(locks, 'styx-mls:');
    expect(held).toBe(true);
    expect(reason).toBeUndefined();
    expect(typeof release).toBe('function');
    expect(locks.calls).toEqual([{ name: 'styx-mls:', opts: { mode: 'exclusive', ifAvailable: true } }]);
    release(); // frees the held promise so the stub can settle
  });

  test('refuses the writer role when another tab holds the lock', async () => {
    const { held, reason } = await acquireWriterLock(locksStub(true), 'styx-mls:');
    expect(held).toBe(false);
    expect(reason).toBe(WRITER_LOCK_REASONS.HELD_ELSEWHERE);
  });

  test.each([
    ['undefined', undefined],
    ['null', null],
    ['an object without request', {}],
    ['a non-function request', { request: true }],
    ['a throwing request getter', Object.defineProperty({}, 'request', { get() { throw new Error('x'); } })],
  ])('fails closed when Web Locks is unavailable (%s)', async (_label, locksApi) => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      const { held, reason, release } = await acquireWriterLock(locksApi, 'styx-mls:');
      expect(held).toBe(false); // no lock API → no writer (fail closed, act §3)
      expect(reason).toBe('unsupported');
      expect(reason).toBe(WRITER_LOCK_REASONS.UNSUPPORTED);
      expect(() => release()).not.toThrow();
    } finally {
      warn.mockRestore();
    }
  });

  test('a request that rejects is treated as not-held', async () => {
    const throwing = { request() { return Promise.reject(new Error('nope')); } };
    const { held, reason } = await acquireWriterLock(throwing, 'styx-mls:');
    expect(held).toBe(false);
    expect(reason).toBe(WRITER_LOCK_REASONS.REJECTED);
  });

  test('a request that throws synchronously is treated as not-held', async () => {
    const { held, reason } = await acquireWriterLock({ request() { throw new Error('SecurityError'); } }, 'styx-mls:');
    expect(held).toBe(false);
    expect(reason).toBe(WRITER_LOCK_REASONS.REJECTED);
  });

  test('a request that settles without calling back is treated as not-held', async () => {
    const { held, reason } = await acquireWriterLock({ request: () => Promise.resolve() }, 'styx-mls:');
    expect(held).toBe(false);
    expect(reason).toBe(WRITER_LOCK_REASONS.REJECTED);
  });

  test('a request that calls back with a grant and then throws is not-held, and the grant is freed', async () => {
    let freed = false;
    const locks = {
      request(name, options, callback) {
        Promise.resolve(callback({ name, mode: 'exclusive' })).then(() => { freed = true; });
        throw new Error('after callback');
      },
    };
    const { held, reason } = await acquireWriterLock(locks, 'styx-mls:');
    expect(held).toBe(false);
    expect(reason).toBe(WRITER_LOCK_REASONS.REJECTED);
    await Promise.resolve();
    expect(freed).toBe(true);
  });

  test('the source has exactly one held:true return (the granted path) and never steals', () => {
    const src = readFileSync(new URL('../src/lib/writer-lock.js', import.meta.url), 'utf8');
    expect(src.match(/held:\s*true/g)).toEqual(['held: true']);
    expect(src).toMatch(/return \{ held: true, release \};\n\}\n?$/);
    expect(src).not.toMatch(/steal/);
  });
});
