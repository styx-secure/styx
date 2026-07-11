// test/writer-lock.test.js — the single-writer decision.
// Web Locks is not in the node test env, so we drive acquireWriterLock with a stub that
// models the two outcomes: lock granted (this tab is the writer) vs already held.
import { describe, test, expect } from '@jest/globals';
import { acquireWriterLock } from '../src/lib/writer-lock.js';

/** A locks stub. If `taken`, the ifAvailable request is called back with null. */
function locksStub(taken) {
  return {
    request(name, opts, cb) {
      const lock = taken ? null : { name };
      return Promise.resolve(cb(lock)); // when granted, cb returns a pending promise
    },
  };
}

describe('acquireWriterLock', () => {
  test('grants the writer role when the lock is free', async () => {
    const { held, release } = await acquireWriterLock(locksStub(false), 'styx-mls:');
    expect(held).toBe(true);
    expect(typeof release).toBe('function');
    release(); // frees the held promise so the stub can settle
  });

  test('refuses the writer role when another tab holds the lock', async () => {
    const { held } = await acquireWriterLock(locksStub(true), 'styx-mls:');
    expect(held).toBe(false);
  });

  test('degrades to writer when Web Locks is unavailable', async () => {
    const { held } = await acquireWriterLock(undefined, 'styx-mls:');
    expect(held).toBe(true); // no lock API → proceed (documented minimal-scope degrade)
  });

  test('a request that rejects is treated as not-held', async () => {
    const throwing = { request() { return Promise.reject(new Error('nope')); } };
    const { held } = await acquireWriterLock(throwing, 'styx-mls:');
    expect(held).toBe(false);
  });
});
