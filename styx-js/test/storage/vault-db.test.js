// vault-db.test.js — non-IDB logic of the vault engine (US-005): bounded
// blocked-wait semantics, structured errors, bounded storage probe. Real
// IndexedDB behaviour is covered by the browser suite
// (vault-db.browser.spec.js, probes P1–P12); here every browser API is an
// injected fake.
import { describe, test, expect } from '@jest/globals';
import {
  openVaultDb, probeStorage, VAULT_NAMESPACES, BLOCKED_WAIT_MS,
} from '../../src/storage/vault-db.js';
import { VaultCryptoError, VaultCryptoErrorCodes as Codes } from '../../src/crypto/vault-errors.js';

class FakeOpenRequest {
  constructor() { this.onsuccess = null; this.onerror = null; this.onblocked = null; this.onupgradeneeded = null; }
}

function makeFakeTimers() {
  const timers = new Map();
  let next = 1;
  return {
    setTimeoutImpl: (fn, ms) => { const id = next; next += 1; timers.set(id, { fn, ms }); return id; },
    clearTimeoutImpl: (id) => { timers.delete(id); },
    fire: () => { for (const [id, t] of [...timers]) { timers.delete(id); t.fn(); } },
    armed: () => timers.size,
    delays: () => [...timers.values()].map((t) => t.ms),
  };
}

const errOf = async (promise) => {
  try { await promise; return 'RESOLVED'; } catch (e) {
    expect(e).toBeInstanceOf(VaultCryptoError);
    return e;
  }
};

describe('openVaultDb — argument and error discipline', () => {
  test('a missing name rejects VAULT_OPEN_FAILED without touching IndexedDB', async () => {
    let opens = 0;
    const fakeIDB = { open: () => { opens += 1; return new FakeOpenRequest(); } };
    const err = await errOf(openVaultDb({ indexedDBImpl: fakeIDB }));
    expect(err.code).toBe(Codes.OPEN_FAILED);
    expect(err.details.reason).toBe('missing-name');
    expect(opens).toBe(0);
  });

  test('the ten frozen namespaces are exactly the plan §B3.0.1 list', () => {
    expect([...VAULT_NAMESPACES].sort()).toEqual([
      'canary', 'contacts', 'identity', 'messages', 'meta', 'migrations',
      'mls', 'outbox', 'push', 'settings',
    ]);
    expect(Object.isFrozen(VAULT_NAMESPACES)).toBe(true);
  });
});

describe('bounded blocked-wait (spike P10: wait on the SAME request, never reopen)', () => {
  test('a permanently blocked open rejects VAULT_BLOCKED after ONE bounded wait, with a single open call', async () => {
    const timers = makeFakeTimers();
    const requests = [];
    const fakeIDB = { open: () => { const r = new FakeOpenRequest(); requests.push(r); return r; } };
    const p = errOf(openVaultDb({
      name: 'styx-vault-test-blocked',
      indexedDBImpl: fakeIDB,
      setTimeoutImpl: timers.setTimeoutImpl,
      clearTimeoutImpl: timers.clearTimeoutImpl,
    }));
    requests[0].onblocked();
    requests[0].onblocked(); // repeated blocked events must not re-arm the bound
    expect(timers.armed()).toBe(1);
    expect(timers.delays()).toEqual([BLOCKED_WAIT_MS]);
    timers.fire();
    const err = await p;
    expect(err.code).toBe(Codes.BLOCKED);
    expect(requests.length).toBe(1); // never a second open behind the pending one
  });

  test('a transient blocker resolves the SAME request: success before the bound wins', async () => {
    const timers = makeFakeTimers();
    const requests = [];
    const fakeDb = {
      name: 'styx-vault-test-transient', version: 1, objectStoreNames: [], onversionchange: null, close: () => {},
    };
    const fakeIDB = { open: () => { const r = new FakeOpenRequest(); requests.push(r); return r; } };
    const p = openVaultDb({
      name: 'styx-vault-test-transient',
      indexedDBImpl: fakeIDB,
      setTimeoutImpl: timers.setTimeoutImpl,
      clearTimeoutImpl: timers.clearTimeoutImpl,
    });
    requests[0].onblocked(); // blocker appears...
    requests[0].result = fakeDb;
    requests[0].onsuccess(); // ...then closes: the pending request completes
    const db = await p;
    expect(db.name).toBe('styx-vault-test-transient');
    expect(timers.armed()).toBe(0); // the bound was cancelled
  });

  test('a success landing AFTER the bound closes the orphan connection', async () => {
    const timers = makeFakeTimers();
    const requests = [];
    let closed = 0;
    const fakeDb = {
      name: 'x', version: 1, objectStoreNames: [], onversionchange: null, close: () => { closed += 1; },
    };
    const fakeIDB = { open: () => { const r = new FakeOpenRequest(); requests.push(r); return r; } };
    const p = errOf(openVaultDb({
      name: 'styx-vault-test-late',
      indexedDBImpl: fakeIDB,
      setTimeoutImpl: timers.setTimeoutImpl,
      clearTimeoutImpl: timers.clearTimeoutImpl,
    }));
    requests[0].onblocked();
    timers.fire(); // bound expires → VAULT_BLOCKED
    expect((await p).code).toBe(Codes.BLOCKED);
    requests[0].result = fakeDb;
    requests[0].onsuccess(); // the blocker went away too late
    expect(closed).toBe(1); // no leaked live connection
  });

  test('a missing migrator step aborts the upgrade fail-closed with VAULT_SCHEMA_GAP', async () => {
    const timers = makeFakeTimers();
    const requests = [];
    let aborted = 0;
    const fakeIDB = { open: () => { const r = new FakeOpenRequest(); requests.push(r); return r; } };
    const p = errOf(openVaultDb({
      name: 'styx-vault-test-gap',
      version: 2,
      migrations: { 1: () => {} }, // no entry for version 2
      indexedDBImpl: fakeIDB,
      setTimeoutImpl: timers.setTimeoutImpl,
      clearTimeoutImpl: timers.clearTimeoutImpl,
    }));
    requests[0].result = { createObjectStore: () => {} };
    requests[0].transaction = { abort: () => { aborted += 1; } };
    requests[0].onupgradeneeded({ oldVersion: 0 });
    requests[0].error = null;
    requests[0].onerror(); // the aborted versionchange surfaces as an error event
    const err = await p;
    expect(err.code).toBe(Codes.SCHEMA_GAP);
    expect(err.details.version).toBe(2);
    expect(aborted).toBe(1); // the WHOLE upgrade was aborted, not partially applied
  });
});

describe('probeStorage — advisory and bounded (spike F8)', () => {
  test('a persist() that never settles resolves as timeout, never hangs', async () => {
    const timers = makeFakeTimers();
    const never = new Promise(() => {});
    const storage = {
      persisted: () => never,
      persist: () => never,
      estimate: () => never,
    };
    const p = probeStorage({ storageImpl: storage, setTimeoutImpl: timers.setTimeoutImpl });
    // The three bounds arm one at a time, between awaits: fire each as it
    // appears, yielding to the microtask queue in between.
    const flush = () => new Promise((r) => { setImmediate(r); });
    for (let i = 0; i < 3; i += 1) {
      timers.fire();
      // eslint-disable-next-line no-await-in-loop
      await flush();
    }
    const out = await p;
    expect(out).toEqual({ persisted: 'timeout', persistGranted: 'timeout', quota: null, usage: null });
  });

  test('an absent storage API is advisory: all null, no throw', async () => {
    expect(await probeStorage({ storageImpl: undefined })).toEqual({
      persisted: null, persistGranted: null, quota: null, usage: null,
    });
  });

  test('a working storage API reports quota and persistence', async () => {
    const storage = {
      persisted: async () => true,
      persist: async () => true,
      estimate: async () => ({ quota: 1000, usage: 10 }),
    };
    expect(await probeStorage({ storageImpl: storage })).toEqual({
      persisted: true, persistGranted: true, quota: 1000, usage: 10,
    });
  });
});
