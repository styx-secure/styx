// vault.test.js — empty-vault lifecycle state machine (US-006). Real Argon2id
// (WASM from disk, OWASP-floor minimum profile) + an in-memory VaultDb fake
// with real transactional semantics (all-or-nothing, structured-clone on
// put/get). Real IndexedDB persistence is covered by the browser suite; here
// the fake lets us interrupt a re-wrap deterministically at each §7.2 step.
import {
  describe, test, expect, beforeAll,
} from '@jest/globals';
import { readFileSync } from 'node:fs';
import initKdf, { argon2id_derive } from '../../vendor/styx-kdf-wasm/pkg/styx_kdf_wasm.js';
import { createVault, VAULT_STATES } from '../../src/storage/vault.js';
import { VaultCryptoError, VaultCryptoErrorCodes as Codes } from '../../src/crypto/vault-errors.js';

const wasmUrl = new URL('../../vendor/styx-kdf-wasm/pkg/styx_kdf_wasm_bg.wasm', import.meta.url);
beforeAll(async () => { await initKdf({ module_or_path: readFileSync(wasmUrl) }); });

// The cheapest policy-valid profile keeps the suite fast while exercising the
// real KDF (mobile-low-memory: mKib=19456 at the OWASP floor, t=4, p=1).
const TEST_PROFILE = 'mobile-low-memory';

let deriveCalls = 0;
const realDeriveKek = async (pw, { salt, mKib, t, p, outLen }) => {
  deriveCalls += 1;
  return argon2id_derive(pw, salt, mKib, t, p, outLen);
};

// Deterministic randomness so a test can reconstruct the same Root Key/salt if
// needed; distinct per instance via a seed offset.
function seededBytes(seed) {
  let s = seed >>> 0;
  return (n) => {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i += 1) { s = (s * 1664525 + 1013904223) >>> 0; out[i] = s & 0xff; }
    return out;
  };
}

// In-realm structured copy. NOT `structuredClone` on purpose: under Jest's
// --experimental-vm-modules the Node global builds objects in a different realm,
// so their Object.prototype !== the module's, and the wrapper's strict-shape
// guard (correctly) rejects a foreign prototype. Real IndexedDB clones in-realm,
// so this mirrors production without the test-harness artifact.
function deepClone(v) {
  if (v instanceof Uint8Array) return new Uint8Array(v);
  if (Array.isArray(v)) return v.map(deepClone);
  if (v !== null && typeof v === 'object') {
    const out = {};
    for (const k of Object.keys(v)) out[k] = deepClone(v[k]);
    return out;
  }
  return v;
}

class FakeVaultDb {
  constructor() {
    this.stores = new Map();
    this.putCount = 0;
    this.failOnPut = null; // global put index to throw on (simulated crash)
    this.destroyed = 0;
  }

  _store(ns) { if (!this.stores.has(ns)) this.stores.set(ns, new Map()); return this.stores.get(ns); }

  async get(ns, key) {
    const v = this._store(ns).get(key);
    return v === undefined ? undefined : deepClone(v);
  }

  async transaction(namespaces, cb) {
    const snap = new Map(namespaces.map((ns) => [ns, new Map(this._store(ns))]));
    const ops = {
      get: (ns, key) => { const v = this._store(ns).get(key); return v === undefined ? undefined : deepClone(v); },
      put: (ns, key, value) => {
        this.putCount += 1;
        if (this.failOnPut === this.putCount) throw new Error('injected crash');
        this._store(ns).set(key, deepClone(value));
      },
      delete: (ns, key) => this._store(ns).delete(key),
      clear: (ns) => this._store(ns).clear(),
      abort: () => { throw new Error('aborted'); },
    };
    try {
      return await cb(ops);
    } catch (e) {
      for (const [ns, m] of snap) this.stores.set(ns, m); // roll back
      throw e;
    }
  }

  async destroy() { this.destroyed += 1; this.stores = new Map(); }
}

function makeVault(db, seed = 1) {
  return createVault({
    db, deriveKek: realDeriveKek, randomBytes: seededBytes(seed),
    todayIso: () => '2026-07-22',
  });
}

const codeOf = async (promise) => {
  try { await promise; return 'RESOLVED'; } catch (e) {
    expect(e).toBeInstanceOf(VaultCryptoError);
    return e.code;
  }
};

describe('lifecycle happy path', () => {
  test('create → status UNLOCKED → lock → unlock round-trips', async () => {
    const db = new FakeVaultDb();
    const v = makeVault(db);
    expect((await v.status()).state).toBe(VAULT_STATES.UNINITIALIZED);
    expect((await v.createVault('correct horse', { profile: TEST_PROFILE })).state).toBe(VAULT_STATES.UNLOCKED);
    expect((await v.status()).initialized).toBe(true);
    await v.lock();
    expect((await v.status()).state).toBe(VAULT_STATES.LOCKED);
    expect((await v.unlock('correct horse')).state).toBe(VAULT_STATES.UNLOCKED);
  });

  test('a second vault instance on the same db opens LOCKED (persistence)', async () => {
    const db = new FakeVaultDb();
    await makeVault(db).createVault('pw', { profile: TEST_PROFILE });
    const reopened = makeVault(db);
    expect((await reopened.status()).state).toBe(VAULT_STATES.LOCKED);
    expect((await reopened.unlock('pw')).state).toBe(VAULT_STATES.UNLOCKED);
  });
});

describe('forbidden transitions (§3) → VAULT_WRONG_STATE', () => {
  test('unlock before create', async () => {
    const v = makeVault(new FakeVaultDb());
    expect(await codeOf(v.unlock('pw'))).toBe(Codes.WRONG_STATE);
  });
  test('create when one already exists', async () => {
    const v = makeVault(new FakeVaultDb());
    await v.createVault('pw', { profile: TEST_PROFILE });
    expect(await codeOf(v.createVault('other', { profile: TEST_PROFILE }))).toBe(Codes.WRONG_STATE);
  });
  test('lock while locked', async () => {
    const db = new FakeVaultDb();
    await makeVault(db).createVault('pw', { profile: TEST_PROFILE });
    const v = makeVault(db);
    expect(await codeOf(v.lock())).toBe(Codes.WRONG_STATE);
  });
  test('changePassword / rewrap while locked', async () => {
    const db = new FakeVaultDb();
    await makeVault(db).createVault('pw', { profile: TEST_PROFILE });
    const v = makeVault(db);
    expect(await codeOf(v.changePassword('new', { profile: TEST_PROFILE }))).toBe(Codes.WRONG_STATE);
    expect(await codeOf(v.rewrap('pw', { profile: TEST_PROFILE }))).toBe(Codes.WRONG_STATE);
  });
  test('MIGRATE trigger is out of scope, fail-closed', async () => {
    const v = makeVault(new FakeVaultDb());
    await v.createVault('pw', { profile: TEST_PROFILE });
    expect(await codeOf(v.migrate())).toBe(Codes.WRONG_STATE);
  });
});

describe('no-oracle (§16.8)', () => {
  test('wrong password → VAULT_WRONG_PASSWORD, non-destructive, no persisted counter', async () => {
    const db = new FakeVaultDb();
    await makeVault(db).createVault('right', { profile: TEST_PROFILE });
    const before = deepClone(db._store('meta').get('wrapper'));
    const v = makeVault(db);
    expect(await codeOf(v.unlock('wrong'))).toBe(Codes.WRONG_PASSWORD);
    expect(await codeOf(v.unlock('wrong'))).toBe(Codes.WRONG_PASSWORD);
    // The stored wrapper is byte-identical after repeated failures (no counter).
    expect(db._store('meta').get('wrapper')).toEqual(before);
    expect((await v.status()).state).toBe(VAULT_STATES.LOCKED); // still usable
    expect((await v.unlock('right')).state).toBe(VAULT_STATES.UNLOCKED);
  });

  test('a corrupted-but-well-formed wrapper is indistinguishable from wrong password', async () => {
    const db = new FakeVaultDb();
    await makeVault(db).createVault('right', { profile: TEST_PROFILE });
    // Flip one byte of the ciphertext, keeping the FORM valid (48 bytes).
    const w = db._store('meta').get('wrapper');
    w.wrappedRootKey[0] ^= 0xff;
    const v = makeVault(db);
    expect(await codeOf(v.unlock('right'))).toBe(Codes.WRONG_PASSWORD);
  });

  test('a malformed FORM → VAULT_WRAPPER_INVALID before any KDF derivation', async () => {
    const db = new FakeVaultDb();
    await makeVault(db).createVault('right', { profile: TEST_PROFILE });
    const w = db._store('meta').get('wrapper');
    w.wrappedRootKey = w.wrappedRootKey.slice(0, 47); // invalid length = invalid form
    const callsBefore = deriveCalls;
    const v = makeVault(db);
    expect(await codeOf(v.unlock('right'))).toBe(Codes.WRAPPER_INVALID);
    expect(deriveCalls).toBe(callsBefore); // the KDF was never invoked
  });
});

describe('re-wrap (§7.2)', () => {
  test('changePassword: new password unlocks, old password no longer does, Root Key unchanged', async () => {
    const db = new FakeVaultDb();
    const v = makeVault(db);
    await v.createVault('old-pw', { profile: TEST_PROFILE });
    await v.changePassword('new-pw', { profile: TEST_PROFILE });
    // The active wrapper carries no pending after commit.
    expect(db._store('meta').get('wrapper').rewrapPending).toBeNull();
    const reopened = makeVault(db);
    expect(await codeOf(reopened.unlock('old-pw'))).toBe(Codes.WRONG_PASSWORD);
    expect((await reopened.unlock('new-pw')).state).toBe(VAULT_STATES.UNLOCKED);
  });

  test('rewrap keeps the same password, re-derives with fresh salt', async () => {
    const db = new FakeVaultDb();
    const v = makeVault(db);
    await v.createVault('pw', { profile: TEST_PROFILE });
    const saltBefore = db._store('meta').get('wrapper').saltB64;
    await v.rewrap('pw', { profile: TEST_PROFILE });
    expect(db._store('meta').get('wrapper').saltB64).not.toBe(saltBefore); // new salt
    const reopened = makeVault(db);
    expect((await reopened.unlock('pw')).state).toBe(VAULT_STATES.UNLOCKED);
  });
});

describe('re-wrap crash recovery (§7.2 — a working wrapper at every instant)', () => {
  // createVault issues put #1; a re-wrap issues put #2 (stage pending) and
  // put #3 (atomic commit). Crash at each and confirm reopen recovers.
  test('crash while staging the pending: old password still works, no pending left', async () => {
    const db = new FakeVaultDb();
    const v = makeVault(db);
    await v.createVault('old', { profile: TEST_PROFILE }); // put #1
    db.failOnPut = 2; // the staging write
    await expect(v.changePassword('new', { profile: TEST_PROFILE })).rejects.toThrow();
    const reopened = makeVault(db);
    expect((await reopened.status()).state).toBe(VAULT_STATES.LOCKED);
    expect(db._store('meta').get('wrapper').rewrapPending ?? null).toBeNull();
    expect((await reopened.unlock('old')).state).toBe(VAULT_STATES.UNLOCKED);
  });

  test('crash after staging, before commit: RECOVERING discards the orphan pending, old password works', async () => {
    const db = new FakeVaultDb();
    const v = makeVault(db);
    await v.createVault('old', { profile: TEST_PROFILE }); // put #1
    db.failOnPut = 3; // the commit write (staging put #2 has persisted)
    await expect(v.changePassword('new', { profile: TEST_PROFILE })).rejects.toThrow();
    // Persisted active wrapper carries an orphan pending at this point.
    expect(db._store('meta').get('wrapper').rewrapPending).not.toBeNull();
    const reopened = makeVault(db);
    // Loading runs the keyless RECOVERING sweep, then LOCKED.
    expect((await reopened.status()).state).toBe(VAULT_STATES.LOCKED);
    expect(db._store('meta').get('wrapper').rewrapPending).toBeNull();
    expect(await codeOf(reopened.unlock('new'))).toBe(Codes.WRONG_PASSWORD); // the change was rolled back
    expect((await reopened.unlock('old')).state).toBe(VAULT_STATES.UNLOCKED);
  });
});

describe('destroy and Root Key confinement', () => {
  test('destroy wipes the database and returns to UNINITIALIZED', async () => {
    const db = new FakeVaultDb();
    const v = makeVault(db);
    await v.createVault('pw', { profile: TEST_PROFILE });
    expect((await v.destroy()).state).toBe(VAULT_STATES.UNINITIALIZED);
    expect(db.destroyed).toBe(1);
    expect((await v.status()).initialized).toBe(false);
  });

  test('no operation ever returns or exposes the Root Key', async () => {
    const db = new FakeVaultDb();
    const v = makeVault(db);
    const created = await v.createVault('pw', { profile: TEST_PROFILE });
    const status = await v.status();
    const seen = JSON.stringify([created, status]);
    // 32-byte Root Key would show up as a byte array; status carries only state.
    expect(Object.keys(created)).toEqual(['state']);
    expect(Object.keys(status).sort()).toEqual(['initialized', 'state']);
    expect(seen).not.toMatch(/rootKey|"0":/i);
  });
});
