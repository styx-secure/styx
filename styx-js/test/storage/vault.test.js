// vault.test.js — empty-vault lifecycle state machine (US-006). Real Argon2id
// (WASM from disk, OWASP-floor minimum profile) + an in-memory VaultDb fake
// with real transactional semantics (all-or-nothing, in-realm deep clone on
// put/get). Real IndexedDB persistence is covered by the browser suite; here
// the fake lets us interrupt a re-wrap deterministically at each §7.2 write.
import {
  describe, test, expect, beforeAll,
} from '@jest/globals';
import { readFileSync } from 'node:fs';
import initKdf, { argon2id_derive } from '../../vendor/styx-kdf-wasm/pkg/styx_kdf_wasm.js';
import { createVault, VAULT_STATES } from '../../src/storage/vault.js';
import { VaultCryptoError, VaultCryptoErrorCodes as Codes } from '../../src/crypto/vault-errors.js';
import { buildManifestCanonicalBytes } from '../../src/crypto/vault-aad.js';

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
// guard (correctly) rejects a foreign prototype. Real IndexedDB clones in-realm.
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
    this.failOn = null; // (ns, key, value) => boolean — simulated crash on a put
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
        if (this.failOn && this.failOn(ns, key, value)) throw new Error('injected crash');
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

  wrapper() { return this._store('meta').get('wrapper'); }

  manifest() { return this._store('meta').get('manifest'); }
}

// The two §7.2 persistence points, targeted by shape rather than by counting:
const STAGING = (ns, key, value) => key === 'wrapper' && value?.rewrapPending != null;
const COMMIT = (ns, key, value) => key === 'manifest' && value?.generation === 2;

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
  test('create → status UNLOCKED → lock → unlock round-trips; manifest v1 persisted', async () => {
    const db = new FakeVaultDb();
    const v = makeVault(db);
    expect((await v.status()).state).toBe(VAULT_STATES.UNINITIALIZED);
    expect((await v.createVault('correct horse', { profile: TEST_PROFILE })).state).toBe(VAULT_STATES.UNLOCKED);
    // Wrapper AND manifest exist after create (spec §11).
    expect(db.wrapper()).toBeTruthy();
    expect(db.manifest()).toMatchObject({ format: 'styx-vault-manifest', version: 1, schemaVersion: 1, generation: 1 });
    expect(typeof db.manifest().lastTxId).toBe('string');
    await v.lock();
    expect((await v.status()).state).toBe(VAULT_STATES.LOCKED);
    expect((await v.unlock('correct horse')).state).toBe(VAULT_STATES.UNLOCKED);
  });

  test('a second vault instance on the same db opens LOCKED (persistence)', async () => {
    const db = new FakeVaultDb();
    await makeVault(db).createVault('pw-eight!!', { profile: TEST_PROFILE });
    const reopened = makeVault(db);
    expect((await reopened.status()).state).toBe(VAULT_STATES.LOCKED);
    expect((await reopened.unlock('pw-eight!!')).state).toBe(VAULT_STATES.UNLOCKED);
  });
});

describe('forbidden transitions (§3) → VAULT_WRONG_STATE', () => {
  test('unlock before create', async () => {
    const v = makeVault(new FakeVaultDb());
    expect(await codeOf(v.unlock('pw-eight!!'))).toBe(Codes.WRONG_STATE);
  });
  test('create when one already exists', async () => {
    const v = makeVault(new FakeVaultDb());
    await v.createVault('pw-eight!!', { profile: TEST_PROFILE });
    expect(await codeOf(v.createVault('another8!', { profile: TEST_PROFILE }))).toBe(Codes.WRONG_STATE);
  });
  test('lock while locked', async () => {
    const db = new FakeVaultDb();
    await makeVault(db).createVault('pw-eight!!', { profile: TEST_PROFILE });
    const v = makeVault(db);
    expect(await codeOf(v.lock())).toBe(Codes.WRONG_STATE);
  });
  test('changePassword / rewrap while locked', async () => {
    const db = new FakeVaultDb();
    await makeVault(db).createVault('pw-eight!!', { profile: TEST_PROFILE });
    const v = makeVault(db);
    expect(await codeOf(v.changePassword('newpass8!', { profile: TEST_PROFILE }))).toBe(Codes.WRONG_STATE);
    expect(await codeOf(v.rewrap('pw-eight!!', { profile: TEST_PROFILE }))).toBe(Codes.WRONG_STATE);
  });
  test('MIGRATE trigger is out of scope, fail-closed', async () => {
    const v = makeVault(new FakeVaultDb());
    await v.createVault('pw-eight!!', { profile: TEST_PROFILE });
    expect(await codeOf(v.migrate())).toBe(Codes.WRONG_STATE);
  });
});

describe('password policy (§B3.0.4: 8–1024 chars)', () => {
  test.each([
    ['too short', 'short'],
    ['empty', ''],
    ['non-string', 12345678],
  ])('createVault rejects a %s password without invoking the KDF', async (_label, bad) => {
    const db = new FakeVaultDb();
    const v = makeVault(db);
    const before = deriveCalls;
    expect(await codeOf(v.createVault(bad, { profile: TEST_PROFILE }))).toBe(Codes.KDF_PARAMS_INVALID);
    expect(deriveCalls).toBe(before); // Argon2id never ran
    expect((await v.status()).state).toBe(VAULT_STATES.UNINITIALIZED);
  });

  test('unlock rejects a too-short password without invoking the KDF', async () => {
    const db = new FakeVaultDb();
    await makeVault(db).createVault('pw-eight!!', { profile: TEST_PROFILE });
    const v = makeVault(db);
    const before = deriveCalls;
    expect(await codeOf(v.unlock('x'))).toBe(Codes.KDF_PARAMS_INVALID);
    expect(deriveCalls).toBe(before);
  });

  test('a 1024-char password is accepted; 1025 is rejected', async () => {
    const db = new FakeVaultDb();
    const v = makeVault(db);
    expect((await v.createVault('a'.repeat(1024), { profile: TEST_PROFILE })).state).toBe(VAULT_STATES.UNLOCKED);
    const v2 = makeVault(new FakeVaultDb());
    expect(await codeOf(v2.createVault('a'.repeat(1025), { profile: TEST_PROFILE }))).toBe(Codes.KDF_PARAMS_INVALID);
  });
});

describe('no-oracle (§16.8)', () => {
  test('wrong password → VAULT_WRONG_PASSWORD, non-destructive, no persisted counter', async () => {
    const db = new FakeVaultDb();
    await makeVault(db).createVault('rightpass1', { profile: TEST_PROFILE });
    const before = deepClone(db.wrapper());
    const v = makeVault(db);
    expect(await codeOf(v.unlock('wrongpass1'))).toBe(Codes.WRONG_PASSWORD);
    expect(await codeOf(v.unlock('wrongpass2'))).toBe(Codes.WRONG_PASSWORD);
    expect(db.wrapper()).toEqual(before); // byte-identical, no counter
    expect((await v.status()).state).toBe(VAULT_STATES.LOCKED);
    expect((await v.unlock('rightpass1')).state).toBe(VAULT_STATES.UNLOCKED);
  });

  test('a corrupted-but-well-formed wrapper is indistinguishable from wrong password', async () => {
    const db = new FakeVaultDb();
    await makeVault(db).createVault('rightpass1', { profile: TEST_PROFILE });
    db.wrapper().wrappedRootKey[0] ^= 0xff; // form stays valid (48 bytes)
    const v = makeVault(db);
    expect(await codeOf(v.unlock('rightpass1'))).toBe(Codes.WRONG_PASSWORD);
  });

  test('a malformed FORM → VAULT_WRAPPER_INVALID before any KDF derivation', async () => {
    const db = new FakeVaultDb();
    await makeVault(db).createVault('rightpass1', { profile: TEST_PROFILE });
    db.wrapper().wrappedRootKey = db.wrapper().wrappedRootKey.slice(0, 47); // invalid length
    const before = deriveCalls;
    const v = makeVault(db);
    expect(await codeOf(v.unlock('rightpass1'))).toBe(Codes.WRAPPER_INVALID);
    expect(deriveCalls).toBe(before);
  });
});

describe('manifest v1 canonical serialization', () => {
  // The independent FROZEN vector (canonical bytes + MAC under a known Root
  // Key) lives in vault-keys.test.js; here we only assert the type guard.
  test('a non-primitive field is rejected before serialization', () => {
    expect(() => buildManifestCanonicalBytes({
      format: 'styx-vault-manifest', version: 1, schemaVersion: 1,
      migrationVersion: 1, generation: 1.5, lastTxId: 'x',
    })).toThrow(TypeError);
  });
});

describe('manifest integrity (§11)', () => {
  test('a tampered manifest with the correct password → VAULT_MANIFEST_TAMPERED (post-unlock, not an oracle)', async () => {
    const db = new FakeVaultDb();
    await makeVault(db).createVault('rightpass1', { profile: TEST_PROFILE });
    db.manifest().generation = 999; // tamper: HMAC no longer matches
    const v = makeVault(db);
    expect(await codeOf(v.unlock('rightpass1'))).toBe(Codes.MANIFEST_TAMPERED);
    expect((await v.status()).state).toBe(VAULT_STATES.LOCKED); // non-destructive
  });

  test('the manifest generation bumps on a re-wrap commit', async () => {
    const db = new FakeVaultDb();
    const v = makeVault(db);
    await v.createVault('rightpass1', { profile: TEST_PROFILE });
    expect(db.manifest().generation).toBe(1);
    await v.changePassword('newpass88', { profile: TEST_PROFILE });
    expect(db.manifest().generation).toBe(2);
    // The bumped manifest still verifies under the (unchanged) Root Key.
    const reopened = makeVault(db);
    expect((await reopened.unlock('newpass88')).state).toBe(VAULT_STATES.UNLOCKED);
  });
});

describe('re-wrap (§7.2)', () => {
  test('changePassword: new password unlocks, old password no longer does, Root Key unchanged', async () => {
    const db = new FakeVaultDb();
    const v = makeVault(db);
    await v.createVault('old-pass1', { profile: TEST_PROFILE });
    await v.changePassword('new-pass1', { profile: TEST_PROFILE });
    expect(db.wrapper().rewrapPending).toBeNull();
    const reopened = makeVault(db);
    expect(await codeOf(reopened.unlock('old-pass1'))).toBe(Codes.WRONG_PASSWORD);
    expect((await reopened.unlock('new-pass1')).state).toBe(VAULT_STATES.UNLOCKED);
  });

  test('rewrap keeps the same password, re-derives with fresh salt', async () => {
    const db = new FakeVaultDb();
    const v = makeVault(db);
    await v.createVault('pw-eight!!', { profile: TEST_PROFILE });
    const saltBefore = db.wrapper().saltB64;
    await v.rewrap('pw-eight!!', { profile: TEST_PROFILE });
    expect(db.wrapper().saltB64).not.toBe(saltBefore);
    const reopened = makeVault(db);
    expect((await reopened.unlock('pw-eight!!')).state).toBe(VAULT_STATES.UNLOCKED);
  });
});

describe('re-wrap crash recovery (§7.2 — a working wrapper at every instant)', () => {
  test('crash while staging the pending: old password still works, no pending left', async () => {
    const db = new FakeVaultDb();
    const v = makeVault(db);
    await v.createVault('old-pass1', { profile: TEST_PROFILE });
    db.failOn = STAGING; // crash the staging write
    await expect(v.changePassword('new-pass1', { profile: TEST_PROFILE })).rejects.toThrow();
    const reopened = makeVault(db);
    expect((await reopened.status()).state).toBe(VAULT_STATES.LOCKED);
    expect(db.wrapper().rewrapPending ?? null).toBeNull();
    expect((await reopened.unlock('old-pass1')).state).toBe(VAULT_STATES.UNLOCKED);
  });

  test('crash during the commit: RECOVERING discards the orphan pending, old password works, generation not bumped', async () => {
    const db = new FakeVaultDb();
    const v = makeVault(db);
    await v.createVault('old-pass1', { profile: TEST_PROFILE });
    db.failOn = COMMIT; // staging persists; the commit write crashes
    await expect(v.changePassword('new-pass1', { profile: TEST_PROFILE })).rejects.toThrow();
    expect(db.wrapper().rewrapPending).not.toBeNull(); // orphan pending on disk
    const reopened = makeVault(db);
    expect((await reopened.status()).state).toBe(VAULT_STATES.LOCKED); // keyless RECOVERING ran
    expect(db.wrapper().rewrapPending).toBeNull();
    expect(db.manifest().generation).toBe(1); // the commit never happened
    expect(await codeOf(reopened.unlock('new-pass1'))).toBe(Codes.WRONG_PASSWORD);
    expect((await reopened.unlock('old-pass1')).state).toBe(VAULT_STATES.UNLOCKED);
  });

  test('a crash during a non-writing step (KDF/verify) leaves the active wrapper untouched by construction', async () => {
    // deriveKek that throws mid-derivation — nothing has been written yet.
    const db = new FakeVaultDb();
    await makeVault(db).createVault('old-pass1', { profile: TEST_PROFILE });
    const before = deepClone(db.wrapper());
    let call = 0;
    const flakyKek = createVault({
      db,
      deriveKek: async (pw, params) => { call += 1; if (call === 2) throw new Error('KDF crash'); return argon2id_derive(pw, params.salt, params.mKib, params.t, params.p, params.outLen); },
      randomBytes: seededBytes(1),
      todayIso: () => '2026-07-22',
    });
    await flakyKek.unlock('old-pass1'); // call #1 (derive KEK to unlock)
    await expect(flakyKek.changePassword('new-pass1', { profile: TEST_PROFILE })).rejects.toThrow('KDF crash'); // call #2
    expect(db.wrapper()).toEqual(before); // no write occurred
  });
});

describe('destroy, ERROR recovery, and Root Key confinement', () => {
  test('destroy wipes the database and returns to UNINITIALIZED', async () => {
    const db = new FakeVaultDb();
    const v = makeVault(db);
    await v.createVault('pw-eight!!', { profile: TEST_PROFILE });
    expect((await v.destroy()).state).toBe(VAULT_STATES.UNINITIALIZED);
    expect(db.destroyed).toBe(1);
    expect((await v.status()).initialized).toBe(false);
  });

  test('destroy works even when the persisted wrapper is malformed (§3 any → DESTROYING)', async () => {
    const db = new FakeVaultDb();
    await makeVault(db).createVault('pw-eight!!', { profile: TEST_PROFILE });
    db.wrapper().wrappedRootKey = db.wrapper().wrappedRootKey.slice(0, 47); // corrupt the FORM
    const v = makeVault(db);
    // A normal op fails closed on the broken load...
    expect(await codeOf(v.status())).toBe(Codes.WRAPPER_INVALID);
    // ...but DESTROY still resets it.
    expect((await v.destroy()).state).toBe(VAULT_STATES.UNINITIALIZED);
    expect(db.destroyed).toBe(1);
  });

  test('no operation ever returns or exposes the Root Key', async () => {
    const db = new FakeVaultDb();
    const v = makeVault(db);
    const created = await v.createVault('pw-eight!!', { profile: TEST_PROFILE });
    const status = await v.status();
    expect(Object.keys(created)).toEqual(['state']);
    expect(Object.keys(status).sort()).toEqual(['initialized', 'state']);
    expect(JSON.stringify([created, status])).not.toMatch(/rootKey|"0":/i);
  });
});
