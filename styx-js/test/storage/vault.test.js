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
import { FakeVaultDb, deepClone, seededBytes } from '../support/fake-vault-db.js';

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
  test('MIGRATE rejects a missing namespace and payload fail-closed', async () => {
    const v = makeVault(new FakeVaultDb());
    await v.createVault('pw-eight!!', { profile: TEST_PROFILE });
    expect(await codeOf(v.migrate())).toBe(Codes.NAMESPACE_UNSUPPORTED);
  });
});

describe('settings migration (US-009)', () => {
  const light = Object.freeze({ v: 1, theme: 'light', installHintDismissed: false });
  const dark = Object.freeze({ v: 1, theme: 'dark', installHintDismissed: true });

  test('writes one authenticated JSON record, verifies it, and is idempotent', async () => {
    const db = new FakeVaultDb();
    const v = makeVault(db);
    await v.createVault('pw-eight!!', { profile: TEST_PROFILE });

    const first = await v.migrate('settings', light);
    expect(first).toMatchObject({ state: 'verified', matched: true, recordVersion: 1 });
    expect(db.record('settings', 'preferences')).toMatchObject({ ct: 'json', rv: 1 });
    expect(db.record('migrations', 'settings')).toMatchObject({
      version: 1, namespace: 'settings', state: 'verified',
      counts: { source: 1, written: 1 },
    });
    expect((await v.getRecord('settings', 'preferences')).value).toEqual(light);

    const generation = db.manifest().generation;
    expect(await v.migrate('settings', light)).toEqual(first);
    expect(db.manifest().generation).toBe(generation);
    expect(db.record('settings', 'preferences').rv).toBe(1);

    expect(await v.migrate('settings', dark)).toMatchObject({ recordVersion: 2 });
    expect((await v.getRecord('settings', 'preferences')).value).toEqual(dark);
  });

  test.each([
    ['phase-2 record commit', (_ns, key) => key === 'preferences'],
    ['phase-3 verified marker', (_ns, key, value) => key === 'settings' && value?.state === 'verified'],
  ])('a crash at %s resumes safely without duplicating the record version', async (_label, failOn) => {
    const db = new FakeVaultDb();
    const v = makeVault(db);
    await v.createVault('pw-eight!!', { profile: TEST_PROFILE });
    db.failOn = failOn;
    await expect(v.migrate('settings', light)).rejects.toThrow('injected crash');
    db.failOn = null;

    expect(await v.migrate('settings', light)).toMatchObject({ state: 'verified', recordVersion: 1 });
    expect(db.record('settings', 'preferences').rv).toBe(1);
    expect(db.record('migrations', 'settings').state).toBe('verified');
  });

  test('a crash after the IDB commit but before verification resumes from written without a rewrite', async () => {
    const db = new FakeVaultDb();
    const v = makeVault(db);
    await v.createVault('pw-eight!!', { profile: TEST_PROFILE });
    let reads = 0;
    db.failGetOn = (namespace, key, value) => {
      if (namespace !== 'settings' || key !== 'preferences' || value === undefined) return false;
      reads += 1;
      return reads === 1;
    };
    await expect(v.migrate('settings', light)).rejects.toThrow('injected read crash');
    expect(db.record('migrations', 'settings').state).toBe('written');
    expect(db.record('settings', 'preferences').rv).toBe(1);
    db.failGetOn = null;
    expect(await v.migrate('settings', light)).toMatchObject({ state: 'verified', recordVersion: 1 });
    expect(db.record('settings', 'preferences').rv).toBe(1);
  });

  test('tampered markers and verified divergence fail closed', async () => {
    const db = new FakeVaultDb();
    const v = makeVault(db);
    await v.createVault('pw-eight!!', { profile: TEST_PROFILE });
    await v.migrate('settings', light);
    const firstDigest = db.record('migrations', 'settings').digests.source;
    db.record('migrations', 'settings').counts.written = 0;
    expect(await codeOf(v.migrate('settings', light))).toBe(Codes.RECORD_INVALID);

    const db2 = new FakeVaultDb();
    const v2 = makeVault(db2, 2);
    await v2.createVault('pw-eight!!', { profile: TEST_PROFILE });
    await v2.migrate('settings', light);
    expect(db2.record('migrations', 'settings').digests.source).not.toBe(firstDigest);
    db2.record('settings', 'preferences').data[0] ^= 0xff;
    expect(await codeOf(v2.migrate('settings', light))).toBe(Codes.RECORD_CORRUPTED);
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
