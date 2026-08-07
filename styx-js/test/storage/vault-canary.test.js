// vault-canary.test.js — record CRUD on the canary namespace and the signed
// schemaVersion high-water mark (US-007). Real Argon2id + the real frozen
// record codec over the shared in-memory engine double; real IndexedDB is
// covered by the browser suite. Every record here is synthetic (plan B3.6).
import {
  describe, test, expect, beforeAll,
} from '@jest/globals';
import { readFileSync } from 'node:fs';
import initKdf, { argon2id_derive } from '../../vendor/styx-kdf-wasm/pkg/styx_kdf_wasm.js';
import { createVault, VAULT_STATES } from '../../src/storage/vault.js';
import { VaultCryptoError, VaultCryptoErrorCodes as Codes } from '../../src/crypto/vault-errors.js';
import { FakeVaultDb, deepClone, seededBytes } from '../support/fake-vault-db.js';

const wasmUrl = new URL('../../vendor/styx-kdf-wasm/pkg/styx_kdf_wasm_bg.wasm', import.meta.url);
beforeAll(async () => { await initKdf({ module_or_path: readFileSync(wasmUrl) }); });

const TEST_PROFILE = 'mobile-low-memory';
const PW = 'canary-pass1';

const realDeriveKek = async (pw, { salt, mKib, t, p, outLen }) => argon2id_derive(pw, salt, mKib, t, p, outLen);

function makeVault(db, seed = 1) {
  return createVault({
    db, deriveKek: realDeriveKek, randomBytes: seededBytes(seed), todayIso: () => '2026-07-25',
  });
}

/** A created, unlocked vault over a fresh fake engine. */
async function unlockedVault({ version = 1 } = {}) {
  const db = new FakeVaultDb({ version });
  const vault = makeVault(db);
  await vault.createVault(PW, { profile: TEST_PROFILE });
  return { db, vault };
}

const codeOf = async (promise) => {
  try { await promise; return 'RESOLVED'; } catch (e) {
    expect(e).toBeInstanceOf(VaultCryptoError);
    return e.code;
  }
};

describe('canary record CRUD', () => {
  test('json round-trip: put then get returns the value', async () => {
    const { vault } = await unlockedVault();
    await vault.putRecord('canary', 'probe:1', { hello: 'synthetic', n: 42 }, { contentType: 'json' });
    const out = await vault.getRecord('canary', 'probe:1');
    expect(out.value).toEqual({ hello: 'synthetic', n: 42 });
    expect(out.contentType).toBe('json');
    expect(out.recordVersion).toBe(1);
  });

  test('bytes round-trip: binary is stored natively and returned byte-identical', async () => {
    const { db, vault } = await unlockedVault();
    const bytes = new Uint8Array([0, 1, 2, 250, 251, 255]);
    await vault.putRecord('canary', 'probe:bin', bytes, { contentType: 'bytes' });
    const out = await vault.getRecord('canary', 'probe:bin');
    expect(Array.from(out.value)).toEqual(Array.from(bytes));
    // The persisted envelope carries native binary, never base64.
    expect(db.record('canary', 'probe:bin').data).toBeInstanceOf(Uint8Array);
  });

  test('the stored envelope never contains the plaintext', async () => {
    const { db, vault } = await unlockedVault();
    await vault.putRecord('canary', 'probe:secret', { marker: 'PLAINTEXT-MARKER-XYZ' }, { contentType: 'json' });
    const stored = db.record('canary', 'probe:secret');
    expect(JSON.stringify(stored)).not.toContain('PLAINTEXT-MARKER-XYZ');
  });

  test('listRecords returns the keys of the namespace', async () => {
    const { vault } = await unlockedVault();
    await vault.putRecord('canary', 'a', { i: 1 }, { contentType: 'json' });
    await vault.putRecord('canary', 'b', { i: 2 }, { contentType: 'json' });
    expect((await vault.listRecords('canary')).sort()).toEqual(['a', 'b']);
  });

  test('deleteRecord removes the record; a later get fails closed', async () => {
    const { vault } = await unlockedVault();
    await vault.putRecord('canary', 'gone', { i: 1 }, { contentType: 'json' });
    await vault.deleteRecord('canary', 'gone');
    expect(await vault.listRecords('canary')).toEqual([]);
    // A missing record is a normal outcome, not an error.
    expect(await vault.getRecord('canary', 'gone')).toBeUndefined();
  });
});

describe('canary-only namespace gate (plan B3.6)', () => {
  test.each(['settings', 'identity', 'contacts', 'messages', 'mls', 'outbox', 'push'])(
    'the product namespace %s is refused by this build', async (ns) => {
      const { vault } = await unlockedVault();
      expect(await codeOf(vault.putRecord(ns, 'k', { a: 1 }, { contentType: 'json' })))
        .toBe(Codes.NAMESPACE_UNSUPPORTED);
      expect(await codeOf(vault.getRecord(ns, 'k'))).toBe(Codes.NAMESPACE_UNSUPPORTED);
      expect(await codeOf(vault.listRecords(ns))).toBe(Codes.NAMESPACE_UNSUPPORTED);
    },
  );

  test('an unknown namespace is refused too', async () => {
    const { vault } = await unlockedVault();
    expect(await codeOf(vault.putRecord('nope', 'k', { a: 1 }, { contentType: 'json' })))
      .toBe(Codes.NAMESPACE_UNSUPPORTED);
  });
});

describe('record ops require UNLOCKED', () => {
  test.each([
    ['putRecord', (v) => v.putRecord('canary', 'k', { a: 1 }, { contentType: 'json' })],
    ['getRecord', (v) => v.getRecord('canary', 'k')],
    ['deleteRecord', (v) => v.deleteRecord('canary', 'k')],
    ['listRecords', (v) => v.listRecords('canary')],
  ])('%s from LOCKED → VAULT_WRONG_STATE', async (_label, op) => {
    const { db } = await unlockedVault();
    const locked = makeVault(db); // fresh instance over the same db = LOCKED
    expect(await codeOf(op(locked))).toBe(Codes.WRONG_STATE);
  });
});

describe('recordVersion is monotonic per key (§6 anti-swap)', () => {
  test('rewriting a key increments rv', async () => {
    const { db, vault } = await unlockedVault();
    await vault.putRecord('canary', 'k', { v: 1 }, { contentType: 'json' });
    expect(db.record('canary', 'k').rv).toBe(1);
    await vault.putRecord('canary', 'k', { v: 2 }, { contentType: 'json' });
    expect(db.record('canary', 'k').rv).toBe(2);
    await vault.putRecord('canary', 'k', { v: 3 }, { contentType: 'json' });
    expect(db.record('canary', 'k').rv).toBe(3);
    expect((await vault.getRecord('canary', 'k')).value).toEqual({ v: 3 });
  });

  test('a deleted key restarts from rv 1', async () => {
    const { db, vault } = await unlockedVault();
    await vault.putRecord('canary', 'k', { v: 1 }, { contentType: 'json' });
    await vault.putRecord('canary', 'k', { v: 2 }, { contentType: 'json' });
    await vault.deleteRecord('canary', 'k');
    await vault.putRecord('canary', 'k', { v: 9 }, { contentType: 'json' });
    expect(db.record('canary', 'k').rv).toBe(1);
  });
});

describe('concurrent mutations are serialized (independent review, PR #104 F1)', () => {
  // Without an internal queue, concurrent calls each read `rv` and
  // `generation` before their asynchronous encryption, so they all compute the
  // same next value: one write is lost and both counters stop being monotonic.
  test('three concurrent writes to the SAME key produce rv 1→3 and lose nothing', async () => {
    const { db, vault } = await unlockedVault();
    const results = await Promise.all([
      vault.putRecord('canary', 'k', { i: 1 }, { contentType: 'json' }),
      vault.putRecord('canary', 'k', { i: 2 }, { contentType: 'json' }),
      vault.putRecord('canary', 'k', { i: 3 }, { contentType: 'json' }),
    ]);
    expect(results.map((r) => r.recordVersion).sort()).toEqual([1, 2, 3]);
    expect(db.record('canary', 'k').rv).toBe(3);
    expect(db.manifest().generation).toBe(4); // 1 create + 3 writes, each a commit
    expect((await vault.getRecord('canary', 'k')).recordVersion).toBe(3);
  });

  test('concurrent writes to DIFFERENT keys each take a distinct generation', async () => {
    const { db, vault } = await unlockedVault();
    await Promise.all([
      vault.putRecord('canary', 'a', { i: 1 }, { contentType: 'json' }),
      vault.putRecord('canary', 'b', { i: 2 }, { contentType: 'json' }),
      vault.putRecord('canary', 'c', { i: 3 }, { contentType: 'json' }),
    ]);
    expect(db.manifest().generation).toBe(4);
    expect((await vault.listRecords('canary')).sort()).toEqual(['a', 'b', 'c']);
  });

  test('a concurrent write and delete leave a coherent generation', async () => {
    const { db, vault } = await unlockedVault();
    await vault.putRecord('canary', 'x', { i: 0 }, { contentType: 'json' });
    await Promise.all([
      vault.putRecord('canary', 'y', { i: 1 }, { contentType: 'json' }),
      vault.deleteRecord('canary', 'x'),
    ]);
    expect(db.manifest().generation).toBe(4); // create + put + (put|delete) + (delete|put)
    expect(await vault.listRecords('canary')).toEqual(['y']);
  });

  test('a failing mutation does not poison the queue', async () => {
    const { db, vault } = await unlockedVault();
    await expect(vault.putRecord('settings', 'k', { i: 1 }, { contentType: 'json' })).rejects.toThrow();
    await vault.putRecord('canary', 'after', { i: 2 }, { contentType: 'json' });
    expect(db.record('canary', 'after')).toBeDefined();
  });
});

describe('bounded atomic record transactions (US-008)', () => {
  test('mixed puts/deletes commit together and bump the manifest exactly once', async () => {
    const { db, vault } = await unlockedVault();
    await vault.putRecord('canary', 'delete-me', { old: true }, { contentType: 'json' });
    await vault.putRecord('canary', 'update-me', { version: 1 }, { contentType: 'json' });
    const genBefore = db.manifest().generation;

    const result = await vault.transactionRecords('canary', [
      { op: 'put', recordKey: 'new', value: { synthetic: true }, contentType: 'json' },
      { op: 'put', recordKey: 'update-me', value: { version: 2 }, contentType: 'json' },
      { op: 'delete', recordKey: 'delete-me' },
    ]);

    expect(result).toEqual({ applied: 3, puts: 2, deletes: 1 });
    expect(db.manifest().generation).toBe(genBefore + 1);
    expect((await vault.getRecord('canary', 'new')).value).toEqual({ synthetic: true });
    expect((await vault.getRecord('canary', 'update-me')).recordVersion).toBe(2);
    expect(await vault.getRecord('canary', 'delete-me')).toBeUndefined();
  });

  test('a failure at any write rolls back every record and the manifest bump', async () => {
    const { db, vault } = await unlockedVault();
    const genBefore = db.manifest().generation;
    db.failOn = (ns, key) => ns === 'canary' && key === 'second';
    await expect(vault.transactionRecords('canary', [
      { op: 'put', recordKey: 'first', value: 1 },
      { op: 'put', recordKey: 'second', value: 2 },
      { op: 'put', recordKey: 'third', value: 3 },
    ])).rejects.toThrow();
    expect(await vault.listRecords('canary')).toEqual([]);
    expect(db.manifest().generation).toBe(genBefore);
  });

  test('empty, oversized, duplicate-key and product-namespace batches fail closed', async () => {
    const { vault } = await unlockedVault();
    expect(await codeOf(vault.transactionRecords('canary', []))).toBe(Codes.RECORD_INVALID);
    expect(await codeOf(vault.transactionRecords('canary', [
      { op: 'delete', recordKey: 'same' },
      { op: 'put', recordKey: 'same', value: 1 },
    ]))).toBe(Codes.RECORD_INVALID);
    expect(await codeOf(vault.transactionRecords('canary', [
      { op: 'delete', recordKey: '' },
    ]))).toBe(Codes.RECORD_INVALID);
    expect(await codeOf(vault.transactionRecords('canary', [
      { op: 'put', recordKey: 'k', value: 1, contentType: 'xml' },
    ]))).toBe(Codes.RECORD_INVALID);
    expect(await codeOf(vault.transactionRecords(
      'canary', Array.from({ length: 129 }, (_, i) => ({ op: 'delete', recordKey: `k${i}` })),
    ))).toBe(Codes.RECORD_INVALID);
    expect(await codeOf(vault.transactionRecords('settings', [
      { op: 'put', recordKey: 'k', value: 1 },
    ]))).toBe(Codes.NAMESPACE_UNSUPPORTED);
  });
});

describe('AAD anti-swap and corruption (§13 rows: AAD tampering, corruption)', () => {
  test('a valid record copied to another key fails authentication', async () => {
    const { db, vault } = await unlockedVault();
    await vault.putRecord('canary', 'origin', { s: 'x' }, { contentType: 'json' });
    // Copy the intact envelope under a different key — the AAD binds `k`.
    db._store('canary').set('copy', deepClone(db.record('canary', 'origin')));
    expect(await codeOf(vault.getRecord('canary', 'copy'))).toBe(Codes.RECORD_INVALID);
    // The original is still readable: the swap did not damage anything.
    expect((await vault.getRecord('canary', 'origin')).value).toEqual({ s: 'x' });
  });

  test('a record made self-consistent under a NEW key still fails GCM: the AAD binds the REQUEST', async () => {
    // The previous test is stopped by the ns/key guard before any decryption.
    // Here the envelope is rewritten so `k` matches the new location, so the
    // guard passes and the real property is exercised: the AAD is rebuilt from
    // the REQUESTED key (§6 binding read-side rule) while the ciphertext was
    // authenticated under the original one.
    const { db, vault } = await unlockedVault();
    await vault.putRecord('canary', 'origin', { s: 'x' }, { contentType: 'json' });
    const moved = deepClone(db.record('canary', 'origin'));
    moved.k = 'copy';
    db._store('canary').set('copy', moved);
    expect(await codeOf(vault.getRecord('canary', 'copy'))).toBe(Codes.RECORD_CORRUPTED);
    expect((await vault.getRecord('canary', 'origin')).value).toEqual({ s: 'x' });
  });

  test('a bit-flip in the ciphertext → VAULT_RECORD_CORRUPTED, other records still readable', async () => {
    const { db, vault } = await unlockedVault();
    await vault.putRecord('canary', 'victim', { s: 'v' }, { contentType: 'json' });
    await vault.putRecord('canary', 'bystander', { s: 'b' }, { contentType: 'json' });
    db.record('canary', 'victim').data[0] ^= 0xff;
    expect(await codeOf(vault.getRecord('canary', 'victim'))).toBe(Codes.RECORD_CORRUPTED);
    expect((await vault.getRecord('canary', 'bystander')).value).toEqual({ s: 'b' });
    // The corrupted record is NOT auto-deleted (spec §11 recovery table).
    expect(await vault.listRecords('canary')).toContain('victim');
  });

  test('a bit-flip in the nonce → VAULT_RECORD_CORRUPTED', async () => {
    const { db, vault } = await unlockedVault();
    await vault.putRecord('canary', 'k', { s: 'x' }, { contentType: 'json' });
    db.record('canary', 'k').nonce[0] ^= 0xff;
    expect(await codeOf(vault.getRecord('canary', 'k'))).toBe(Codes.RECORD_CORRUPTED);
  });

  test('nonce uniqueness across many writes', async () => {
    const { db, vault } = await unlockedVault();
    const seen = new Set();
    for (let i = 0; i < 64; i += 1) {
      // eslint-disable-next-line no-await-in-loop
      await vault.putRecord('canary', `n:${i}`, { i }, { contentType: 'json' });
      seen.add(db.record('canary', `n:${i}`).nonce.join(','));
    }
    expect(seen.size).toBe(64);
  });
});

describe('manifest generation tracks every committed transaction (§11)', () => {
  test('each write bumps generation; reads do not', async () => {
    const { db, vault } = await unlockedVault();
    expect(db.manifest().generation).toBe(1); // creation
    await vault.putRecord('canary', 'a', { i: 1 }, { contentType: 'json' });
    expect(db.manifest().generation).toBe(2);
    await vault.putRecord('canary', 'b', { i: 2 }, { contentType: 'json' });
    expect(db.manifest().generation).toBe(3);
    await vault.getRecord('canary', 'a');
    await vault.listRecords('canary');
    expect(db.manifest().generation).toBe(3); // reads are not commits
    await vault.deleteRecord('canary', 'a');
    expect(db.manifest().generation).toBe(4);
  });

  test('the manifest still verifies after record writes (reopen and unlock)', async () => {
    const { db, vault } = await unlockedVault();
    await vault.putRecord('canary', 'a', { i: 1 }, { contentType: 'json' });
    const reopened = makeVault(db);
    expect((await reopened.unlock(PW)).state).toBe(VAULT_STATES.UNLOCKED);
    expect((await reopened.getRecord('canary', 'a')).value).toEqual({ i: 1 });
  });

  test('a record write and its manifest bump are one atomic transaction', async () => {
    const { db, vault } = await unlockedVault();
    const genBefore = db.manifest().generation;
    db.failOn = (ns, key) => ns === 'meta' && key === 'manifest'; // crash on the manifest write
    await expect(vault.putRecord('canary', 'atomic', { i: 1 }, { contentType: 'json' })).rejects.toThrow();
    // Neither the record nor the bump survived.
    expect(db.record('canary', 'atomic')).toBeUndefined();
    expect(db.manifest().generation).toBe(genBefore);
  });
});

describe('factory reset follows the §12 order', () => {
  test('the wrapper is overwritten BEFORE the database is deleted', async () => {
    const { db, vault } = await unlockedVault();
    await vault.putRecord('canary', 'doomed', { s: 1 }, { contentType: 'json' });
    const order = [];
    const realTransaction = db.transaction.bind(db);
    db.transaction = async (ns, cb) => { order.push('overwrite-wrapper'); return realTransaction(ns, cb); };
    const realDestroy = db.destroy.bind(db);
    db.destroy = async () => { order.push('delete-database'); return realDestroy(); };
    await vault.destroy();
    // If the cleanup failed after step 2, the leftover ciphertext would have
    // no active wrapper — that is the whole point of the ordering (§12).
    expect(order).toEqual(['overwrite-wrapper', 'delete-database']);
  });

  test('reset works from LOCKED as well (§3 "any → DESTROYING")', async () => {
    const { db } = await unlockedVault();
    const locked = makeVault(db); // fresh instance over the same db
    expect((await locked.status()).state).toBe(VAULT_STATES.LOCKED);
    expect((await locked.destroy()).state).toBe(VAULT_STATES.UNINITIALIZED);
    expect(db.destroyed).toBe(1);
  });

  test('after a reset no key material remains usable', async () => {
    const { db, vault } = await unlockedVault();
    await vault.putRecord('canary', 'k', { i: 1 }, { contentType: 'json' });
    await vault.destroy();
    // Step 1 of §12 wiped the keys: every keyed operation is refused.
    expect(await codeOf(vault.getRecord('canary', 'k'))).toBe(Codes.WRONG_STATE);
    expect(await codeOf(vault.putRecord('canary', 'k', { i: 2 }, { contentType: 'json' }))).toBe(Codes.WRONG_STATE);
  });

  test('a reset vault reopens as UNINITIALIZED even if the deletion left the store behind', async () => {
    const { db, vault } = await unlockedVault();
    db.destroy = async () => { db.destroyed += 1; }; // deletion silently does nothing
    await vault.destroy();
    // The wrapper was overwritten first, so no vault can be opened.
    expect(db.wrapper()).toBeNull();
    expect((await makeVault(db).status()).state).toBe(VAULT_STATES.UNINITIALIZED);
  });
});

describe('schemaVersion as a signed high-water mark', () => {
  test('a keyless upgrade while locked is reconciled at the next unlock', async () => {
    const { db, vault } = await unlockedVault({ version: 1 });
    expect(db.manifest().schemaVersion).toBe(1);
    await vault.lock();
    db.version = 2; // an upgrade ran at open time, keyless
    const reopened = makeVault(db);
    const genBefore = db.manifest().generation;
    expect((await reopened.unlock(PW)).state).toBe(VAULT_STATES.UNLOCKED);
    expect(db.manifest().schemaVersion).toBe(2); // re-signed
    expect(db.manifest().generation).toBe(genBefore + 1); // the reconcile is a commit
    // And the re-signed manifest verifies on a further unlock.
    await reopened.lock();
    expect((await makeVault(db).unlock(PW)).state).toBe(VAULT_STATES.UNLOCKED);
  });

  test('a database older than the signed marker fails closed', async () => {
    // Created at schema 2, so the SIGNED manifest says 2...
    const { db, vault } = await unlockedVault({ version: 2 });
    expect(db.manifest().schemaVersion).toBe(2);
    await vault.lock();
    db.version = 1; // ...but the database came back at 1: a rollback.
    const reopened = makeVault(db);
    const err = await codeOf(reopened.unlock(PW));
    expect(err).toBe(Codes.MANIFEST_TAMPERED);
    expect((await reopened.status()).state).toBe(VAULT_STATES.LOCKED); // non-destructive
  });

  test('an unchanged schema version neither re-signs nor bumps', async () => {
    const { db, vault } = await unlockedVault({ version: 1 });
    await vault.lock();
    const genBefore = db.manifest().generation;
    await makeVault(db).unlock(PW);
    expect(db.manifest().generation).toBe(genBefore);
  });
});
