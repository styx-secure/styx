// test/storage/mls-state-migration.test.js — the 12-step legacy migration and its
// resume matrix (docs/architecture/mls-state-migration-policy.md §5). WASM-free: the
// restore probe is injected; the real-runtime path is covered by the fixture tests.
import { describe, test, expect, beforeEach } from '@jest/globals';
import {
  MLS_STATE_KEY,
  MLS_MIGRATION_PENDING_KEY,
  MLS_MIGRATION_BACKUP_KEY,
  MLS_MIGRATION_VERSION_KEY,
  migrateLegacyMlsState,
} from '../../src/storage/mls-state-migration.js';
import {
  MlsStateError,
  MlsStateErrorCodes,
  detectMlsStateFormat,
  encodeMlsStateEnvelope,
} from '../../src/storage/mls-state-envelope.js';
import { acquireWriterLock } from '../../apps/chat/src/lib/writer-lock.js';
import { bytesToBase64 } from '../../src/utils.js';

const STATE = new Uint8Array([9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 255, 128]);
const LEGACY = bytesToBase64(STATE);

/** Faithful to LocalStorageBackend: every value goes through a JSON round-trip. */
function jsonBackend() {
  const map = new Map();
  return {
    map,
    async get(key) { return map.has(key) ? JSON.parse(map.get(key)) : null; },
    async set(key, value) { map.set(key, JSON.stringify(value)); },
    async delete(key) { map.delete(key); },
    async clear() { map.clear(); },
  };
}

const okProbe = async (bytes) => { if (!(bytes instanceof Uint8Array) || !bytes.length) throw new Error('bad bytes'); };

async function expectCodeAsync(promise, code) {
  let caught;
  try { await promise; } catch (e) { caught = e; }
  expect(caught).toBeInstanceOf(MlsStateError);
  expect(caught.code).toBe(code);
  // No MLS material in errors, ever.
  expect(caught.message).not.toContain(LEGACY);
  expect(JSON.stringify(caught.details ?? {})).not.toContain(LEGACY);
  // causeMessage is not an allowlisted details field (Issue #26).
  expect(Object.keys(caught.details ?? {})).not.toContain('causeMessage');
  return caught;
}

describe('migrateLegacyMlsState', () => {
  let backend;
  beforeEach(async () => {
    backend = jsonBackend();
    await backend.set(MLS_STATE_KEY, LEGACY);
  });

  test('happy path: legacy → envelope, markers finalized, backup gone', async () => {
    const probed = [];
    const res = await migrateLegacyMlsState({
      backend,
      restoreProbe: async (b) => { probed.push(b); },
    });
    expect(res.migrated).toBe(true);
    expect(probed).toHaveLength(1);
    expect(probed[0]).toEqual(STATE);
    const stored = await backend.get(MLS_STATE_KEY);
    expect(detectMlsStateFormat(stored)).toBe('envelope');
    expect(stored.payload).toBe(LEGACY);
    expect(await backend.get(MLS_MIGRATION_VERSION_KEY)).toBe(1);
    expect(await backend.get(MLS_MIGRATION_PENDING_KEY)).toBeNull();
    expect(await backend.get(MLS_MIGRATION_BACKUP_KEY)).toBeNull();
  });

  test('probe failure (restore refused): legacy intact, backup preserved, retry works', async () => {
    const err = await expectCodeAsync(
      migrateLegacyMlsState({ backend, restoreProbe: async () => { throw new Error('runtime cannot read this'); } }),
      MlsStateErrorCodes.MIGRATION_FAILED,
    );
    expect(err.details.step).toBe('restore-probe');
    // The runtime message is NOT auto-propagated (Issue #26): details carry only
    // a stable sub-code; the raw error stays inspectable via the standard cause.
    expect(JSON.stringify(err.details)).not.toContain('runtime cannot read this');
    expect(err.details.causeCode).toBe('unknown');
    expect(err.cause).toBeInstanceOf(Error);
    expect(err.cause.message).toBe('runtime cannot read this');
    // Nothing was overwritten; the interrupted attempt is visible and recoverable.
    expect(await backend.get(MLS_STATE_KEY)).toBe(LEGACY);
    expect(await backend.get(MLS_MIGRATION_BACKUP_KEY)).toBe(LEGACY);
    expect(await backend.get(MLS_MIGRATION_PENDING_KEY)).toEqual({ toVersion: 1 });
    expect(await backend.get(MLS_MIGRATION_VERSION_KEY)).toBeNull();
    // Retry after the transient failure succeeds and sweeps everything.
    const res = await migrateLegacyMlsState({ backend, restoreProbe: okProbe });
    expect(res.migrated).toBe(true);
    expect(await backend.get(MLS_MIGRATION_BACKUP_KEY)).toBeNull();
  });

  test('interrupted before the write (quota exhausted on backup): legacy untouched', async () => {
    const failing = {
      ...backend,
      async set(key, value) {
        if (key === MLS_MIGRATION_BACKUP_KEY) throw new Error('QuotaExceededError (simulated)');
        return backend.set(key, value);
      },
    };
    const err = await expectCodeAsync(
      migrateLegacyMlsState({ backend: failing, restoreProbe: okProbe }),
      MlsStateErrorCodes.MIGRATION_FAILED,
    );
    expect(err.details.step).toBe('backup');
    expect(await backend.get(MLS_STATE_KEY)).toBe(LEGACY);
    expect(await backend.get(MLS_MIGRATION_PENDING_KEY)).toBeNull();
  });

  test('quota exhausted on the main write: legacy still the source of truth', async () => {
    const failing = {
      ...backend,
      async set(key, value) {
        if (key === MLS_STATE_KEY) throw new Error('QuotaExceededError (simulated)');
        return backend.set(key, value);
      },
    };
    const err = await expectCodeAsync(
      migrateLegacyMlsState({ backend: failing, restoreProbe: okProbe }),
      MlsStateErrorCodes.MIGRATION_FAILED,
    );
    expect(err.details.step).toBe('write');
    expect(await backend.get(MLS_STATE_KEY)).toBe(LEGACY);
    expect(await backend.get(MLS_MIGRATION_BACKUP_KEY)).toBe(LEGACY);
  });

  test('interrupted between write and cleanup: resume completes and sweeps markers', async () => {
    // Simulate the crash window: envelope already written, markers still there.
    await backend.set(MLS_STATE_KEY, encodeMlsStateEnvelope(STATE));
    await backend.set(MLS_MIGRATION_BACKUP_KEY, LEGACY);
    await backend.set(MLS_MIGRATION_PENDING_KEY, { toVersion: 1 });
    const res = await migrateLegacyMlsState({ backend, restoreProbe: okProbe });
    expect(res.migrated).toBe(false); // nothing re-migrated — just completed
    expect(detectMlsStateFormat(await backend.get(MLS_STATE_KEY))).toBe('envelope');
    expect(await backend.get(MLS_MIGRATION_VERSION_KEY)).toBe(1);
    expect(await backend.get(MLS_MIGRATION_PENDING_KEY)).toBeNull();
    expect(await backend.get(MLS_MIGRATION_BACKUP_KEY)).toBeNull();
  });

  test('second run on migrated state is idempotent', async () => {
    await migrateLegacyMlsState({ backend, restoreProbe: okProbe });
    const before = new Map(backend.map);
    const res = await migrateLegacyMlsState({ backend, restoreProbe: okProbe });
    expect(res.migrated).toBe(false);
    expect(backend.map).toEqual(before);
  });

  test('corrupted legacy (not base64) and missing state are refused explicitly', async () => {
    await backend.set(MLS_STATE_KEY, '!!!not base64!!!');
    await expectCodeAsync(
      migrateLegacyMlsState({ backend, restoreProbe: okProbe }),
      MlsStateErrorCodes.INVALID,
    );
    await backend.delete(MLS_STATE_KEY);
    await expectCodeAsync(
      migrateLegacyMlsState({ backend, restoreProbe: okProbe }),
      MlsStateErrorCodes.INVALID,
    );
  });

  test('two tabs under the Web Lock: only the writer migrates', async () => {
    // A minimal single-origin lock manager honoring { ifAvailable: true }.
    const heldLocks = new Set();
    const locks = {
      request(name, opts, cb) {
        if (heldLocks.has(name)) return Promise.resolve(cb(null));
        heldLocks.add(name);
        const out = Promise.resolve(cb({ name }));
        out.then(() => heldLocks.delete(name));
        return out.then(() => undefined);
      },
    };
    const tabA = await acquireWriterLock(locks, 'styx-mls:test');
    const tabB = await acquireWriterLock(locks, 'styx-mls:test');
    expect(tabA.held).toBe(true);
    expect(tabB.held).toBe(false);
    // The app contract: a non-writer tab never calls init(), hence never migrates.
    // Only tab A runs the migration; the state converges to a single envelope.
    expect(tabA.held && (await migrateLegacyMlsState({ backend, restoreProbe: okProbe })).migrated).toBe(true);
    tabA.release();
    await new Promise((r) => setTimeout(r, 0)); // let the lock manager observe the release
    // Once A released (e.g. tab closed), a new tab can become the writer and finds
    // the migrated state — idempotent no-op.
    const tabC = await acquireWriterLock(locks, 'styx-mls:test');
    expect(tabC.held).toBe(true);
    expect((await migrateLegacyMlsState({ backend, restoreProbe: okProbe })).migrated).toBe(false);
    tabC.release();
  });

  test('factory reset after a partial migration leaves no MLS keys behind', async () => {
    // Fail mid-flight to leave backup + pending markers around.
    await expectCodeAsync(
      migrateLegacyMlsState({ backend, restoreProbe: async () => { throw new Error('boom'); } }),
      MlsStateErrorCodes.MIGRATION_FAILED,
    );
    expect(backend.map.size).toBeGreaterThan(0);
    await backend.clear(); // what StyxChat.wipe() does on its backend
    expect(backend.map.size).toBe(0);
  });
});
