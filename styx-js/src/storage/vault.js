// vault.js — vault lifecycle state machine (Blocco 3, PR-5 / US-006, US-008).
// Pure factory `createVault({ db, deriveKek, randomBytes, todayIso })`: it owns
// the §3 state machine and the seven lifecycle operations, orchestrating the
// FROZEN PR-2 wrapper/manifest modules and the PR-4 IndexedDB engine. US-008
// assembles this factory inside the dedicated worker without changing those
// frozen persisted interfaces.
//
// Root Storage Key confinement (spec §4): the Root Key is 32 random bytes
// generated HERE, held in memory ONLY while UNLOCKED, wrapped/unwrapped through
// the existing module, and NEVER returned by an operation, exposed in status,
// or logged. `deriveKek` only ever produces the KEK — it never sees the Root
// Key. `lock()` is a best-effort `fill(0)` + drop of references (JS/WASM cannot
// guarantee physical erasure — the UI must not promise more).
//
// No-oracle (spec §16.8): inherited from the module. `parseVaultWrapper`
// rejects a malformed FORM with VAULT_WRAPPER_INVALID BEFORE any derivation
// (the form is public); `unwrapSyntheticRootKey` maps every GCM failure to the
// SAME VAULT_WRONG_PASSWORD. This module adds no distinguishing signal and
// keeps no persisted attempt counter. Manifest verification runs only AFTER a
// successful unwrap, so it is not a password oracle.
//
// Persisted layout (FROZEN by the §16.13 irreversible-contract gate at merge):
// the `meta` store holds two keys — `wrapper` (the active wrapper v1, whose
// `.rewrapPending` is null or the single depth-1 pending wrapper of an in-flight
// re-wrap, spec §7.2; deliberately OUTSIDE the wrapper AAD) and `manifest` (the
// integrity manifest v1, spec §11: schema/migration versions, a monotone
// generation counter and lastTxId, HMAC-signed under K_manifest).

import { VaultCryptoError, VaultCryptoErrorCodes as Codes } from '../crypto/vault-errors.js';
import {
  wrapSyntheticRootKey, unwrapSyntheticRootKey, parseVaultWrapper,
  ROOT_KEY_BYTES, KEK_BYTES,
} from './vault-wrapper.js';
import {
  deriveManifestKey, deriveNamespaceKey, signManifestBytes, verifyManifestBytes, VAULT_KEY_VERSION,
} from '../crypto/vault-keys.js';
import {
  encryptVaultRecord, decryptVaultRecord, CONTENT_TYPES, MAX_RECORD_KEY_CHARS,
} from './vault-record.js';
import { buildManifestCanonicalBytes, encodeBase64, decodeCanonicalBase64 } from '../crypto/vault-aad.js';
import { KDF_PROFILES, KDF_POLICY } from '../crypto/kdf-bounds.js';
import { constantTimeEqual, uuidv4 } from '../utils.js';
import { snapshotStrictPlainObject } from '../crypto/vault-shape.js';
import {
  SETTINGS_NAMESPACE, SETTINGS_RECORD_KEY, SETTINGS_MARKER_KEY, SETTINGS_CONTENT_TYPE,
  SettingsMigrationError, validateSettingsPreferences, validateSettingsMarker,
  buildSettingsMarker, canonicalSettingsBytes, settingsEqual,
} from './vault-migration.js';

export const VAULT_STATES = Object.freeze({
  UNINITIALIZED: 'UNINITIALIZED',
  LOCKED: 'LOCKED',
  UNLOCKING: 'UNLOCKING',
  UNLOCKED: 'UNLOCKED',
  LOCKING: 'LOCKING',
  RECOVERING: 'RECOVERING',
  DESTROYING: 'DESTROYING',
  ERROR: 'ERROR',
  // Transient state while the settings migration commits and verifies.
  MIGRATING: 'MIGRATING',
});

const META_STORE = 'meta';
const WRAPPER_KEY = 'wrapper'; // FROZEN §16.13
const MANIFEST_KEY = 'manifest'; // FROZEN §16.13
const SALT_BYTES = KDF_POLICY.saltLen; // 16
export const DEFAULT_VAULT_PROFILE = 'desktop';

// Manifest v1 constants (spec §11), frozen at the gate.
const MANIFEST_FORMAT = 'styx-vault-manifest';
const MANIFEST_VERSION = 1;
const MIGRATION_VERSION = 1; // no migration has run for a fresh vault

/**
 * Namespaces this build may read or write (plan B3.6 gate). The canary holds
 * synthetic records only; the product namespaces open one at a time in the
 * later stories, so the gate is enforced here mechanically rather than by
 * convention. `deriveNamespaceKey` knows the full list — this is deliberately
 * narrower.
 */
export const ENABLED_NAMESPACES = Object.freeze(['canary', SETTINGS_NAMESPACE]);

// Password policy (plan §B3.0.4): 8–1024 characters.
const PASSWORD_MIN = 8;
const PASSWORD_MAX = 1024;
const MAX_TRANSACTION_OPERATIONS = 128;
const RECORD_KEY_CONTROL_CHARS = /[\u0000-\u001F\u007F]/;

const wrongState = (message, details) => new VaultCryptoError(Codes.WRONG_STATE, message, details);

const isSafeInt = (x) => typeof x === 'number' && Number.isSafeInteger(x);

function assertPasswordPolicy(password) {
  if (typeof password !== 'string' || password.length < PASSWORD_MIN || password.length > PASSWORD_MAX) {
    throw new VaultCryptoError(Codes.KDF_PARAMS_INVALID, 'password must be 8–1024 characters', { reason: 'password-length' });
  }
}

/** UTC calendar date for the wrapper's `createdAt` (YYYY-MM-DD). */
function defaultTodayIso(date) {
  const y = date.getUTCFullYear();
  const m = String(date.getUTCMonth() + 1).padStart(2, '0');
  const d = String(date.getUTCDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

/**
 * @param {object} deps
 * @param {import('./vault-db.js').VaultDb} deps.db opened US-005 engine
 * @param {(passwordBytes: Uint8Array, params: {salt: Uint8Array, mKib: number,
 *   t: number, p: number, outLen: number}) => Promise<Uint8Array>} deps.deriveKek
 *   Argon2id-backed KEK derivation — it NEVER sees the Root Key
 * @param {(n: number) => Uint8Array} [deps.randomBytes]
 * @param {() => string} [deps.todayIso]
 */
export function createVault({
  db,
  deriveKek,
  randomBytes = (n) => crypto.getRandomValues(new Uint8Array(n)),
  todayIso = () => defaultTodayIso(new Date()),
}) {
  if (db == null) throw new VaultCryptoError(Codes.CRYPTO_FAILED, 'a vault-db is required', { field: 'db' });
  if (typeof deriveKek !== 'function') {
    throw new VaultCryptoError(Codes.CRYPTO_FAILED, 'deriveKek must be injected', { field: 'deriveKek' });
  }

  let state = null; // null until first load; then a VAULT_STATES value
  let rootKey = null; // Uint8Array(32) ONLY while UNLOCKED
  let generation = 0; // current manifest generation while UNLOCKED
  let schemaVersion = 0; // signed high-water mark while UNLOCKED
  let loadPromise = null;
  const utf8 = new TextEncoder();
  // Subkeys derived from the in-memory Root Key. Caching them is no weaker
  // than holding the Root Key they come from, and it keeps a record write to a
  // single HMAC. Both are released together with the Root Key on lock/destroy.
  let manifestKeyCache = null;
  const namespaceKeys = new Map();
  // Bumped by every wipe. A subkey derivation that was in flight across a
  // lock/destroy must not install its result into a cache that was just
  // cleared, so derivations check the epoch they started in.
  let sessionEpoch = 0;

  // Every MUTATING operation runs through this queue. Without it, two
  // concurrent writes would both read the same `rv`/`generation` before their
  // (asynchronous) encryption and then commit in either order — losing a write
  // and breaking the monotonicity of both counters. The Web Lock elects a
  // single writer ACROSS TABS; this serializes calls WITHIN one instance.
  let mutationQueue = Promise.resolve();
  const serialize = (fn) => {
    const result = mutationQueue.then(fn);
    mutationQueue = result.then(() => {}, () => {}); // a failure must not poison the queue
    return result;
  };

  const paramsFor = (profileName) => {
    const profile = KDF_PROFILES[profileName];
    if (profile == null) {
      throw new VaultCryptoError(Codes.KDF_PARAMS_INVALID, 'unknown kdf profile', { field: 'profile' });
    }
    return { profile: profileName, ...profile, outLen: KDF_POLICY.outLen };
  };

  const wipeRootKey = () => {
    if (rootKey !== null) { rootKey.fill(0); rootKey = null; }
    generation = 0;
    schemaVersion = 0;
    // CryptoKeys cannot be zeroized; dropping the references is the best
    // effort available (spec §4 says as much for the Root Key itself).
    manifestKeyCache = null;
    namespaceKeys.clear();
    sessionEpoch += 1; // invalidate derivations that are still in flight
  };

  /** Install a freshly derived subkey only if this session is still the one that asked for it. */
  const stillCurrent = (epoch) => epoch === sessionEpoch && rootKey !== null;

  const manifestKey = async () => {
    if (manifestKeyCache !== null) return manifestKeyCache;
    const epoch = sessionEpoch;
    const derived = await deriveManifestKey(rootKey, VAULT_KEY_VERSION);
    if (!stillCurrent(epoch)) {
      throw wrongState('the vault was locked while deriving', { reason: 'session-ended' });
    }
    manifestKeyCache = derived;
    return derived;
  };

  const assertUnlocked = (what) => {
    if (state !== VAULT_STATES.UNLOCKED) {
      throw wrongState(`the vault must be unlocked to ${what}`, { reason: `state:${state}` });
    }
  };

  const assertCanaryNamespace = (namespace) => {
    if (namespace !== 'canary') {
      throw new VaultCryptoError(Codes.NAMESPACE_UNSUPPORTED, 'namespace not enabled in this build', { namespace: typeof namespace === 'string' ? namespace : 'invalid' });
    }
  };

  const assertReadableRecord = (namespace, recordKey) => {
    if (namespace === 'canary') return;
    if (namespace === SETTINGS_NAMESPACE && recordKey === SETTINGS_RECORD_KEY) return;
    throw new VaultCryptoError(Codes.NAMESPACE_UNSUPPORTED, 'record is not readable in this build', { namespace: typeof namespace === 'string' ? namespace : 'invalid' });
  };

  const assertTransactionRecordKey = (recordKey) => {
    const valid = typeof recordKey === 'string'
      && recordKey.length >= 1
      && recordKey.length <= MAX_RECORD_KEY_CHARS
      && recordKey.isWellFormed()
      && !RECORD_KEY_CONTROL_CHARS.test(recordKey);
    if (!valid) {
      throw new VaultCryptoError(Codes.RECORD_INVALID, 'transaction record key is invalid', { field: 'recordKey' });
    }
  };

  const namespaceKeyFor = async (namespace) => {
    if (namespaceKeys.has(namespace)) return namespaceKeys.get(namespace);
    const epoch = sessionEpoch;
    const derived = await deriveNamespaceKey(rootKey, namespace, VAULT_KEY_VERSION);
    if (!stillCurrent(epoch)) {
      throw wrongState('the vault was locked while deriving', { reason: 'session-ended' });
    }
    namespaceKeys.set(namespace, derived);
    return derived;
  };

  // Build a signed manifest v1 record. K_manifest comes from the in-memory
  // Root Key, so this only runs while unlocked.
  const buildManifest = async (gen, schema) => {
    const fields = {
      format: MANIFEST_FORMAT,
      version: MANIFEST_VERSION,
      schemaVersion: schema,
      migrationVersion: MIGRATION_VERSION,
      generation: gen,
      lastTxId: uuidv4(),
    };
    const mac = await signManifestBytes(await manifestKey(), buildManifestCanonicalBytes(fields));
    return { ...fields, hmacB64: encodeBase64(mac) };
  };

  // Settings have only six possible values, so an unkeyed SHA-256 marker
  // would disclose them by enumeration. Reuse the existing K_manifest HMAC
  // primitive: no new key, label or format, and the marker remains bounded.
  const settingsMarkerDigest = async (value) => {
    const bytes = canonicalSettingsBytes(value);
    let mac;
    try {
      mac = await signManifestBytes(await manifestKey(), bytes);
      return [...mac].map((b) => b.toString(16).padStart(2, '0')).join('');
    } finally {
      bytes.fill(0);
      mac?.fill(0);
    }
  };

  // Verify a stored manifest against K_manifest. Runs after a successful
  // unwrap, so it is a post-unlock integrity check, not a password oracle.
  const verifyManifest = async (stored) => {
    if (stored === null || typeof stored !== 'object'
      || stored.format !== MANIFEST_FORMAT || stored.version !== MANIFEST_VERSION) {
      return { ok: false };
    }
    const mac = typeof stored.hmacB64 === 'string' ? decodeCanonicalBase64(stored.hmacB64) : null;
    if (mac === null) return { ok: false };
    let canonical;
    try {
      canonical = buildManifestCanonicalBytes(stored); // throws on any bad field type
    } catch { return { ok: false }; }
    try {
      // verifyManifestBytes returns true or THROWS on any deviation (one code).
      await verifyManifestBytes(await manifestKey(), canonical, mac);
    } catch { return { ok: false }; }
    return { ok: true, generation: stored.generation, schemaVersion: stored.schemaVersion };
  };

  // Read the persisted wrapper once and settle the initial state, running the
  // keyless RECOVERING sweep for an orphan pending (crash mid re-wrap).
  const load = async () => {
    const stored = await db.get(META_STORE, WRAPPER_KEY);
    if (stored == null) { state = VAULT_STATES.UNINITIALIZED; return; }
    let parsed;
    try {
      parsed = parseVaultWrapper(stored); // validates form + depth-1 pending
    } catch (e) {
      // A structurally broken wrapper is an unrecoverable open: fail closed.
      state = VAULT_STATES.ERROR;
      throw e instanceof VaultCryptoError ? e
        : new VaultCryptoError(Codes.WRAPPER_INVALID, 'stored wrapper is unreadable');
    }
    if (parsed.rewrapPending != null) {
      // Keyless recovery (spec §7.2): completing the re-wrap needs the new KEK,
      // which we do not have here. The active wrapper still unlocks with the
      // old password, so DISCARD the orphan pending; the user re-runs
      // CHANGE_PASSWORD. A single write, then LOCKED. The manifest is untouched
      // (the re-wrap never committed, so its generation never bumped).
      state = VAULT_STATES.RECOVERING;
      const cleaned = { ...stored, rewrapPending: null };
      await db.transaction([META_STORE], (ops) => ops.put(META_STORE, WRAPPER_KEY, cleaned));
    }
    state = VAULT_STATES.LOCKED;
  };

  const ensureLoaded = () => {
    if (loadPromise === null) loadPromise = load();
    return loadPromise;
  };

  // Shared re-wrap orchestration (spec §7.2): the Root Key never changes and no
  // records are re-encrypted. Atomic and resumable — at every instant at least
  // one working wrapper is persisted. The commit bumps the manifest generation
  // in the same transaction.
  const doRewrap = async (password, profileName) => {
    assertPasswordPolicy(password);
    const params = paramsFor(profileName);
    const salt = randomBytes(SALT_BYTES);
    const pw = utf8.encode(password);
    let kek = null;
    let verifyKey = null;
    try {
      kek = await deriveKek(pw, { salt, mKib: params.mKib, t: params.t, p: params.p, outLen: params.outLen });
      if (!(kek instanceof Uint8Array) || kek.length !== KEK_BYTES) {
        throw new VaultCryptoError(Codes.CRYPTO_FAILED, 'deriveKek returned an unexpected key');
      }
      const pending = await wrapSyntheticRootKey({
        kek, rootKey, salt, mKib: params.mKib, t: params.t, p: params.p,
        profile: params.profile, createdAt: todayIso(), calibratedMs: 0,
      });
      // Stage the pending inside the active wrapper (rewrapPending is out of
      // the AAD, so the active wrapper still unlocks). One write.
      const active = await db.get(META_STORE, WRAPPER_KEY);
      await db.transaction([META_STORE], (ops) => ops.put(META_STORE, WRAPPER_KEY, { ...active, rewrapPending: pending }));
      // Verify the pending decrypts to the SAME Root Key before making it live.
      verifyKey = await unwrapSyntheticRootKey(pending, kek);
      if (!constantTimeEqual(verifyKey, rootKey)) {
        // Should be unreachable (we just wrapped this Root Key); fail closed
        // and leave the active wrapper untouched — recovery discards the pending.
        throw new VaultCryptoError(Codes.CRYPTO_FAILED, 're-wrap verification mismatch');
      }
      // Atomic commit: the new wrapper becomes active (pending null) and the
      // manifest generation bumps — one transaction, one commit.
      const nextGen = generation + 1;
      const manifest = await buildManifest(nextGen, schemaVersion);
      await db.transaction([META_STORE], (ops) => {
        ops.put(META_STORE, WRAPPER_KEY, pending);
        ops.put(META_STORE, MANIFEST_KEY, manifest);
      });
      generation = nextGen;
    } finally {
      if (kek !== null) kek.fill(0);
      if (verifyKey !== null) verifyKey.fill(0);
      pw.fill(0);
    }
  };

  const api = {
    /** Create a new empty vault. Only from UNINITIALIZED. */
    async createVault(password, { profile = DEFAULT_VAULT_PROFILE } = {}) {
      await ensureLoaded();
      if (state !== VAULT_STATES.UNINITIALIZED) {
        throw wrongState('a vault already exists', { reason: `state:${state}` });
      }
      assertPasswordPolicy(password);
      const params = paramsFor(profile);
      const salt = randomBytes(SALT_BYTES);
      const newRootKey = randomBytes(ROOT_KEY_BYTES);
      const pw = utf8.encode(password);
      let kek = null;
      try {
        kek = await deriveKek(pw, { salt, mKib: params.mKib, t: params.t, p: params.p, outLen: params.outLen });
        if (!(kek instanceof Uint8Array) || kek.length !== KEK_BYTES) {
          throw new VaultCryptoError(Codes.CRYPTO_FAILED, 'deriveKek returned an unexpected key');
        }
        const wrapper = await wrapSyntheticRootKey({
          kek, rootKey: newRootKey, salt, mKib: params.mKib, t: params.t, p: params.p,
          profile: params.profile, createdAt: todayIso(), calibratedMs: 0,
        });
        rootKey = newRootKey; // owned by the vault; needed to sign the manifest
        const manifest = await buildManifest(1, db.version);
        // Wrapper + manifest are written atomically (spec §11).
        await db.transaction([META_STORE], (ops) => {
          ops.put(META_STORE, WRAPPER_KEY, wrapper);
          ops.put(META_STORE, MANIFEST_KEY, manifest);
        });
        generation = 1;
        schemaVersion = db.version;
        state = VAULT_STATES.UNLOCKED;
        return { state };
      } catch (e) {
        newRootKey.fill(0);
        wipeRootKey();
        state = VAULT_STATES.UNINITIALIZED;
        throw e;
      } finally {
        if (kek !== null) kek.fill(0);
        pw.fill(0);
      }
    },

    /** Unlock an existing vault. Only from LOCKED. */
    async unlock(password) {
      await ensureLoaded();
      if (state !== VAULT_STATES.LOCKED) {
        throw wrongState('the vault is not locked', { reason: `state:${state}` });
      }
      assertPasswordPolicy(password);
      state = VAULT_STATES.UNLOCKING;
      const stored = await db.get(META_STORE, WRAPPER_KEY);
      const pw = utf8.encode(password);
      let kek = null;
      let unwrapped = null;
      try {
        // Form first (public) → VAULT_WRAPPER_INVALID before any derivation.
        const wrapper = parseVaultWrapper(stored);
        kek = await deriveKek(pw, {
          salt: decodeWrapperSalt(wrapper.saltB64), mKib: wrapper.mKib, t: wrapper.t, p: wrapper.p, outLen: wrapper.outLen,
        });
        // GCM failure → VAULT_WRONG_PASSWORD (no oracle beyond the public form).
        unwrapped = await unwrapSyntheticRootKey(stored, kek);
        rootKey = unwrapped;
        unwrapped = null; // ownership transferred to `rootKey`
        // Post-unlock integrity: the manifest HMAC under K_manifest. A correct
        // password with a tampered manifest → VAULT_MANIFEST_TAMPERED (not a
        // password oracle: the unwrap already succeeded).
        const manifestRecord = await db.get(META_STORE, MANIFEST_KEY);
        const verified = await verifyManifest(manifestRecord);
        if (!verified.ok) {
          throw new VaultCryptoError(Codes.MANIFEST_TAMPERED, 'vault manifest failed integrity verification');
        }
        generation = verified.generation;
        schemaVersion = verified.schemaVersion;
        // The signed schemaVersion is a HIGH-WATER MARK. Schema upgrades run
        // keyless in `onupgradeneeded` (vault LOCKED, no Root Key), so the
        // database can legitimately be AHEAD of the last signature — that is
        // reconciled here, on the first unlock that has K_manifest. The
        // database being BEHIND the signed marker means it was rolled back
        // under a signature we produced: fail closed.
        if (db.version < schemaVersion) {
          throw new VaultCryptoError(Codes.MANIFEST_TAMPERED, 'the database is older than the signed schema marker', { reason: 'schema-downgrade' });
        }
        if (db.version > schemaVersion) {
          const reconciled = await buildManifest(generation + 1, db.version);
          await db.transaction([META_STORE], (ops) => ops.put(META_STORE, MANIFEST_KEY, reconciled));
          generation += 1;
          schemaVersion = db.version;
        }
        state = VAULT_STATES.UNLOCKED;
        return { state };
      } catch (e) {
        if (unwrapped !== null) unwrapped.fill(0);
        wipeRootKey();
        state = VAULT_STATES.LOCKED; // non-destructive: a wrong password just returns here
        throw e;
      } finally {
        if (kek !== null) kek.fill(0);
        pw.fill(0);
      }
    },

    /** Best-effort key wipe. From UNLOCKED. */
    async lock() {
      await ensureLoaded();
      if (state !== VAULT_STATES.UNLOCKED) {
        throw wrongState('the vault is not unlocked', { reason: `state:${state}` });
      }
      state = VAULT_STATES.LOCKING;
      wipeRootKey();
      state = VAULT_STATES.LOCKED;
      return { state };
    },

    /** Change the vault password (new KEK from the new password). From UNLOCKED. */
    async changePassword(newPassword, { profile } = {}) {
      await ensureLoaded();
      if (state !== VAULT_STATES.UNLOCKED) {
        throw wrongState('the vault must be unlocked to change the password', { reason: `state:${state}` });
      }
      await doRewrap(newPassword, profile ?? currentProfile(await db.get(META_STORE, WRAPPER_KEY)));
      return { state };
    },

    /** Re-wrap with (possibly upgraded) parameters, same password. From UNLOCKED. */
    async rewrap(password, { profile = DEFAULT_VAULT_PROFILE } = {}) {
      await ensureLoaded();
      if (state !== VAULT_STATES.UNLOCKED) {
        throw wrongState('the vault must be unlocked to re-wrap', { reason: `state:${state}` });
      }
      await doRewrap(password, profile);
      return { state };
    },

    /**
     * Write one record. The namespace subkey encrypts it (the codec binds
     * namespace, key, record version, key version and content type into the
     * AAD, so a record cannot be replayed under another key or namespace), and
     * the record lands together with the re-signed manifest in ONE transaction
     * — one commit, one generation bump (spec §11).
     *
     * The previous `rv` is read BEFORE the transaction: the engine forbids
     * awaiting anything but its own ops inside a transaction callback (an
     * IndexedDB transaction auto-commits at a microtask checkpoint), and the
     * encryption between the read and the write is asynchronous. This is safe
     * under the vault's single-writer discipline (Web Lock election), which is
     * the only supported configuration.
     */
    async putRecord(namespace, recordKey, value, { contentType = 'json' } = {}) {
      await ensureLoaded();
      assertUnlocked('write a record');
      assertCanaryNamespace(namespace);
      const namespaceKey = await namespaceKeyFor(namespace);
      const previous = await db.get(namespace, recordKey);
      const recordVersion = isSafeInt(previous?.rv) && previous.rv >= 1 ? previous.rv + 1 : 1;
      const record = await encryptVaultRecord({
        namespace, recordKey, plaintext: value, contentType, recordVersion,
      }, namespaceKey);
      const nextGen = generation + 1;
      const manifest = await buildManifest(nextGen, schemaVersion);
      await db.transaction([namespace, META_STORE], (ops) => {
        ops.put(namespace, recordKey, record);
        ops.put(META_STORE, MANIFEST_KEY, manifest);
      });
      generation = nextGen;
      return { recordVersion };
    },

    /**
     * Read one record. A missing key is a normal outcome (`undefined`), not an
     * error; a present record that fails authentication is
     * `VAULT_RECORD_CORRUPTED` and is never deleted automatically (§11).
     */
    async getRecord(namespace, recordKey) {
      await ensureLoaded();
      assertUnlocked('read a record');
      assertReadableRecord(namespace, recordKey);
      const stored = await db.get(namespace, recordKey);
      if (stored === undefined) return undefined;
      const namespaceKey = await namespaceKeyFor(namespace);
      // The AAD's `ns`/`k` come from THIS request, not from the stored record
      // (codec contract, §6): a record moved to another key fails to authenticate.
      return decryptVaultRecord(stored, { namespace, recordKey }, namespaceKey);
    },

    /** Delete one record; the deletion and its manifest bump are one commit. */
    async deleteRecord(namespace, recordKey) {
      await ensureLoaded();
      assertUnlocked('delete a record');
      assertCanaryNamespace(namespace);
      const nextGen = generation + 1;
      const manifest = await buildManifest(nextGen, schemaVersion);
      await db.transaction([namespace, META_STORE], (ops) => {
        ops.delete(namespace, recordKey);
        ops.put(META_STORE, MANIFEST_KEY, manifest);
      });
      generation = nextGen;
      return { deleted: true };
    },

    /**
     * Apply a bounded, data-only batch in one durable IndexedDB transaction.
     * Crypto and record-version reads finish before the transaction starts;
     * then every record mutation and exactly one manifest bump commit or roll
     * back together. Duplicate keys are rejected so record-version semantics
     * stay unambiguous inside the batch.
     */
    async transactionRecords(namespace, operations) {
      await ensureLoaded();
      assertUnlocked('apply a record transaction');
      assertCanaryNamespace(namespace);
      if (!Array.isArray(operations)
        || operations.length < 1
        || operations.length > MAX_TRANSACTION_OPERATIONS) {
        throw new VaultCryptoError(Codes.RECORD_INVALID, 'transaction operation count is invalid', { reason: 'bad-transaction-size' });
      }

      const invalidOperation = (message, details) => new VaultCryptoError(
        Codes.RECORD_INVALID,
        message,
        { field: String(details?.field ?? 'operation').slice(0, 64) },
      );
      const seen = new Set();
      const normalized = operations.map((raw) => {
        const opDesc = raw !== null && typeof raw === 'object'
          ? Object.getOwnPropertyDescriptor(raw, 'op') : undefined;
        const op = opDesc && Object.hasOwn(opDesc, 'value') ? opDesc.value : undefined;
        const keys = op === 'put'
          ? ['op', 'recordKey', 'value', 'contentType']
          : ['op', 'recordKey'];
        const requiredKeys = op === 'put' ? ['op', 'recordKey', 'value'] : keys;
        if (op !== 'put' && op !== 'delete') {
          throw new VaultCryptoError(Codes.RECORD_INVALID, 'transaction operation is invalid', { reason: 'bad-transaction-op' });
        }
        const item = snapshotStrictPlainObject(raw, keys, invalidOperation, { requiredKeys });
        assertTransactionRecordKey(item.recordKey);
        if (op === 'put' && item.contentType !== undefined && !CONTENT_TYPES.includes(item.contentType)) {
          throw new VaultCryptoError(Codes.RECORD_INVALID, 'transaction content type is invalid', { field: 'contentType' });
        }
        if (seen.has(item.recordKey)) {
          throw new VaultCryptoError(Codes.RECORD_INVALID, 'transaction record keys must be unique', { reason: 'duplicate-transaction-key' });
        }
        seen.add(item.recordKey);
        return op === 'put'
          ? { op, recordKey: item.recordKey, value: item.value, contentType: item.contentType ?? 'json' }
          : { op, recordKey: item.recordKey };
      });

      const hasPuts = normalized.some((op) => op.op === 'put');
      const namespaceKey = hasPuts ? await namespaceKeyFor(namespace) : null;
      const prepared = [];
      let putCount = 0;
      let deleteCount = 0;
      for (const op of normalized) {
        if (op.op === 'delete') {
          prepared.push(op);
          deleteCount += 1;
          continue;
        }
        const previous = await db.get(namespace, op.recordKey);
        const recordVersion = isSafeInt(previous?.rv) && previous.rv >= 1 ? previous.rv + 1 : 1;
        const record = await encryptVaultRecord({
          namespace,
          recordKey: op.recordKey,
          plaintext: op.value,
          contentType: op.contentType,
          recordVersion,
        }, namespaceKey);
        prepared.push({ op: 'put', recordKey: op.recordKey, record });
        putCount += 1;
      }

      const nextGen = generation + 1;
      const manifest = await buildManifest(nextGen, schemaVersion);
      await db.transaction([namespace, META_STORE], (ops) => {
        for (const op of prepared) {
          if (op.op === 'put') ops.put(namespace, op.recordKey, op.record);
          else ops.delete(namespace, op.recordKey);
        }
        ops.put(META_STORE, MANIFEST_KEY, manifest);
      });
      generation = nextGen;
      return { applied: prepared.length, puts: putCount, deletes: deleteCount };
    },

    /** Keys of a namespace. A read: no commit, no generation bump. */
    async listRecords(namespace) {
      await ensureLoaded();
      assertUnlocked('list records');
      assertCanaryNamespace(namespace);
      return db.list(namespace);
    },

    /**
     * Migrate the single frozen settings record. localStorage stays page-side;
     * this worker-owned operation receives only the already-normalized, bounded
     * preference object and commits encrypted data, marker and manifest.
     */
    async migrate(namespace, preferences) {
      await ensureLoaded();
      assertUnlocked('migrate settings');
      if (namespace !== SETTINGS_NAMESPACE) {
        throw new VaultCryptoError(Codes.NAMESPACE_UNSUPPORTED, 'migration namespace is not enabled', { reason: 'migration-namespace' });
      }

      let normalized;
      try {
        normalized = validateSettingsPreferences(preferences);
      } catch (error) {
        if (error instanceof SettingsMigrationError) {
          throw new VaultCryptoError(Codes.RECORD_INVALID, 'settings migration payload is invalid', { reason: 'settings-payload-invalid' });
        }
        throw error;
      }

      state = VAULT_STATES.MIGRATING;
      try {
        const digest = await settingsMarkerDigest(normalized);
        const existingMarkerRaw = await db.get('migrations', SETTINGS_MARKER_KEY);
        let existingMarker;
        if (existingMarkerRaw !== undefined) {
          try {
            existingMarker = validateSettingsMarker(existingMarkerRaw);
          } catch (error) {
            if (error instanceof SettingsMigrationError) {
              throw new VaultCryptoError(Codes.RECORD_INVALID, 'settings migration marker is invalid', { reason: 'settings-marker-invalid' });
            }
            throw error;
          }
        }

        const previous = await db.get(SETTINGS_NAMESPACE, SETTINGS_RECORD_KEY);
        let previousPlain;
        if (previous !== undefined) {
          const key = await namespaceKeyFor(SETTINGS_NAMESPACE);
          previousPlain = await decryptVaultRecord(
            previous,
            { namespace: SETTINGS_NAMESPACE, recordKey: SETTINGS_RECORD_KEY },
            key,
          );
          try {
            previousPlain = { ...previousPlain, value: validateSettingsPreferences(previousPlain.value) };
          } catch (error) {
            if (error instanceof SettingsMigrationError) {
              throw new VaultCryptoError(Codes.RECORD_INVALID, 'stored settings payload is invalid', { reason: 'settings-record-invalid' });
            }
            throw error;
          }
        }

        const markerMatches = existingMarker?.digests.source === digest;
        const recordMatches = previousPlain !== undefined
          && settingsEqual(previousPlain.value, normalized);

        if (existingMarker?.state === 'verified' && markerMatches) {
          if (!recordMatches) {
            throw new VaultCryptoError(Codes.RECORD_INVALID, 'verified settings diverged', { reason: 'settings-divergence' });
          }
          return Object.freeze({ state: 'verified', matched: true, digest,
            recordVersion: previousPlain.recordVersion });
        }
        if (existingMarker?.state === 'written' && markerMatches && !recordMatches) {
          throw new VaultCryptoError(Codes.RECORD_INVALID, 'written settings diverged', { reason: 'settings-divergence' });
        }

        // Phase 1: a signed generation records that migration has started.
        let nextGen;
        let manifest;
        if (!(existingMarker?.state === 'pending' && markerMatches)
          && !(existingMarker?.state === 'written' && markerMatches)) {
          const pending = buildSettingsMarker('pending', digest);
          nextGen = generation + 1;
          manifest = await buildManifest(nextGen, schemaVersion);
          await db.transaction(['migrations', META_STORE], (ops) => {
            ops.put('migrations', SETTINGS_MARKER_KEY, pending);
            ops.put(META_STORE, MANIFEST_KEY, manifest);
          });
          generation = nextGen;
        }

        // Phase 2: encrypted settings + written marker + manifest are one
        // IndexedDB transaction. Crypto is complete before the transaction.
        const namespaceKey = await namespaceKeyFor(SETTINGS_NAMESPACE);
        let recordVersion = previousPlain?.recordVersion;
        if (!(existingMarker?.state === 'written' && markerMatches)) {
          recordVersion = isSafeInt(previous?.rv) && previous.rv >= 1 ? previous.rv + 1 : 1;
          const record = await encryptVaultRecord({
            namespace: SETTINGS_NAMESPACE,
            recordKey: SETTINGS_RECORD_KEY,
            plaintext: normalized,
            contentType: SETTINGS_CONTENT_TYPE,
            recordVersion,
          }, namespaceKey);
          const written = buildSettingsMarker('written', digest);
          nextGen = generation + 1;
          manifest = await buildManifest(nextGen, schemaVersion);
          await db.transaction([SETTINGS_NAMESPACE, 'migrations', META_STORE], (ops) => {
            ops.put(SETTINGS_NAMESPACE, SETTINGS_RECORD_KEY, record);
            ops.put('migrations', SETTINGS_MARKER_KEY, written);
            ops.put(META_STORE, MANIFEST_KEY, manifest);
          });
          generation = nextGen;
        }

        // Phase 3: verify the committed bytes through the normal authenticated
        // read path before marking them authoritative.
        const committed = await db.get(SETTINGS_NAMESPACE, SETTINGS_RECORD_KEY);
        const verifiedRecord = await decryptVaultRecord(
          committed,
          { namespace: SETTINGS_NAMESPACE, recordKey: SETTINGS_RECORD_KEY },
          namespaceKey,
        );
        let committedValue;
        try {
          committedValue = validateSettingsPreferences(verifiedRecord.value);
        } catch (error) {
          if (error instanceof SettingsMigrationError) {
            throw new VaultCryptoError(Codes.RECORD_INVALID, 'committed settings payload is invalid', { reason: 'settings-verify-invalid' });
          }
          throw error;
        }
        if (!settingsEqual(committedValue, normalized)
          || await settingsMarkerDigest(committedValue) !== digest) {
          throw new VaultCryptoError(Codes.RECORD_INVALID, 'settings verification diverged', { reason: 'settings-divergence' });
        }

        const verified = buildSettingsMarker('verified', digest);
        nextGen = generation + 1;
        manifest = await buildManifest(nextGen, schemaVersion);
        await db.transaction(['migrations', META_STORE], (ops) => {
          ops.put('migrations', SETTINGS_MARKER_KEY, verified);
          ops.put(META_STORE, MANIFEST_KEY, manifest);
        });
        generation = nextGen;
        return Object.freeze({ state: 'verified', matched: true, digest, recordVersion });
      } finally {
        if (state === VAULT_STATES.MIGRATING) state = VAULT_STATES.UNLOCKED;
      }
    },

    /**
     * Factory reset. From ANY state, INCLUDING a failed/ERROR load: a malformed
     * persisted wrapper must still be resettable through the lifecycle API
     * (§3 "any → DESTROYING"), so a failed load never blocks DESTROY.
     */
    async destroy() {
      try { await ensureLoaded(); } catch { state = VAULT_STATES.ERROR; }
      state = VAULT_STATES.DESTROYING;
      // §12 mandates the ORDER: keys first, then the wrapper, then the data.
      // Step 1 — best-effort wipe of the in-memory keys.
      wipeRootKey();
      // Step 2 — overwrite the wrapper record BEFORE deleting the database, so
      // that a partially failed cleanup cannot leave ciphertext behind with a
      // still-active wrapper. Best-effort by construction: an IndexedDB put
      // does not physically erase the previous bytes (§4/§12 say as much).
      try {
        await db.transaction([META_STORE], (ops) => ops.put(META_STORE, WRAPPER_KEY, null));
      } catch { /* the deletion below is the real cleanup */ }
      // Step 3 — delete the whole database.
      await db.destroy();
      state = VAULT_STATES.UNINITIALIZED;
      loadPromise = null; // a destroyed vault re-loads as UNINITIALIZED
      return { state };
    },

    /** State + non-sensitive markers. NEVER the Root Key. */
    async status() {
      await ensureLoaded();
      return Object.freeze({ state, initialized: state !== VAULT_STATES.UNINITIALIZED });
    },
  };

  // Operations that read or write vault state through an await boundary must
  // not interleave: each one reads counters (`rv`, `generation`), performs
  // asynchronous crypto, then commits. Reads are excluded — they take no
  // counters and IndexedDB isolates them.
  const MUTATING = Object.freeze([
    'createVault', 'unlock', 'lock', 'changePassword', 'rewrap', 'putRecord', 'deleteRecord',
    'transactionRecords', 'migrate', 'destroy',
  ]);
  return Object.freeze(Object.fromEntries(Object.entries(api).map(
    ([name, fn]) => [name, MUTATING.includes(name) ? (...args) => serialize(() => fn(...args)) : fn],
  )));
}

// parseVaultWrapper validates the canonical salt then zeroizes its local copy,
// so re-decode the (already validated) base64 for the KEK derivation.
function decodeWrapperSalt(b64) {
  if (typeof b64 !== 'string') {
    throw new VaultCryptoError(Codes.KDF_PARAMS_INVALID, 'wrapper salt is missing', { field: 'saltB64' });
  }
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

function currentProfile(stored) {
  const p = stored?.profile;
  return typeof p === 'string' && KDF_PROFILES[p] ? p : DEFAULT_VAULT_PROFILE;
}
