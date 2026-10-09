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
  IDENTITY_NAMESPACE, IDENTITY_RECORD_KEY, IDENTITY_MARKER_KEY, IDENTITY_CONTENT_TYPE,
  IdentityMigrationError, validateIdentityEnvelope, validateIdentityMarker,
  buildIdentityMarker, canonicalIdentityBytes, identityEqual,
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
  // Transient state while a stage-enabled product migration commits and verifies.
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
export const ENABLED_NAMESPACES = Object.freeze(['canary', SETTINGS_NAMESPACE, IDENTITY_NAMESPACE]);

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
  // The single open M2 destructive-reset confirmation (R-UX): an opaque handle,
  // bound to one C-REST result and one unlocked session, consumed on use.
  let pendingReset = null;

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
    if (namespace === IDENTITY_NAMESPACE && recordKey === IDENTITY_RECORD_KEY) return;
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

  // Product migration markers use a namespace-specific domain and the existing
  // K_manifest HMAC. No source digest is exposed as an unkeyed fingerprint.
  const migrationMarkerDigest = async (domainLabel, payload) => {
    const domain = new TextEncoder().encode(domainLabel);
    const bytes = new Uint8Array(domain.length + payload.length);
    bytes.set(domain);
    bytes.set(payload, domain.length);
    payload.fill(0);
    domain.fill(0);
    let mac;
    try {
      mac = await signManifestBytes(await manifestKey(), bytes);
      return [...mac].map((b) => b.toString(16).padStart(2, '0')).join('');
    } finally {
      bytes.fill(0);
      mac?.fill(0);
    }
  };
  const settingsMarkerDigest = (value) => migrationMarkerDigest(
    'styx/settings-marker/v1\0', canonicalSettingsBytes(value),
  );
  const identityMarkerDigest = (value) => migrationMarkerDigest(
    'styx/identity-marker/v1\0', canonicalIdentityBytes(value),
  );

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

  const migrateSingleRecord = async ({
    namespace, recordKey, markerKey, contentType, normalized, validate, ErrorType,
    validateMarker, buildMarker, digestValue, equal, reasonPrefix, includeDigest,
  }) => {
    const digest = await digestValue(normalized);
    const existingMarkerRaw = await db.get('migrations', markerKey);
    let existingMarker;
    let repairRequired = false;
    if (existingMarkerRaw !== undefined) {
      try { existingMarker = validateMarker(existingMarkerRaw); } catch (error) {
        if (error instanceof ErrorType) repairRequired = true;
        else throw error;
      }
    }

    const previous = await db.get(namespace, recordKey);
    // A record without its migration marker cannot be a legitimate crash
    // state: phase 2 commits both atomically. Treat it as shadow corruption so
    // repair advances rv instead of silently reusing the old version.
    if (existingMarkerRaw === undefined && previous !== undefined) repairRequired = true;
    let previousPlain;
    if (previous !== undefined) {
      const key = await namespaceKeyFor(namespace);
      try {
        previousPlain = await decryptVaultRecord(previous, { namespace, recordKey }, key);
      } catch (error) {
        if (error?.code === Codes.RECORD_CORRUPTED || error?.code === Codes.RECORD_INVALID) {
          repairRequired = true;
          previousPlain = undefined;
        } else throw error;
      }
      try {
        if (previousPlain !== undefined) {
          previousPlain = { ...previousPlain, value: validate(previousPlain.value) };
        }
      } catch (error) {
        if (error instanceof ErrorType) {
          repairRequired = true;
          previousPlain = undefined;
        } else throw error;
      }
    }

    const markerMatches = existingMarker?.digests.source === digest;
    const recordMatches = previousPlain !== undefined && equal(previousPlain.value, normalized);
    if (existingMarker?.state === 'verified' && markerMatches) {
      if (!recordMatches) repairRequired = true;
      if (!repairRequired) {
        return Object.freeze({
          state: 'verified', matched: true,
          ...(includeDigest ? { digest } : {}),
          recordVersion: previousPlain.recordVersion,
        });
      }
    }
    if (existingMarker?.state === 'written' && markerMatches && !recordMatches) {
      repairRequired = true;
    }

    let nextGen;
    let manifest;
    if (repairRequired
      || (!(existingMarker?.state === 'pending' && markerMatches)
        && !(existingMarker?.state === 'written' && markerMatches))) {
      const pending = buildMarker('pending', digest);
      nextGen = generation + 1;
      manifest = await buildManifest(nextGen, schemaVersion);
      await db.transaction(['migrations', META_STORE], (ops) => {
        ops.put('migrations', markerKey, pending);
        ops.put(META_STORE, MANIFEST_KEY, manifest);
      });
      generation = nextGen;
    }

    const namespaceKey = await namespaceKeyFor(namespace);
    let recordVersion = previousPlain?.recordVersion;
    if (repairRequired || !(existingMarker?.state === 'written' && markerMatches)) {
      recordVersion = isSafeInt(previous?.rv) && previous.rv >= 1 ? previous.rv + 1 : 1;
      const record = await encryptVaultRecord({
        namespace, recordKey, plaintext: normalized, contentType, recordVersion,
      }, namespaceKey);
      const written = buildMarker('written', digest);
      nextGen = generation + 1;
      manifest = await buildManifest(nextGen, schemaVersion);
      await db.transaction([namespace, 'migrations', META_STORE], (ops) => {
        ops.put(namespace, recordKey, record);
        ops.put('migrations', markerKey, written);
        ops.put(META_STORE, MANIFEST_KEY, manifest);
      });
      generation = nextGen;
    }

    const committed = await db.get(namespace, recordKey);
    const verifiedRecord = await decryptVaultRecord(
      committed, { namespace, recordKey }, namespaceKey,
    );
    let committedValue;
    try { committedValue = validate(verifiedRecord.value); } catch (error) {
      if (error instanceof ErrorType) {
        throw new VaultCryptoError(Codes.RECORD_INVALID, 'committed migration payload is invalid', {
          reason: `${reasonPrefix}-verify-invalid`,
        });
      }
      throw error;
    }
    if (!equal(committedValue, normalized) || await digestValue(committedValue) !== digest) {
      throw new VaultCryptoError(Codes.RECORD_INVALID, 'migration verification diverged', {
        reason: `${reasonPrefix}-divergence`,
      });
    }

    const verified = buildMarker('verified', digest);
    nextGen = generation + 1;
    manifest = await buildManifest(nextGen, schemaVersion);
    await db.transaction(['migrations', META_STORE], (ops) => {
      ops.put('migrations', markerKey, verified);
      ops.put(META_STORE, MANIFEST_KEY, manifest);
    });
    generation = nextGen;
    return Object.freeze({
      state: 'verified', matched: true,
      ...(includeDigest ? { digest } : {}),
      recordVersion,
    });
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

    /** Migrate one stage-enabled product shadow record; legacy stays page-side. */
    async migrate(namespace, source, { pairingActive } = {}) {
      await ensureLoaded();
      assertUnlocked('migrate product data');
      if (namespace !== SETTINGS_NAMESPACE && namespace !== IDENTITY_NAMESPACE) {
        throw new VaultCryptoError(Codes.NAMESPACE_UNSUPPORTED, 'migration namespace is not enabled', { reason: 'migration-namespace' });
      }
      if (namespace === IDENTITY_NAMESPACE && pairingActive !== false) {
        throw wrongState('identity migration requires an idle pairing state', { reason: 'pairing-active' });
      }

      state = VAULT_STATES.MIGRATING;
      try {
        const config = namespace === SETTINGS_NAMESPACE ? {
          namespace, recordKey: SETTINGS_RECORD_KEY, markerKey: SETTINGS_MARKER_KEY,
          contentType: SETTINGS_CONTENT_TYPE, validate: validateSettingsPreferences,
          ErrorType: SettingsMigrationError, validateMarker: validateSettingsMarker,
          buildMarker: buildSettingsMarker, digestValue: settingsMarkerDigest,
          equal: settingsEqual, reasonPrefix: 'settings', includeDigest: true,
        } : {
          namespace, recordKey: IDENTITY_RECORD_KEY, markerKey: IDENTITY_MARKER_KEY,
          contentType: IDENTITY_CONTENT_TYPE, validate: validateIdentityEnvelope,
          ErrorType: IdentityMigrationError, validateMarker: validateIdentityMarker,
          buildMarker: buildIdentityMarker, digestValue: identityMarkerDigest,
          equal: identityEqual, reasonPrefix: 'identity', includeDigest: false,
        };
        let normalized;
        try { normalized = config.validate(source); } catch (error) {
          if (error instanceof config.ErrorType) {
            throw new VaultCryptoError(Codes.RECORD_INVALID, 'migration payload is invalid', {
              reason: `${config.reasonPrefix}-payload-invalid`,
            });
          }
          throw error;
        }
        return await migrateSingleRecord({ ...config, normalized });
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

    /**
     * M2 recovery (R-UX, C-REC §7): open one explicit destructive-reset
     * confirmation. Refused, with no storage access, unless the one-writer lock
     * is held and the injected complete C-REST result is reset-eligible and the
     * vault is UNLOCKED (an eligible M2 failure is produced only after
     * WRAPPER_AUTH, so any other vault state is ineligible). On acceptance it
     * returns the value-free disclosure and a fresh opaque confirmation handle,
     * bound to this result and this unlocked session; any earlier handle is void.
     * It never loads the vault: an instance that has not reached UNLOCKED in this
     * session (never loaded, LOCKED, ERROR) is decided from memory as ineligible,
     * so a refusal reads and writes no byte. Every call, malformed included, voids
     * any open handle before validating its input (R-WIRE, superseding the R-UX
     * rule 5 phrase "a second `begin` voids the first"; R-UX ratification item 2).
     */
    async beginRecoveryReset(input) {
      pendingReset = null;
      const s = snapshotRecoveryInput(input, ['restoreResult', 'lockHeld']);
      if (s === null || typeof s.lockHeld !== 'boolean') {
        throw new TypeError('recovery reset input is malformed');
      }
      const eligibleResult = state === VAULT_STATES.UNLOCKED ? s.restoreResult : null;
      const gate = decideRecoveryAction({
        action: 'RESET', result: eligibleResult, confirmed: true, disclosure: true,
        lock: s.lockHeld ? 'HELD' : 'NOT_HELD', token: 'FRESH_BOUND_TOKEN',
      });
      if (gate.accepted !== true) return gate;
      const handle = Object.freeze(Object.create(null));
      pendingReset = { handle, result: s.restoreResult, epoch: sessionEpoch };
      return Object.freeze({ disclosure: RESET_DISCLOSURE, confirmation: handle });
    },

    /**
     * M2 recovery (R-UX, C-REC §7/§8): execute a confirmed destructive reset. The
     * closed ACTION gate runs first (lock → explicit confirmation → eligibility →
     * disclosure → fresh bound handle) and a refusal touches no byte. The handle
     * is single-use. On acceptance the existing `destroy()` order runs unchanged
     * (keys, then wrapper, then database). It never reads or writes legacy bytes
     * or the L-MARK marker (neither lives in the vault database). A failure after
     * the gate is the closed INTERRUPTED outcome: it is classified only by the next
     * complete C-REST run, with no automatic completion and no cleanup. Like
     * beginRecoveryReset it never loads the vault, and every call — malformed
     * included — consumes the open handle before anything else.
     */
    async confirmRecoveryReset(input) {
      const pending = pendingReset;
      pendingReset = null; // single-use, whatever the decision, before any validation
      const s = snapshotRecoveryInput(input, ['restoreResult', 'lockHeld', 'confirmed', 'disclosure', 'confirmation']);
      if (s === null || typeof s.lockHeld !== 'boolean') {
        throw new TypeError('recovery reset input is malformed');
      }
      const fresh = pending !== null && s.confirmation === pending.handle
        && s.restoreResult === pending.result && pending.epoch === sessionEpoch;
      const gate = decideRecoveryAction({
        action: 'RESET',
        result: state === VAULT_STATES.UNLOCKED ? s.restoreResult : null,
        confirmed: s.confirmed === true,
        disclosure: s.disclosure === true,
        lock: s.lockHeld ? 'HELD' : 'NOT_HELD',
        token: fresh ? 'FRESH_BOUND_TOKEN' : 'STALE',
      });
      if (gate.accepted !== true) return gate;
      try {
        await api.destroy();
      } catch {
        return Object.freeze({
          accepted: false, outcome: 'INTERRUPTED', boundary: recoveryBoundary('DURING_RESET'),
        });
      }
      return Object.freeze({ ...gate, state });
    },

    /** M2 recovery (R-UX, C-REC RESET_CANCEL): void any open reset confirmation. No storage access. */
    async cancelRecoveryReset() {
      pendingReset = null;
      return decideRecoveryAction({ action: 'RESET_CANCEL' });
    },

    /**
     * M2 recovery (R-UX, C-REC §5): password re-wrap on the M2 recovery surface.
     * Gate order: lock → C-REST precondition (RESTORED_ACTIVE or RESTORED_EMPTY;
     * NO_M2_STATE / LEGACY_ONLY return EXISTING_VAULT_FACILITY_UNCHANGED and do
     * nothing; reconciliation and every failure are RESTORE_PRECONDITION_FAILED)
     * → wrapper authentication of `currentPassword` against the stored wrapper
     * (a wrong credential is WRAPPER_AUTH_FAILED: no re-wrap, no reset, no record
     * oracle). Only then the existing atomic re-wrap runs, unchanged: same Root
     * Storage Key, no record touched. It never loads the vault: every gate before
     * wrapper authentication is decided from memory, and an instance that is not
     * UNLOCKED in this session is WRAPPER_AUTH_FAILED with no storage access.
     */
    async recoveryChangePassword(input) {
      const s = snapshotRecoveryInput(input, ['restoreResult', 'lockHeld', 'currentPassword', 'newPassword', 'profile']);
      if (s === null || typeof s.lockHeld !== 'boolean' || typeof s.restoreResult !== 'string') {
        throw new TypeError('recovery re-wrap input is malformed');
      }
      const lock = s.lockHeld ? 'HELD' : 'NOT_HELD';
      const pre = decidePasswordRewrap({ result: s.restoreResult, wrapperAuthenticated: true, lock });
      if (pre.accepted !== true) return pre;
      const refused = decidePasswordRewrap({ result: s.restoreResult, wrapperAuthenticated: false, lock });
      if (state !== VAULT_STATES.UNLOCKED || typeof s.currentPassword !== 'string') return refused;
      const stored = await db.get(META_STORE, WRAPPER_KEY);
      const pw = utf8.encode(s.currentPassword);
      let kek = null;
      let candidate = null;
      let authenticated = false;
      try {
        const wrapper = parseVaultWrapper(stored);
        kek = await deriveKek(pw, {
          salt: decodeWrapperSalt(wrapper.saltB64), mKib: wrapper.mKib, t: wrapper.t, p: wrapper.p, outLen: wrapper.outLen,
        });
        candidate = await unwrapSyntheticRootKey(stored, kek);
        authenticated = rootKey !== null && constantTimeEqual(candidate, rootKey);
      } catch {
        authenticated = false;
      } finally {
        if (candidate !== null) candidate.fill(0);
        if (kek !== null) kek.fill(0);
        pw.fill(0);
      }
      if (!authenticated) return refused;
      await doRewrap(s.newPassword, s.profile ?? currentProfile(stored));
      return Object.freeze({ ...pre, state });
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
    'beginRecoveryReset', 'confirmRecoveryReset', 'cancelRecoveryReset', 'recoveryChangePassword',
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

// ---------------------------------------------------------------------------
// M2 recovery and reset actions (card R-UX, G-SCOPE #317). Value-free.
//
// Normative source: the owner-ratified C-REC contract
// `docs/architecture/m2/recovery-and-coexistence.md` (SHA-256
// ab11271cc038b49f24d356ee4a52bfc993dfd62195fec3e27925bc71e8837149), §3, §5, §7,
// §8, §9 and the §13 record. The tables below are transcribed from that record;
// `test/storage/m2/recovery.test.js` replays every DISPATCH, ACTION,
// PASSWORD_REWRAP and DIAGNOSTIC fixture and the re-wrap/reset BOUNDARY fixtures
// against them.
//
// Everything here is a pure, closed decision: no I/O, no clock, no randomness,
// no key, no byte of a record, no legacy value and no marker byte is read. The
// vault methods `beginRecoveryReset`, `confirmRecoveryReset`,
// `cancelRecoveryReset` and `recoveryChangePassword` (inside `createVault`) run
// these decisions BEFORE touching storage; a refusal never touches storage.
// The C-REST result and the one-writer lock are injected facts (the lock is a
// boolean, as in L-MARK and L-REEST): this module neither classifies storage
// nor acquires a lock.
// ---------------------------------------------------------------------------

const deepFreezeRecovery = (value) => {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const key of Object.keys(value)) deepFreezeRecovery(value[key]);
    Object.freeze(value);
  }
  return value;
};

/** C-REC `/restoreResults`, in record order. */
const RECOVERY_RESULTS = Object.freeze([
  'NO_M2_STATE', 'LEGACY_ONLY', 'RESTORED_EMPTY', 'RESTORED_ACTIVE',
  'RESTORED_RECONCILIATION_REQUIRED', 'LOCKED_ELSEWHERE', 'WRAPPER_AUTH_FAILED',
  'INCOMPATIBLE_BUILD', 'INCOMPATIBLE_FORMAT', 'UNSUPPORTED_VERSION', 'SELECTOR_INVALID',
  'AUTHENTICATION_FAILED', 'MANIFEST_INVALID', 'RECORD_SET_INCOMPLETE', 'RECORD_INVALID',
  'REFERENCE_INCONSISTENT', 'PARTIAL_GENERATION', 'INTERNAL_VALIDATION_FAILED',
]);
const INVENTORY_AND_SUCCESS = Object.freeze(RECOVERY_RESULTS.slice(0, 5));

/** C-REC `/dispositionEnum`. */
const RECOVERY_DISPOSITIONS = Object.freeze([
  'CONTINUE_ACTIVE', 'CONTINUE_EMPTY', 'RECONCILE_ONLY', 'SHOW_CREATE', 'SHOW_COMPATIBLE_BUILD',
  'SHOW_REESTABLISHMENT', 'PRESERVE_AND_STOP', 'LOCK_RETRY',
]);

/** C-REC `/reset/eligibleResults`: the only reset-eligible results. */
const RESET_ELIGIBLE_RESULTS = Object.freeze([
  'AUTHENTICATION_FAILED', 'INCOMPATIBLE_FORMAT', 'MANIFEST_INVALID', 'RECORD_INVALID',
  'RECORD_SET_INCOMPLETE', 'REFERENCE_INCONSISTENT', 'UNSUPPORTED_VERSION',
]);

// C-REC `/dispatchRows`: result -> [disposition, authority, legacyCondition].
// `resetEligible` is membership of RESET_ELIGIBLE_RESULTS; `byteAction` is PRESERVE
// for every row.
const DISPATCH_TABLE = Object.freeze({
  NO_M2_STATE: Object.freeze(['SHOW_CREATE', 'NONE', 'UNAVAILABLE']),
  LEGACY_ONLY: Object.freeze(['SHOW_REESTABLISHMENT', 'NONE', 'REQUIRED']),
  RESTORED_EMPTY: Object.freeze(['CONTINUE_EMPTY', 'SELECTED_AUTHORITY', 'OPTIONAL']),
  RESTORED_ACTIVE: Object.freeze(['CONTINUE_ACTIVE', 'SELECTED_AUTHORITY', 'OPTIONAL']),
  RESTORED_RECONCILIATION_REQUIRED: Object.freeze(['RECONCILE_ONLY', 'SELECTED_ORIGINAL_AUTHORITY', 'OPTIONAL']),
  LOCKED_ELSEWHERE: Object.freeze(['LOCK_RETRY', 'NONE', 'UNAVAILABLE']),
  WRAPPER_AUTH_FAILED: Object.freeze(['PRESERVE_AND_STOP', 'NONE', 'OPTIONAL']),
  INCOMPATIBLE_BUILD: Object.freeze(['SHOW_COMPATIBLE_BUILD', 'NONE', 'UNAVAILABLE']),
  INCOMPATIBLE_FORMAT: Object.freeze(['PRESERVE_AND_STOP', 'NONE', 'OPTIONAL']),
  UNSUPPORTED_VERSION: Object.freeze(['PRESERVE_AND_STOP', 'NONE', 'OPTIONAL']),
  SELECTOR_INVALID: Object.freeze(['PRESERVE_AND_STOP', 'NONE', 'OPTIONAL']),
  AUTHENTICATION_FAILED: Object.freeze(['PRESERVE_AND_STOP', 'NONE', 'OPTIONAL']),
  MANIFEST_INVALID: Object.freeze(['PRESERVE_AND_STOP', 'NONE', 'OPTIONAL']),
  RECORD_SET_INCOMPLETE: Object.freeze(['PRESERVE_AND_STOP', 'NONE', 'OPTIONAL']),
  RECORD_INVALID: Object.freeze(['PRESERVE_AND_STOP', 'NONE', 'OPTIONAL']),
  REFERENCE_INCONSISTENT: Object.freeze(['PRESERVE_AND_STOP', 'NONE', 'OPTIONAL']),
  PARTIAL_GENERATION: Object.freeze(['PRESERVE_AND_STOP', 'NONE', 'OPTIONAL']),
  INTERNAL_VALIDATION_FAILED: Object.freeze(['PRESERVE_AND_STOP', 'NONE', 'OPTIONAL']),
});

// C-REC `/reachableConditionRows`: a pair (result, legacyPresent) is reachable iff
// the row's legacyCondition admits it (REQUIRED: true only; UNAVAILABLE: false only;
// OPTIONAL: both). This yields exactly the record's 32 rows.
const legacyAdmits = (condition, legacyPresent) => (condition === 'OPTIONAL'
  || (condition === 'REQUIRED' && legacyPresent === true)
  || (condition === 'UNAVAILABLE' && legacyPresent === false));

/** The six forbidden ACTION names of C-REC §6/§8 and their ratified reject codes. */
const FORBIDDEN_RECOVERY_ACTIONS = Object.freeze({
  LEGACY_FALLBACK: 'LEGACY_FALLBACK_FORBIDDEN',
  LEGACY_IMPORT: 'LEGACY_IMPORT_FORBIDDEN',
  RETRY_ORIGINAL_MUTATION: 'MUTATION_RETRY_FORBIDDEN',
  USER_SELECT_CANDIDATE: 'CANDIDATE_SELECTION_FORBIDDEN',
  RESTORE_RELEASE_ESCROW: 'RESTORE_OUTPUT_RELEASE_FORBIDDEN',
  DELETE_LEGACY: 'CLEANUP_DEFERRED',
});

const RECOVERY_ACTIONS = Object.freeze(['RESET', 'RESET_CANCEL', ...Object.keys(FORBIDDEN_RECOVERY_ACTIONS)]);
const ACTION_MEMBERS = Object.freeze(['action', 'result', 'confirmed', 'lock', 'token', 'disclosure']);
const REWRAP_MEMBERS = Object.freeze(['result', 'wrapperAuthenticated', 'lock']);
const DISPATCH_MEMBERS = Object.freeze(['result', 'legacyPresent']);
const DIAGNOSTIC_MEMBERS = Object.freeze(['fields']);

/** C-REC `/diagnostics`. */
const DIAGNOSTIC_ALLOWED = Object.freeze([
  'restoreResult', 'condition', 'recoveryDisposition', 'stageCode', 'reasonCode', 'boundedCount',
]);
const DIAGNOSTIC_FORBIDDEN = Object.freeze([
  'key', 'nonce', 'plaintext', 'bindingByte', 'contextIdentifier', 'sessionIdentifier',
  'packageReference', 'digest', 'recordKey', 'legacyContent', 'markerBinding', 'escrow',
]);
const DIAGNOSTIC_MAX_FIELDS = DIAGNOSTIC_ALLOWED.length;

/** The closed reject codes this surface can return (all ratified C-REC values). */
const RECOVERY_REJECT_CODES = Object.freeze([
  'UNKNOWN_RESULT', 'MISSING_DISPATCH_INPUT', 'UNREACHABLE_CONDITION_PAIR', 'LOCKED_ELSEWHERE',
  'EXPLICIT_CONFIRMATION_REQUIRED', 'RESET_INELIGIBLE', 'DISCLOSURE_REQUIRED',
  'FRESH_CONFIRMATION_REQUIRED', 'WRAPPER_AUTH_FAILED', 'RESTORE_PRECONDITION_FAILED',
  'RAW_VALUE_DIAGNOSTIC', ...Object.values(FORBIDDEN_RECOVERY_ACTIONS),
]);

/**
 * Closed user-visible guidance (it-IT), one entry per disposition and per action
 * family. C-REC §9: the wording distinguishes restored authority, new-session
 * re-establishment, compatible-build handoff and destructive reset. No entry
 * promises recovery, freshness, rollback protection or physical erasure.
 */
const RECOVERY_GUIDANCE = Object.freeze({
  CONTINUE_ACTIVE: 'Sessione ripristinata: continui a usare la sessione esistente.',
  CONTINUE_EMPTY: 'Archivio ripristinato senza sessione M2 attiva.',
  RECONCILE_ONLY: 'È in corso una riconciliazione: nessuna altra azione è disponibile finché non termina.',
  SHOW_CREATE: 'Nessuna sessione M2 trovata: può creare una nuova sessione. Questo non attesta che prima non ce ne fossero.',
  SHOW_REESTABLISHMENT: 'È presente solo una sessione precedente: può avviare, con il suo consenso, una nuova sessione. La sessione precedente non viene convertita né importata.',
  SHOW_COMPATIBLE_BUILD: 'Questi dati richiedono una versione compatibile dell’app (CFMT_EXACT_9DACE4A0). Nulla è stato letto o modificato.',
  PRESERVE_AND_STOP: 'I dati non sono leggibili da questa versione. Sono stati conservati senza modifiche.',
  LOCK_RETRY: 'La sessione è in uso in un’altra scheda. Riprovi più tardi.',
  PASSWORD_REWRAP: 'Cambio password: la chiave dell’archivio resta la stessa; cambia solo la protezione. Non è un recupero di password dimenticata.',
  RESET: 'Azzeramento distruttivo: è un’azione separata e irreversibile. La sessione M2 attuale diventerà inutilizzabile. Non è un recupero della sessione precedente.',
  RESET_NO_ERASURE: 'L’azzeramento non garantisce la cancellazione fisica dei dati dal dispositivo.',
});

/** The value-free disclosure a confirmed reset requires (C-REC §7). */
const RESET_DISCLOSURE = Object.freeze({
  authorityBecomesUnavailable: 'M2_SESSION_AUTHORITY',
  legacyBytes: 'UNCHANGED',
  markerState: 'UNCHANGED',
  physicalErasureClaim: false,
  recoveryOfPriorAuthority: false,
  irreversible: true,
  interruptedClassification: 'NEXT_COMPLETE_C_REST_RESULT_ONLY',
  guidance: RECOVERY_GUIDANCE.RESET,
  noErasureStatement: RECOVERY_GUIDANCE.RESET_NO_ERASURE,
});

/**
 * R-WIRE: the closed vault-unlock rejection → C-REST fault table, a positive allowlist. Each row is
 * `{ code, detail, fault }`; `detail` is `ANY`, `NO_REASON` (no own `details.reason`),
 * `REASON:<slug>` (own `details.reason` equals the slug), `FIELD` (own string `details.field`) or
 * `REASON_EXCEPT:<slug>` (own string `details.reason` other than the slug). The first matching row
 * wins; no matching row means the rejection is not C-REST evidence (`null`). Rows 7 and 8 are the
 * vault-container failures that the owner interpretation (#317 comment 6022947656) places in
 * C-REST `WRAPPER_AUTH` as `wrapperWrongOrInvalid`.
 */
const VAULT_UNLOCK_FAULT_ROWS = Object.freeze([
  Object.freeze({ code: Codes.WRONG_PASSWORD, detail: 'ANY', fault: 'wrapperWrongOrInvalid' }),
  Object.freeze({ code: Codes.WRAPPER_INVALID, detail: 'ANY', fault: 'wrapperWrongOrInvalid' }),
  Object.freeze({ code: Codes.WRAPPER_UNSUPPORTED, detail: 'ANY', fault: 'wrapperWrongOrInvalid' }),
  Object.freeze({ code: Codes.KEY_VERSION_UNSUPPORTED, detail: 'ANY', fault: 'wrapperWrongOrInvalid' }),
  Object.freeze({ code: Codes.KDF_PARAMS_INVALID, detail: 'FIELD', fault: 'wrapperWrongOrInvalid' }),
  Object.freeze({ code: Codes.KDF_PARAMS_INVALID, detail: 'REASON_EXCEPT:password-length', fault: 'wrapperWrongOrInvalid' }),
  Object.freeze({ code: Codes.MANIFEST_TAMPERED, detail: 'NO_REASON', fault: 'wrapperWrongOrInvalid' }),
  Object.freeze({ code: Codes.MANIFEST_TAMPERED, detail: 'REASON:schema-downgrade', fault: 'wrapperWrongOrInvalid' }),
]);

export const M2_RECOVERY = deepFreezeRecovery({
  SCHEMA: 'styx-m2-recovery-actions/v1',
  C_REC_DOCUMENT_SHA256: 'ab11271cc038b49f24d356ee4a52bfc993dfd62195fec3e27925bc71e8837149',
  RESULTS: RECOVERY_RESULTS,
  DISPOSITIONS: RECOVERY_DISPOSITIONS,
  RESET_ELIGIBLE_RESULTS,
  RESET_INELIGIBLE_RESULTS: RECOVERY_RESULTS.filter((r) => !RESET_ELIGIBLE_RESULTS.includes(r)),
  REWRAP_ELIGIBLE_RESULTS: ['RESTORED_ACTIVE', 'RESTORED_EMPTY'],
  REWRAP_EXISTING_FACILITY_RESULTS: ['NO_M2_STATE', 'LEGACY_ONLY'],
  ACTIONS: RECOVERY_ACTIONS,
  FORBIDDEN_ACTIONS: FORBIDDEN_RECOVERY_ACTIONS,
  REJECT_CODES: RECOVERY_REJECT_CODES,
  DIAGNOSTIC_ALLOWED,
  DIAGNOSTIC_FORBIDDEN,
  GUIDANCE: RECOVERY_GUIDANCE,
  RESET_DISCLOSURE,
  BOUNDARIES: ['REWRAP_BEFORE_ATOMIC_REPLACEMENT', 'REWRAP_AFTER_ATOMIC_REPLACEMENT', 'DURING_RESET'],
  // Closed flags (C-REC `/reset`, `/legacy`, `/limits`, `/precedence`).
  BYTE_ACTION: 'PRESERVE',
  LOCKED_DISPOSITION: 'LOCK_RETRY',
  REQUIRES_ONE_WRITER_LOCK_FOR_STATE_CHANGE: true,
  RESET_AUTOMATIC: false,
  RESET_LEGACY_BYTES: 'UNCHANGED',
  RESET_MARKER_STATE: 'UNCHANGED',
  PHYSICAL_ERASURE_CLAIM: false,
  FRESHNESS_CLAIM: false,
  RECOVERY_SUCCESS_CLAIM: false,
  FORGOTTEN_PASSWORD_RECOVERY: false,
  LEGACY_IMPORT: false,
  LEGACY_FALLBACK: false,
  CLEANUP: 'DEFERRED',
  // C-REC `/reset/preserveDiagnosis` (R-WIRE; R-UX ratification item 3). Policy only:
  // the diagnosis is the caller's injected C-REST result, never stored or cleared here.
  RESET_PRESERVE_DIAGNOSIS: true,
  // R-WIRE: the closed vault-unlock rejection → C-REST fault rows of
  // `vaultUnlockRestoreFault` (owner interpretation #317 comment 6022947656 for rows 7-8).
  VAULT_UNLOCK_FAULTS: VAULT_UNLOCK_FAULT_ROWS,
});

const agreementOf = (disposition, authorityIdentity, firstFailingPhase) => Object.freeze({
  disposition, authorityIdentity, markerState: 'UNCHANGED', firstFailingPhase,
});
const rejectOf = (reject, authorityIdentity, firstFailingPhase, disposition = 'REJECT') => Object.freeze({
  reject, agreement: agreementOf(disposition, authorityIdentity, firstFailingPhase),
});

// Untrusted input: read own enumerable data members only, through descriptors, so
// no accessor or proxy trap can choose a value twice. `null` means malformed.
function snapshotRecoveryInput(input, allowed) {
  try {
    if (input === null || typeof input !== 'object' || Array.isArray(input)) return null;
    const proto = Object.getPrototypeOf(input);
    if (proto !== Object.prototype && proto !== null) return null;
    const out = Object.create(null);
    for (const key of Reflect.ownKeys(input)) {
      if (typeof key !== 'string' || !allowed.includes(key)) return null;
      const d = Object.getOwnPropertyDescriptor(input, key);
      if (d === undefined || !Object.hasOwn(d, 'value') || d.enumerable !== true) return null;
      out[key] = d.value;
    }
    return out;
  } catch {
    return null;
  }
}

const has = (snapshot, key) => Object.prototype.hasOwnProperty.call(snapshot, key);

/**
 * C-REC §3 dispatch of one complete C-REST result. Returns the fixture-shaped
 * decision: `{ disposition, authority, resetEligible, agreement }`, or
 * `{ reject, agreement }` for an unknown result, a missing/malformed input or an
 * unreachable (result, legacyPresent) pair. Total: never throws.
 */
export function dispatchRecovery(input) {
  const s = snapshotRecoveryInput(input, DISPATCH_MEMBERS);
  if (s === null || !has(s, 'result') || !has(s, 'legacyPresent') || typeof s.legacyPresent !== 'boolean') {
    return rejectOf('MISSING_DISPATCH_INPUT', 'NONE', 'C_REST_CLASSIFIED');
  }
  if (typeof s.result !== 'string' || !Object.hasOwn(DISPATCH_TABLE, s.result)) {
    return rejectOf('UNKNOWN_RESULT', 'NONE', 'C_REST_CLASSIFIED');
  }
  const [disposition, authority, condition] = DISPATCH_TABLE[s.result];
  if (!legacyAdmits(condition, s.legacyPresent)) {
    return rejectOf('UNREACHABLE_CONDITION_PAIR', 'NONE', 'C_REST_CLASSIFIED');
  }
  const phase = INVENTORY_AND_SUCCESS.includes(s.result) ? 'NONE' : 'C_REST_CLASSIFIED';
  return Object.freeze({
    disposition,
    authority,
    resetEligible: RESET_ELIGIBLE_RESULTS.includes(s.result),
    agreement: agreementOf(disposition, authority, phase),
  });
}

/** The closed it-IT guidance for one disposition or action family; `null` if unknown. */
export function recoveryGuidance(key) {
  return typeof key === 'string' && Object.hasOwn(RECOVERY_GUIDANCE, key) ? RECOVERY_GUIDANCE[key] : null;
}

/**
 * C-REC ACTION decision. Gate order for RESET (C-REC §7/§8 and its fixtures):
 * lock (a non-holder learns only LOCKED_ELSEWHERE) → explicit confirmation →
 * eligibility → value-free disclosure → fresh bound token. `RESET_CANCEL` has no
 * side effect. The six forbidden actions are refused unconditionally.
 * Throws `TypeError` only for a malformed input or an unknown action name.
 */
export function decideRecoveryAction(input) {
  const s = snapshotRecoveryInput(input, ACTION_MEMBERS);
  if (s === null || typeof s.action !== 'string' || !RECOVERY_ACTIONS.includes(s.action)) {
    throw new TypeError('recovery action input is malformed');
  }
  if (Object.hasOwn(FORBIDDEN_RECOVERY_ACTIONS, s.action)) {
    return rejectOf(FORBIDDEN_RECOVERY_ACTIONS[s.action], 'UNCHANGED', 'ACTION_GATE');
  }
  if (s.action === 'RESET_CANCEL') {
    return Object.freeze({
      accepted: false, sideEffects: 'NONE', agreement: agreementOf('ACTION_RESULT', 'UNCHANGED', 'NONE'),
    });
  }
  if (s.lock !== 'HELD') return rejectOf('LOCKED_ELSEWHERE', 'NONE', 'LOCK', 'LOCK_RETRY');
  if (s.confirmed !== true) return rejectOf('EXPLICIT_CONFIRMATION_REQUIRED', 'UNCHANGED', 'ACTION_GATE');
  if (typeof s.result !== 'string' || !RESET_ELIGIBLE_RESULTS.includes(s.result)) {
    return rejectOf('RESET_INELIGIBLE', 'UNCHANGED', 'ACTION_GATE');
  }
  if (s.disclosure !== true) return rejectOf('DISCLOSURE_REQUIRED', 'UNCHANGED', 'ACTION_GATE');
  if (s.token !== 'FRESH_BOUND_TOKEN') return rejectOf('FRESH_CONFIRMATION_REQUIRED', 'UNCHANGED', 'ACTION_GATE');
  return Object.freeze({
    accepted: true, outcome: 'ATOMIC_RESET', agreement: agreementOf('ACTION_RESULT', 'UNCHANGED', 'NONE'),
  });
}

/**
 * C-REC §5 password re-wrap decision. `lock` is optional in the record's fixtures;
 * when present and not `HELD` the non-holder learns only LOCKED_ELSEWHERE. For
 * NO_M2_STATE / LEGACY_ONLY the M2 surface is not applicable and the existing vault
 * facility is unchanged. Any other non-eligible result (including
 * RESTORED_RECONCILIATION_REQUIRED) is RESTORE_PRECONDITION_FAILED. Wrong
 * credentials are WRAPPER_AUTH_FAILED with no record oracle.
 * Throws `TypeError` only for a malformed input.
 */
export function decidePasswordRewrap(input) {
  const s = snapshotRecoveryInput(input, REWRAP_MEMBERS);
  if (s === null || typeof s.result !== 'string' || typeof s.wrapperAuthenticated !== 'boolean') {
    throw new TypeError('password re-wrap input is malformed');
  }
  if (has(s, 'lock') && s.lock !== 'HELD') return rejectOf('LOCKED_ELSEWHERE', 'NONE', 'LOCK', 'LOCK_RETRY');
  if (s.result === 'NO_M2_STATE' || s.result === 'LEGACY_ONLY') {
    return Object.freeze({
      m2RecoverySurface: 'NOT_APPLICABLE',
      existingVaultFacility: 'UNCHANGED_BY_C_REC',
      agreement: agreementOf('EXISTING_VAULT_FACILITY_UNCHANGED', 'UNCHANGED', 'NONE'),
    });
  }
  if (s.result !== 'RESTORED_ACTIVE' && s.result !== 'RESTORED_EMPTY') {
    return rejectOf('RESTORE_PRECONDITION_FAILED', 'UNCHANGED', 'ACTION_GATE');
  }
  if (s.wrapperAuthenticated !== true) {
    return Object.freeze({
      reject: 'WRAPPER_AUTH_FAILED', recordOracle: false,
      agreement: agreementOf('REJECT', 'UNCHANGED', 'WRAPPER_AUTH'),
    });
  }
  return Object.freeze({
    accepted: true, effect: 'ATOMIC_WRAPPER_REPLACEMENT_ONLY',
    agreement: agreementOf('PASSWORD_REWRAP', 'UNCHANGED', 'NONE'),
  });
}

/**
 * C-REC §9 diagnostic gate: a diagnostic may carry only the six allowlisted
 * value-free field names. Returns `{ accepted: true, fields }` or the
 * RAW_VALUE_DIAGNOSTIC rejection. Total: never throws.
 */
export function decideRecoveryDiagnostic(input) {
  const s = snapshotRecoveryInput(input, DIAGNOSTIC_MEMBERS);
  let fields = null;
  try {
    if (s !== null && Array.isArray(s.fields) && Object.getPrototypeOf(s.fields) === Array.prototype) {
      const d = Object.getOwnPropertyDescriptor(s.fields, 'length');
      const n = d && Object.hasOwn(d, 'value') ? d.value : -1;
      if (Number.isSafeInteger(n) && n >= 0 && n <= DIAGNOSTIC_MAX_FIELDS) {
        // R-WIRE (R-UX ratification item 4): the own keys are exactly the indices and `length`,
        // and every index is an own enumerable data member; anything else is not value-free.
        const keys = Reflect.ownKeys(s.fields);
        const exact = keys.length === n + 1 && keys.every((k) => typeof k === 'string'
          && (k === 'length' || (/^(0|[1-9][0-9]*)$/.test(k) && Number(k) < n)));
        const copy = [];
        for (let i = 0; exact && i < n; i += 1) {
          const e = Object.getOwnPropertyDescriptor(s.fields, String(i));
          if (!e || !Object.hasOwn(e, 'value') || e.enumerable !== true) { copy.length = 0; break; }
          copy.push(e.value);
        }
        if (exact && copy.length === n) fields = copy;
      }
    }
  } catch {
    fields = null;
  }
  if (fields === null || new Set(fields).size !== fields.length
    || fields.some((f) => typeof f !== 'string' || !DIAGNOSTIC_ALLOWED.includes(f))) {
    return rejectOf('RAW_VALUE_DIAGNOSTIC', 'NONE', 'DIAGNOSTIC_GATE');
  }
  return Object.freeze({
    accepted: true, fields: Object.freeze(fields), agreement: agreementOf('ACTION_RESULT', 'UNCHANGED', 'NONE'),
  });
}

/**
 * C-REC BOUNDARY facts for the two re-wrap crash boundaries and the interrupted
 * reset. Returns the fixture-shaped fact, or `null` for an unknown boundary.
 */
export function recoveryBoundary(boundary) {
  const boundaryAgreement = agreementOf('BOUNDARY_RESULT', 'NONE', 'NONE');
  if (boundary === 'REWRAP_BEFORE_ATOMIC_REPLACEMENT') {
    return Object.freeze({ wrapper: 'OLD_VALID_WRAPPER', m2State: 'BYTE_IDENTICAL', agreement: boundaryAgreement });
  }
  if (boundary === 'REWRAP_AFTER_ATOMIC_REPLACEMENT') {
    return Object.freeze({ wrapper: 'NEW_VALID_WRAPPER', m2State: 'BYTE_IDENTICAL', agreement: boundaryAgreement });
  }
  if (boundary === 'DURING_RESET') {
    return Object.freeze({
      classificationSource: 'NEXT_COMPLETE_C_REST_RESULT_ONLY',
      authority: 'NONE',
      automaticCompletion: false,
      cleanup: 'NONE',
      agreement: boundaryAgreement,
    });
  }
  return null;
}

// ---------------------------------------------------------------------------
// R-WIRE: vault-level unlock failures → C-REST fault (card R-WIRE, #317).
//
// Owner interpretation #317 comment 6022947656 (R-WIRE Q1 = A): for C-REST,
// `WRAPPER_AUTH` ("Unlock and authenticate the existing wrapper") completes only
// when `vault.unlock()` completes. A `VAULT_MANIFEST_TAMPERED` failure, including
// `schema-downgrade`, raised after a successful unwrap is the
// `wrapperWrongOrInvalid` fault: reset-ineligible, its only reset the existing
// `destroy()`. The distinct vault code may drive vault-lifecycle wording only,
// never C-REC diagnostics.
//
// This is a pure, total mapping. It does no I/O and does not classify: the
// caller feeds the fault to the C-REST classifier, and may do so only for the
// rejection of the same `unlock()` call whose run is being classified, after
// LOCK, BUILD_ELIGIBILITY and INVENTORY (= M2) have genuinely passed.
// ---------------------------------------------------------------------------

const UNLOCK_FAULT_UNREAD = Symbol('unread');

// Own data member of a non-null object, or UNLOCK_FAULT_UNREAD when absent. An
// accessor is never invoked: it throws, and the caller maps every throw to null.
function ownDataMember(obj, key) {
  const d = Object.getOwnPropertyDescriptor(obj, key);
  if (d === undefined) return UNLOCK_FAULT_UNREAD;
  if (!Object.hasOwn(d, 'value')) throw new TypeError('accessor member');
  return d.value;
}

const unlockDetailMatches = (detail, reason, field) => {
  if (detail === 'ANY') return true;
  if (detail === 'NO_REASON') return reason === UNLOCK_FAULT_UNREAD;
  if (detail === 'FIELD') return typeof field === 'string';
  if (detail.startsWith('REASON_EXCEPT:')) {
    return typeof reason === 'string' && reason !== detail.slice('REASON_EXCEPT:'.length);
  }
  if (detail.startsWith('REASON:')) return reason === detail.slice('REASON:'.length);
  return false;
};

/**
 * The C-REST fault that the rejection of ONE `vault.unlock()` call stands for, or
 * `null` when that rejection is not C-REST evidence (no complete C-REST result may
 * be formed from it: a caller precondition, an interruption, or an unrecognised or
 * infrastructure failure). Accepts only a `VaultCryptoError`; reads `code`,
 * `details`, `details.reason` and `details.field` through own data descriptors and
 * never invokes an accessor. Total: never throws.
 */
export function vaultUnlockRestoreFault(error) {
  try {
    if (!(error instanceof VaultCryptoError)) return null;
    const code = ownDataMember(error, 'code');
    if (typeof code !== 'string') return null;
    const details = ownDataMember(error, 'details');
    let reason = UNLOCK_FAULT_UNREAD;
    let field = UNLOCK_FAULT_UNREAD;
    if (details !== UNLOCK_FAULT_UNREAD && details !== undefined) {
      if (details === null || typeof details !== 'object' || Array.isArray(details)
        || Object.getPrototypeOf(details) !== Object.prototype) {
        return null;
      }
      reason = ownDataMember(details, 'reason');
      field = ownDataMember(details, 'field');
    }
    for (const row of VAULT_UNLOCK_FAULT_ROWS) {
      if (row.code === code && unlockDetailMatches(row.detail, reason, field)) return row.fault;
    }
    return null;
  } catch {
    return null;
  }
}
