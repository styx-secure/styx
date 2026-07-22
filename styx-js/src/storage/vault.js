// vault.js — empty-vault lifecycle state machine (Blocco 3, PR-5 / US-006).
// Pure factory `createVault({ db, deriveKek, randomBytes, todayIso })`: it owns
// the §3 state machine and the seven lifecycle operations, orchestrating the
// FROZEN PR-2 wrapper/manifest modules and the PR-4 IndexedDB engine. No
// worker-protocol wiring here — that is a later PR; keeping this off the frozen
// PR-3 boundary.
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
  deriveManifestKey, signManifestBytes, verifyManifestBytes, VAULT_KEY_VERSION,
} from '../crypto/vault-keys.js';
import { buildManifestCanonicalBytes, encodeBase64, decodeCanonicalBase64 } from '../crypto/vault-aad.js';
import { KDF_PROFILES, KDF_POLICY } from '../crypto/kdf-bounds.js';
import { constantTimeEqual, uuidv4 } from '../utils.js';

export const VAULT_STATES = Object.freeze({
  UNINITIALIZED: 'UNINITIALIZED',
  LOCKED: 'LOCKED',
  UNLOCKING: 'UNLOCKING',
  UNLOCKED: 'UNLOCKED',
  LOCKING: 'LOCKING',
  RECOVERING: 'RECOVERING',
  DESTROYING: 'DESTROYING',
  ERROR: 'ERROR',
  // Enum-only in this story: the MIGRATE trigger is out of scope (no
  // localStorage migration), rejected fail-closed by the state machine.
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
const VAULT_SCHEMA_VERSION = 1;
const MIGRATION_VERSION = 1; // no migration has run for a fresh vault

// Password policy (plan §B3.0.4): 8–1024 characters.
const PASSWORD_MIN = 8;
const PASSWORD_MAX = 1024;

const wrongState = (message, details) => new VaultCryptoError(Codes.WRONG_STATE, message, details);

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
  let loadPromise = null;
  const utf8 = new TextEncoder();

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
  };

  // Build a signed manifest v1 record for the given generation. K_manifest is
  // derived from the in-memory Root Key, so this only runs while unlocked.
  const buildManifest = async (gen) => {
    const manifestKey = await deriveManifestKey(rootKey, VAULT_KEY_VERSION);
    const fields = {
      format: MANIFEST_FORMAT,
      version: MANIFEST_VERSION,
      schemaVersion: VAULT_SCHEMA_VERSION,
      migrationVersion: MIGRATION_VERSION,
      generation: gen,
      lastTxId: uuidv4(),
    };
    const mac = await signManifestBytes(manifestKey, buildManifestCanonicalBytes(fields));
    return { ...fields, hmacB64: encodeBase64(mac) };
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
    const manifestKey = await deriveManifestKey(rootKey, VAULT_KEY_VERSION);
    try {
      // verifyManifestBytes returns true or THROWS on any deviation (one code).
      await verifyManifestBytes(manifestKey, canonical, mac);
    } catch { return { ok: false }; }
    return { ok: true, generation: stored.generation };
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
      const manifest = await buildManifest(nextGen);
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
        const manifest = await buildManifest(1);
        // Wrapper + manifest are written atomically (spec §11).
        await db.transaction([META_STORE], (ops) => {
          ops.put(META_STORE, WRAPPER_KEY, wrapper);
          ops.put(META_STORE, MANIFEST_KEY, manifest);
        });
        generation = 1;
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

    /** Explicit MIGRATE trigger is out of scope for this story (fail-closed). */
    async migrate() {
      await ensureLoaded();
      throw wrongState('migration is not available in this build', { reason: 'migrate-out-of-scope' });
    },

    /**
     * Factory reset. From ANY state, INCLUDING a failed/ERROR load: a malformed
     * persisted wrapper must still be resettable through the lifecycle API
     * (§3 "any → DESTROYING"), so a failed load never blocks DESTROY.
     */
    async destroy() {
      try { await ensureLoaded(); } catch { state = VAULT_STATES.ERROR; }
      state = VAULT_STATES.DESTROYING;
      try {
        await db.destroy();
      } finally {
        wipeRootKey();
      }
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

  return Object.freeze(api);
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
