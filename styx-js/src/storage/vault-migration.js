// vault-migration.js — strict, data-only helpers for the first product
// namespace migration (US-009 / B3.7). This module performs no I/O: the page
// owns the two allowlisted localStorage reads, while the worker owns crypto,
// IndexedDB records, markers and manifest updates.

import { snapshotStrictPlainObject } from '../crypto/vault-shape.js';

export const SETTINGS_NAMESPACE = 'settings';
export const SETTINGS_RECORD_KEY = 'preferences';
export const SETTINGS_MARKER_KEY = 'settings';
export const SETTINGS_PAYLOAD_VERSION = 1;
export const SETTINGS_CONTENT_TYPE = 'json';

export const IDENTITY_NAMESPACE = 'identity';
export const IDENTITY_RECORD_KEY = 'self';
export const IDENTITY_MARKER_KEY = 'identity';
export const IDENTITY_CONTENT_TYPE = 'json';
export const LEGACY_IDENTITY_KEY = 'styxchat:styx:identity';
export const IDENTITY_PAYLOAD_VERSION = 1;
export const IDENTITY_PBKDF2_ITERATIONS = 210000;

export const LEGACY_THEME_KEY = 'styx-theme';
export const LEGACY_INSTALL_DISMISSED_KEY = 'styx-install-dismissed';
export const LEGACY_SETTINGS_KEYS = Object.freeze([
  LEGACY_THEME_KEY,
  LEGACY_INSTALL_DISMISSED_KEY,
]);

export const SETTINGS_MIGRATION_STATES = Object.freeze([
  'pending', 'written', 'verified',
]);

const SETTINGS_KEYS = Object.freeze(['v', 'theme', 'installHintDismissed']);
const IDENTITY_KEYS = Object.freeze(['v', 'iterations', 'salt', 'iv', 'ct']);
const LEGACY_INPUT_KEYS = Object.freeze(['theme', 'installHintDismissed']);
const MARKER_KEYS = Object.freeze(['version', 'namespace', 'state', 'counts', 'digests']);
const COUNT_KEYS = Object.freeze(['source', 'written']);
const DIGEST_KEYS = Object.freeze(['source', 'vault']);
const SHA256_HEX = /^[0-9a-f]{64}$/;

export class SettingsMigrationError extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.name = 'SettingsMigrationError';
    this.code = code;
  }
}

export class IdentityMigrationError extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.name = 'IdentityMigrationError';
    this.code = code;
  }
}

const invalid = (code, message) => new SettingsMigrationError(code, message);
const invalidIdentity = (code, message) => new IdentityMigrationError(code, message);
const strict = (raw, keys, code, requiredKeys = keys) => snapshotStrictPlainObject(
  raw,
  keys,
  () => invalid(code, 'value has an invalid shape'),
  { requiredKeys },
);

/** Read exactly the two contract-authorized keys; never enumerate storage. */
export function readLegacySettings(storage) {
  if (storage === null || typeof storage !== 'object' || typeof storage.getItem !== 'function') {
    throw invalid('SETTINGS_STORAGE_UNAVAILABLE', 'a storage reader is required');
  }
  return Object.freeze({
    theme: storage.getItem(LEGACY_THEME_KEY),
    installHintDismissed: storage.getItem(LEGACY_INSTALL_DISMISSED_KEY),
  });
}

/** Strict legacy parser. Unknown historical values remain legacy-only. */
export function normalizeLegacySettings(raw) {
  const s = strict(raw, LEGACY_INPUT_KEYS, 'SETTINGS_LEGACY_INVALID');
  if (s.theme !== null && s.theme !== 'light' && s.theme !== 'dark') {
    throw invalid('SETTINGS_LEGACY_INVALID', 'theme is not allowlisted');
  }
  if (s.installHintDismissed !== null && s.installHintDismissed !== '1') {
    throw invalid('SETTINGS_LEGACY_INVALID', 'install hint value is not allowlisted');
  }
  return Object.freeze({
    v: SETTINGS_PAYLOAD_VERSION,
    theme: s.theme ?? 'system',
    installHintDismissed: s.installHintDismissed === '1',
  });
}

/** Re-validate the page-normalized object at the worker/lifecycle boundary. */
export function validateSettingsPreferences(raw) {
  const s = strict(raw, SETTINGS_KEYS, 'SETTINGS_PAYLOAD_INVALID');
  if (s.v !== SETTINGS_PAYLOAD_VERSION) {
    throw invalid('SETTINGS_PAYLOAD_INVALID', 'unsupported settings version');
  }
  if (!['system', 'light', 'dark'].includes(s.theme)) {
    throw invalid('SETTINGS_PAYLOAD_INVALID', 'theme is not allowlisted');
  }
  if (typeof s.installHintDismissed !== 'boolean') {
    throw invalid('SETTINGS_PAYLOAD_INVALID', 'install hint flag must be boolean');
  }
  // Property insertion order is the frozen canonical JSON order.
  return Object.freeze({
    v: SETTINGS_PAYLOAD_VERSION,
    theme: s.theme,
    installHintDismissed: s.installHintDismissed,
  });
}

export function canonicalSettingsJson(raw) {
  return JSON.stringify(validateSettingsPreferences(raw));
}

export function canonicalSettingsBytes(raw) {
  return new TextEncoder().encode(canonicalSettingsJson(raw));
}

export function settingsEqual(a, b) {
  return canonicalSettingsJson(a) === canonicalSettingsJson(b);
}

export function buildSettingsMarker(state, digest) {
  if (!SETTINGS_MIGRATION_STATES.includes(state) || !SHA256_HEX.test(digest)) {
    throw invalid('SETTINGS_MARKER_INVALID', 'marker inputs are invalid');
  }
  const written = state === 'pending' ? 0 : 1;
  return Object.freeze({
    version: 1,
    namespace: SETTINGS_NAMESPACE,
    state,
    counts: Object.freeze({ source: 1, written }),
    digests: Object.freeze({ source: digest, vault: written === 1 ? digest : null }),
  });
}

export function validateSettingsMarker(raw) {
  const s = strict(raw, MARKER_KEYS, 'SETTINGS_MARKER_INVALID');
  const counts = strict(s.counts, COUNT_KEYS, 'SETTINGS_MARKER_INVALID');
  const digests = strict(s.digests, DIGEST_KEYS, 'SETTINGS_MARKER_INVALID');
  if (s.version !== 1 || s.namespace !== SETTINGS_NAMESPACE
    || !SETTINGS_MIGRATION_STATES.includes(s.state)
    || counts.source !== 1
    || !Number.isSafeInteger(counts.written)
    || !SHA256_HEX.test(digests.source)
    || (digests.vault !== null && !SHA256_HEX.test(digests.vault))) {
    throw invalid('SETTINGS_MARKER_INVALID', 'marker fields are invalid');
  }
  const expectedWritten = s.state === 'pending' ? 0 : 1;
  if (counts.written !== expectedWritten
    || (expectedWritten === 0 && digests.vault !== null)
    || (expectedWritten === 1 && digests.vault !== digests.source)) {
    throw invalid('SETTINGS_MARKER_INVALID', 'marker state is inconsistent');
  }
  return buildSettingsMarker(s.state, digests.source);
}

function canonicalBase64(raw, expectedBytes) {
  if (typeof raw !== 'string' || raw.length === 0
    || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(raw)) {
    throw invalidIdentity('IDENTITY_PAYLOAD_INVALID', 'identity field is not canonical base64');
  }
  let binary;
  try { binary = atob(raw); } catch {
    throw invalidIdentity('IDENTITY_PAYLOAD_INVALID', 'identity field is not canonical base64');
  }
  if (binary.length !== expectedBytes || btoa(binary) !== raw) {
    throw invalidIdentity('IDENTITY_PAYLOAD_INVALID', 'identity field has an invalid decoded length');
  }
  return raw;
}

/** Read exactly the default-profile encrypted identity envelope. */
export function readLegacyIdentity(storage) {
  if (storage === null || typeof storage !== 'object' || typeof storage.getItem !== 'function') {
    throw invalidIdentity('IDENTITY_STORAGE_UNAVAILABLE', 'a storage reader is required');
  }
  const raw = storage.getItem(LEGACY_IDENTITY_KEY);
  if (raw === null) return null;
  if (typeof raw !== 'string') {
    throw invalidIdentity('IDENTITY_LEGACY_INVALID', 'legacy identity must be serialized JSON');
  }
  let parsed;
  try { parsed = JSON.parse(raw); } catch {
    throw invalidIdentity('IDENTITY_LEGACY_INVALID', 'legacy identity is not valid JSON');
  }
  try { return validateIdentityEnvelope(parsed); } catch (error) {
    if (error instanceof IdentityMigrationError) {
      throw invalidIdentity('IDENTITY_LEGACY_INVALID', 'legacy identity envelope is invalid');
    }
    throw error;
  }
}

/** Strict legacy-envelope snapshot, repeated at the worker lifecycle boundary. */
export function validateIdentityEnvelope(raw) {
  const s = snapshotStrictPlainObject(
    raw,
    IDENTITY_KEYS,
    () => invalidIdentity('IDENTITY_PAYLOAD_INVALID', 'identity envelope has an invalid shape'),
  );
  if (s.v !== IDENTITY_PAYLOAD_VERSION || s.iterations !== IDENTITY_PBKDF2_ITERATIONS) {
    throw invalidIdentity('IDENTITY_PAYLOAD_INVALID', 'identity envelope version is unsupported');
  }
  return Object.freeze({
    v: IDENTITY_PAYLOAD_VERSION,
    iterations: IDENTITY_PBKDF2_ITERATIONS,
    salt: canonicalBase64(s.salt, 16),
    iv: canonicalBase64(s.iv, 12),
    ct: canonicalBase64(s.ct, 48),
  });
}

export function canonicalIdentityJson(raw) {
  return JSON.stringify(validateIdentityEnvelope(raw));
}

export function canonicalIdentityBytes(raw) {
  return new TextEncoder().encode(canonicalIdentityJson(raw));
}

export function identityEqual(a, b) {
  return canonicalIdentityJson(a) === canonicalIdentityJson(b);
}

export function buildIdentityMarker(state, digest) {
  if (!SETTINGS_MIGRATION_STATES.includes(state) || !SHA256_HEX.test(digest)) {
    throw invalidIdentity('IDENTITY_MARKER_INVALID', 'marker inputs are invalid');
  }
  const written = state === 'pending' ? 0 : 1;
  return Object.freeze({
    version: 1,
    namespace: IDENTITY_NAMESPACE,
    state,
    counts: Object.freeze({ source: 1, written }),
    digests: Object.freeze({ source: digest, vault: written === 1 ? digest : null }),
  });
}

export function validateIdentityMarker(raw) {
  const strictIdentity = (value, keys) => snapshotStrictPlainObject(
    value,
    keys,
    () => invalidIdentity('IDENTITY_MARKER_INVALID', 'marker has an invalid shape'),
  );
  const s = strictIdentity(raw, MARKER_KEYS);
  const counts = strictIdentity(s.counts, COUNT_KEYS);
  const digests = strictIdentity(s.digests, DIGEST_KEYS);
  if (s.version !== 1 || s.namespace !== IDENTITY_NAMESPACE
    || !SETTINGS_MIGRATION_STATES.includes(s.state)
    || counts.source !== 1
    || !Number.isSafeInteger(counts.written)
    || !SHA256_HEX.test(digests.source)
    || (digests.vault !== null && !SHA256_HEX.test(digests.vault))) {
    throw invalidIdentity('IDENTITY_MARKER_INVALID', 'marker fields are invalid');
  }
  const expectedWritten = s.state === 'pending' ? 0 : 1;
  if (counts.written !== expectedWritten
    || (expectedWritten === 0 && digests.vault !== null)
    || (expectedWritten === 1 && digests.vault !== digests.source)) {
    throw invalidIdentity('IDENTITY_MARKER_INVALID', 'marker state is inconsistent');
  }
  return buildIdentityMarker(s.state, digests.source);
}
