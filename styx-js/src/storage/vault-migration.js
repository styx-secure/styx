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

const invalid = (code, message) => new SettingsMigrationError(code, message);
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
