import { describe, test, expect } from '@jest/globals';
import {
  LEGACY_THEME_KEY, LEGACY_INSTALL_DISMISSED_KEY,
  readLegacySettings, normalizeLegacySettings, validateSettingsPreferences,
  canonicalSettingsJson, buildSettingsMarker, validateSettingsMarker,
  SettingsMigrationError,
  LEGACY_IDENTITY_KEY, readLegacyIdentity, validateIdentityEnvelope,
  canonicalIdentityJson, identityEqual, buildIdentityMarker, validateIdentityMarker,
  IdentityMigrationError,
} from '../../src/storage/vault-migration.js';

describe('settings migration data boundary', () => {
  test('reads exactly the two allowlisted legacy keys without enumeration', () => {
    const calls = [];
    const storage = new Proxy({
      getItem(key) { calls.push(key); return key === LEGACY_THEME_KEY ? 'dark' : '1'; },
    }, {
      ownKeys() { throw new Error('storage enumeration is forbidden'); },
    });
    expect(readLegacySettings(storage)).toEqual({ theme: 'dark', installHintDismissed: '1' });
    expect(calls).toEqual([LEGACY_THEME_KEY, LEGACY_INSTALL_DISMISSED_KEY]);
  });

  test('normalizes missing values and rejects unknown, exotic, or extended input', () => {
    expect(normalizeLegacySettings({ theme: null, installHintDismissed: null })).toEqual({
      v: 1, theme: 'system', installHintDismissed: false,
    });
    expect(normalizeLegacySettings({ theme: 'light', installHintDismissed: '1' })).toEqual({
      v: 1, theme: 'light', installHintDismissed: true,
    });
    for (const bad of [
      { theme: 'sepia', installHintDismissed: null },
      { theme: null, installHintDismissed: 'true' },
      { theme: null, installHintDismissed: null, extra: true },
      Object.create({ theme: null, installHintDismissed: null }),
    ]) expect(() => normalizeLegacySettings(bad)).toThrow(SettingsMigrationError);

    let getterCalls = 0;
    const accessor = { installHintDismissed: null };
    Object.defineProperty(accessor, 'theme', {
      enumerable: true,
      get() { getterCalls += 1; return 'dark'; },
    });
    expect(() => normalizeLegacySettings(accessor)).toThrow(SettingsMigrationError);
    expect(getterCalls).toBe(0);
  });

  test('freezes a canonical payload with the exact JSON order', () => {
    const value = validateSettingsPreferences({ v: 1, theme: 'dark', installHintDismissed: true });
    expect(Object.isFrozen(value)).toBe(true);
    expect(canonicalSettingsJson(value)).toBe('{"v":1,"theme":"dark","installHintDismissed":true}');
  });

  test('marker states are exact, internally consistent, and descriptor-strict', () => {
    const digest = 'a'.repeat(64); // lifecycle supplies a K_manifest HMAC
    expect(validateSettingsMarker(buildSettingsMarker('pending', digest))).toEqual({
      version: 1, namespace: 'settings', state: 'pending',
      counts: { source: 1, written: 0 }, digests: { source: digest, vault: null },
    });
    expect(validateSettingsMarker(buildSettingsMarker('verified', digest)).state).toBe('verified');
    expect(() => validateSettingsMarker({
      ...buildSettingsMarker('verified', digest), state: 'unknown',
    })).toThrow(SettingsMigrationError);
  });
});

describe('identity migration data boundary', () => {
  const valid = Object.freeze({
    v: 1,
    iterations: 210000,
    salt: btoa('s'.repeat(16)),
    iv: btoa('i'.repeat(12)),
    ct: btoa('c'.repeat(48)),
  });

  test('reads only the fixed default-profile key and preserves missing as a no-op', () => {
    const calls = [];
    const storage = new Proxy({
      getItem(key) { calls.push(key); return JSON.stringify(valid); },
    }, { ownKeys() { throw new Error('enumeration forbidden'); } });
    expect(readLegacyIdentity(storage)).toEqual(valid);
    expect(calls).toEqual([LEGACY_IDENTITY_KEY]);
    expect(readLegacyIdentity({ getItem: () => null })).toBeNull();
  });

  test('accepts only the frozen canonical envelope and JSON order', () => {
    const value = validateIdentityEnvelope(valid);
    expect(Object.isFrozen(value)).toBe(true);
    expect(canonicalIdentityJson(value)).toBe(JSON.stringify(valid));
    expect(identityEqual(value, { ...valid })).toBe(true);
    for (const bad of [
      { ...valid, v: 2 },
      { ...valid, iterations: 1 },
      { ...valid, salt: btoa('short') },
      { ...valid, iv: `${valid.iv}=`, },
      { ...valid, ct: btoa('c'.repeat(47)) },
      { ...valid, extra: true },
      Object.create(valid),
    ]) expect(() => validateIdentityEnvelope(bad)).toThrow(IdentityMigrationError);
  });

  test('never invokes identity-envelope accessors', () => {
    let calls = 0;
    const hostile = { ...valid };
    Object.defineProperty(hostile, 'ct', {
      enumerable: true,
      get() { calls += 1; return valid.ct; },
    });
    expect(() => validateIdentityEnvelope(hostile)).toThrow(IdentityMigrationError);
    expect(calls).toBe(0);
  });

  test('rejects malformed legacy JSON without returning a replacement identity', () => {
    expect(() => readLegacyIdentity({ getItem: () => '{' })).toThrow(IdentityMigrationError);
    expect(() => readLegacyIdentity({ getItem: () => JSON.stringify({ ...valid, ct: 'bad' }) }))
      .toThrow(IdentityMigrationError);
  });

  test('identity marker is closed, consistent, and namespace-bound', () => {
    const digest = 'b'.repeat(64);
    expect(validateIdentityMarker(buildIdentityMarker('pending', digest))).toEqual({
      version: 1, namespace: 'identity', state: 'pending',
      counts: { source: 1, written: 0 }, digests: { source: digest, vault: null },
    });
    expect(validateIdentityMarker(buildIdentityMarker('verified', digest)).state).toBe('verified');
    expect(() => validateIdentityMarker({
      ...buildIdentityMarker('verified', digest), namespace: 'settings',
    })).toThrow(IdentityMigrationError);
  });
});
