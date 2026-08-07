import { describe, test, expect } from '@jest/globals';
import {
  LEGACY_THEME_KEY, LEGACY_INSTALL_DISMISSED_KEY,
  readLegacySettings, normalizeLegacySettings, validateSettingsPreferences,
  canonicalSettingsJson, buildSettingsMarker, validateSettingsMarker,
  SettingsMigrationError,
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
