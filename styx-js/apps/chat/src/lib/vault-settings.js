// Stage-gated settings bridge. localStorage remains the rollback copy; the
// dedicated worker owns encryption, IndexedDB and migration markers.

import {
  LEGACY_THEME_KEY, LEGACY_INSTALL_DISMISSED_KEY,
  SettingsMigrationError, readLegacySettings, normalizeLegacySettings,
  settingsEqual,
} from '../../../../src/storage/vault-migration.js';
import { loadVaultLifecycle } from '../../../../src/config/vault-stage.js';

const safeDiagnostic = (raw = {}) => Object.freeze({
  code: typeof raw.code === 'string' ? raw.code.slice(0, 64) : 'SETTINGS_SYNC_FAILED',
  phase: typeof raw.phase === 'string' ? raw.phase.slice(0, 64) : 'settings',
  markerState: typeof raw.markerState === 'string' ? raw.markerState.slice(0, 64) : 'unknown',
  mismatch: raw.mismatch === true,
  sourceCount: Number.isSafeInteger(raw.sourceCount) ? raw.sourceCount : 0,
  writtenCount: Number.isSafeInteger(raw.writtenCount) ? raw.writtenCount : 0,
  digest: typeof raw.digest === 'string' && /^[0-9a-f]{64}$/.test(raw.digest) ? raw.digest : '',
});

function defaultDiagnostic(event) {
  // Local-only, bounded and value-free. Never pass the caught exception.
  console.debug('[styx-vault-settings]', event);
}

function errorCode(error) {
  return typeof error?.code === 'string' ? error.code : 'SETTINGS_SYNC_FAILED';
}

/**
 * Data-only coordinator shared by the production opener and deterministic
 * tests. `request` is the already-open worker boundary; no crypto or storage
 * implementation can be injected into the production worker itself.
 */
export function createVaultSettingsCoordinator({
  storage,
  request,
  stop = () => {},
  onDiagnostic = defaultDiagnostic,
}) {
  const emit = (event) => onDiagnostic(safeDiagnostic(event));
  let current = null;

  async function synchronize() {
    let preferences;
    try {
      preferences = normalizeLegacySettings(readLegacySettings(storage));
    } catch (error) {
      emit({ code: errorCode(error), phase: 'legacy-read', markerState: 'unknown' });
      return Object.freeze({ synchronized: false, preferences: null });
    }

    try {
      const migration = await request('MIGRATE', {
        namespace: 'settings', preferences,
      });
      const read = await request('GET', {
        namespace: 'settings', recordKey: 'preferences',
      });
      const matched = migration?.state === 'verified'
        && migration.matched === true
        && read?.found === true
        && settingsEqual(read.record?.value, preferences);
      emit({
        code: matched ? 'SETTINGS_SYNC_VERIFIED' : 'SETTINGS_DIVERGENCE',
        phase: 'verify',
        markerState: migration?.state,
        mismatch: !matched,
        sourceCount: 1,
        writtenCount: matched ? 1 : 0,
      });
      if (!matched) return Object.freeze({ synchronized: false, preferences });
      current = read.record.value;
      return Object.freeze({ synchronized: true, preferences: current });
    } catch (error) {
      emit({ code: errorCode(error), phase: 'migrate', markerState: 'unknown' });
      current = preferences; // legacy remains authoritative
      return Object.freeze({ synchronized: false, preferences });
    }
  }

  async function writeLegacyThenSync(key, value) {
    try {
      storage.setItem(key, value);
    } catch {
      emit({ code: 'SETTINGS_LEGACY_WRITE_FAILED', phase: 'legacy-write', markerState: 'unknown' });
      return Object.freeze({ synchronized: false, preferences: current });
    }
    return synchronize();
  }

  return Object.freeze({
    synchronize,
    setTheme: (theme) => {
      if (theme !== 'light' && theme !== 'dark') {
        throw new SettingsMigrationError('SETTINGS_PAYLOAD_INVALID', 'theme is not allowlisted');
      }
      return writeLegacyThenSync(LEGACY_THEME_KEY, theme);
    },
    dismissInstallHint: () => writeLegacyThenSync(LEGACY_INSTALL_DISMISSED_KEY, '1'),
    stop,
  });
}

/**
 * Open the fixed product vault for the default profile only. Returns null when
 * the build flag is off or a non-default peer test namespace is active.
 */
export async function openVaultSettings({
  password,
  peerProfile = '',
  storage = globalThis.localStorage,
  onDiagnostic = defaultDiagnostic,
} = {}) {
  if (peerProfile !== '') return null;
  const workerModule = await loadVaultLifecycle();
  if (!workerModule) return null;

  const supervisor = workerModule.createProductVaultWorkerSupervisor();

  try {
    await supervisor.start();
    const status = await supervisor.request('STATUS');
    if (status.vaultState === 'UNINITIALIZED') {
      await supervisor.request('CREATE_VAULT', {
        password,
        ...(import.meta.env.VITE_VAULT_STAGE === 'test-profile' ? { profile: 'mobile-low-memory' } : {}),
      });
    } else if (status.vaultState === 'LOCKED') {
      await supervisor.request('UNLOCK', { password });
    } else if (status.vaultState !== 'UNLOCKED') {
      throw new SettingsMigrationError('SETTINGS_VAULT_STATE_INVALID', 'vault is not available');
    }
  } catch (error) {
    supervisor.stop();
    throw error;
  }

  const coordinator = createVaultSettingsCoordinator({
    storage,
    request: (type, payload) => supervisor.request(type, payload),
    stop: () => supervisor.shutdown(),
    onDiagnostic,
  });
  const initial = await coordinator.synchronize();
  return Object.freeze({ ...coordinator, initial });
}
