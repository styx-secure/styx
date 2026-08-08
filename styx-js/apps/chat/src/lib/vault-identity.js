// Stage-gated identity shadow migration. The encrypted localStorage envelope
// remains the sole runtime source of truth; this coordinator only proves that
// an authenticated vault copy can be written and read back before networking.

import {
  IdentityMigrationError,
  readLegacyIdentity,
  identityEqual,
} from '../../../../src/storage/vault-migration.js';

const safeDiagnostic = (raw = {}) => Object.freeze({
  code: typeof raw.code === 'string' ? raw.code.slice(0, 64) : 'IDENTITY_SYNC_FAILED',
  phase: typeof raw.phase === 'string' ? raw.phase.slice(0, 64) : 'identity',
  markerState: typeof raw.markerState === 'string' ? raw.markerState.slice(0, 64) : 'unknown',
  mismatch: raw.mismatch === true,
  sourceCount: Number.isSafeInteger(raw.sourceCount) ? raw.sourceCount : 0,
  writtenCount: Number.isSafeInteger(raw.writtenCount) ? raw.writtenCount : 0,
});

function defaultDiagnostic(event) {
  // Local-only, bounded and value-free. Never pass identity bytes or exceptions.
  console.debug('[styx-vault-identity]', event);
}

function errorCode(error) {
  return typeof error?.code === 'string' ? error.code : 'IDENTITY_SYNC_FAILED';
}

/**
 * Coordinate the page-owned legacy read with the already-open product worker.
 * Failure is reported but never removes or replaces the legacy identity.
 */
export function createVaultIdentityCoordinator({
  storage,
  request,
  onDiagnostic = defaultDiagnostic,
}) {
  if (typeof request !== 'function') {
    throw new IdentityMigrationError('IDENTITY_WORKER_UNAVAILABLE', 'a worker request function is required');
  }
  const emit = (event) => onDiagnostic(safeDiagnostic(event));

  async function synchronize({ pairingActive } = {}) {
    let identity;
    try {
      identity = readLegacyIdentity(storage);
    } catch (error) {
      emit({ code: errorCode(error), phase: 'legacy-read', markerState: 'unknown' });
      return Object.freeze({ synchronized: false, present: true });
    }

    if (identity === null) {
      emit({
        code: 'IDENTITY_NOT_PRESENT', phase: 'legacy-read', markerState: 'absent',
        sourceCount: 0, writtenCount: 0,
      });
      return Object.freeze({ synchronized: false, present: false });
    }

    try {
      const migration = await request('MIGRATE', {
        namespace: 'identity', identity, pairingActive,
      });
      const read = await request('GET', {
        namespace: 'identity', recordKey: 'self',
      });
      let readbackEqual = false;
      try { readbackEqual = identityEqual(read.record?.value, identity); } catch { /* divergence */ }
      const matched = migration?.state === 'verified'
        && migration.matched === true
        && read?.found === true
        && readbackEqual;
      emit({
        code: matched ? 'IDENTITY_SYNC_VERIFIED' : 'IDENTITY_DIVERGENCE',
        phase: 'verify',
        markerState: migration?.state,
        mismatch: !matched,
        sourceCount: 1,
        writtenCount: matched ? 1 : 0,
      });
      return Object.freeze({ synchronized: matched, present: true });
    } catch (error) {
      emit({ code: errorCode(error), phase: 'migrate', markerState: 'unknown' });
      return Object.freeze({ synchronized: false, present: true });
    }
  }

  return Object.freeze({ synchronize });
}
