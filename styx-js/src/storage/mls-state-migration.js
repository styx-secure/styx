// mls-state-migration.js — safe migration of the legacy `mls:state` value to envelope v1.
//
// Implements the 12-step sequence and the resume matrix of
// docs/architecture/mls-state-migration-policy.md §5: back up the legacy value first,
// round-trip-parse and restore-probe the new envelope BEFORE overwriting anything, and
// drop the backup only after the written value re-reads clean. A failure at any step
// leaves the legacy value (and its backup) in place and raises a structured error —
// never a partial state, never a deleted session, never a silent fresh start.
//
// localStorage gives single-key atomicity only (each set succeeds or throws, no
// multi-key transactions): the step ordering exists precisely so that any interruption
// leaves the key set in a state the resume matrix recognizes.

import {
  MLS_ENVELOPE_VERSION,
  MlsStateError,
  MlsStateErrorCodes,
  detectMlsStateFormat,
  encodeMlsStateEnvelope,
  parseMlsStateEnvelope,
} from './mls-state-envelope.js';
import { MLS_BUILD_INFO } from '../crypto/mls/mls-build-info.js';
import { base64ToBytes } from '../utils.js';

/** Backend keys (namespaced by the backend's own prefix, i.e. per profile). */
export const MLS_STATE_KEY = 'mls:state';
export const MLS_MIGRATION_PENDING_KEY = 'mls:state:migration:pending';
export const MLS_MIGRATION_BACKUP_KEY = 'mls:state:migration:backup';
export const MLS_MIGRATION_VERSION_KEY = 'mls:state:migration:version';

/**
 * Migrate a legacy base64 `mls:state` value to envelope v1, safely.
 *
 * PRECONDITION: the caller holds the exclusive MLS writer Web Lock (`styx-mls:<ns>`,
 * acquired by the app for the whole session lifetime BEFORE init — Web Locks are not
 * reentrant, so this function inherits it and must not re-acquire it). A tab that is
 * not the writer must not call this.
 *
 * Re-running on an already-migrated state is a no-op that verifies the stored envelope
 * and sweeps leftover markers (crash between steps 9 and 12). Retrying after a failure
 * is safe: the legacy value is still the source of truth until step 9 succeeds.
 *
 * @param {object} opts
 * @param {{get:Function,set:Function,delete:Function}} opts.backend namespaced KV
 * @param {(stateBytes: Uint8Array) => Promise<void>} opts.restoreProbe throws if the
 *   current runtime cannot interpret the bytes (e.g. wraps MlsEngine.restore)
 * @param {object} [opts.buildInfo]
 * @returns {Promise<{migrated: boolean, envelope: object}>}
 * @throws {MlsStateError}
 */
export async function migrateLegacyMlsState({ backend, restoreProbe, buildInfo = MLS_BUILD_INFO }) {
  const { INVALID, CORRUPTED, MIGRATION_FAILED } = MlsStateErrorCodes;
  if (!backend || typeof restoreProbe !== 'function') {
    throw new MlsStateError(INVALID, 'migrateLegacyMlsState needs a backend and a restoreProbe');
  }

  const value = await backend.get(MLS_STATE_KEY);
  const fmt = detectMlsStateFormat(value);

  if (fmt === 'envelope') {
    // Resume path: either a crash between steps 9 and 12 left markers behind, or the
    // migration already completed. Verify the stored envelope BEFORE sweeping.
    const { envelope } = parseMlsStateEnvelope(value);
    await backend.set(MLS_MIGRATION_VERSION_KEY, MLS_ENVELOPE_VERSION);
    await backend.delete(MLS_MIGRATION_PENDING_KEY);
    await backend.delete(MLS_MIGRATION_BACKUP_KEY);
    return { migrated: false, envelope };
  }
  if (fmt !== 'legacy-base64') {
    throw new MlsStateError(INVALID, `nothing to migrate: state format is "${fmt}"`);
  }

  let step = 'backup';
  try {
    // 3. Keep an intact copy of the legacy value, and mark the migration as running.
    await backend.set(MLS_MIGRATION_BACKUP_KEY, value);
    await backend.set(MLS_MIGRATION_PENDING_KEY, { toVersion: MLS_ENVELOPE_VERSION });

    // 4. The legacy payload must decode to real bytes.
    step = 'decode-legacy';
    const stateBytes = base64ToBytes(value);
    if (stateBytes.length === 0) {
      throw new MlsStateError(CORRUPTED, 'legacy state decodes to zero bytes');
    }

    // 5–7. Build the envelope and prove it survives the backend's JSON round-trip.
    step = 'encode';
    const envelope = encodeMlsStateEnvelope(stateBytes, buildInfo);
    step = 'roundtrip-parse';
    parseMlsStateEnvelope(JSON.parse(JSON.stringify(envelope)));

    // 8. Prove the CURRENT runtime can actually restore from this payload — before
    //    anything is overwritten, so a probe failure costs nothing.
    step = 'restore-probe';
    await restoreProbe(stateBytes);

    // 9–10. Write, then re-read and re-verify what was actually stored.
    step = 'write';
    await backend.set(MLS_STATE_KEY, envelope);
    step = 'verify-written';
    const written = await backend.get(MLS_STATE_KEY);
    const reparsed = parseMlsStateEnvelope(written);
    if (reparsed.envelope.payload !== envelope.payload) {
      throw new MlsStateError(CORRUPTED, 'written envelope does not match what was encoded');
    }

    // 11–12. Mark done; only now drop the temporary copy of the legacy value.
    step = 'finalize';
    await backend.set(MLS_MIGRATION_VERSION_KEY, MLS_ENVELOPE_VERSION);
    await backend.delete(MLS_MIGRATION_PENDING_KEY);
    await backend.delete(MLS_MIGRATION_BACKUP_KEY);
    return { migrated: true, envelope };
  } catch (err) {
    // No rollback writes here: before step 9 the legacy value is untouched; after it
    // the stored envelope has already been fully validated and probed, and the resume
    // path completes the sweep on retry. The backup stays until a migration finishes.
    throw new MlsStateError(MIGRATION_FAILED, `legacy MLS state migration failed at step "${step}"`, {
      step,
      causeCode: err instanceof MlsStateError ? err.code : undefined,
      causeMessage: err?.message,
    });
  }
}
