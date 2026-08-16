// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — bounded concurrent-fork proof constants.

export const B33B2B_ERROR = Object.freeze({
  BLOCKED: 'B33B2B_BLOCKED',
  CAS_CONFLICT: 'B33B2B_CAS_CONFLICT',
  CORRUPT: 'B33B2B_CORRUPT',
  DUPLICATE_INITIALIZATION: 'B33B2B_DUPLICATE_INITIALIZATION',
  ENGINE_REJECTED: 'B33B2B_ENGINE_REJECTED',
  INVALID: 'B33B2B_INVALID',
  MDK_BEHAVIOR_DRIFT: 'B33B2B_MDK_BEHAVIOR_DRIFT',
  PERSISTENCE_FAILED: 'B33B2B_PERSISTENCE_FAILED',
  PIN_DRIFT: 'B33B2B_PIN_DRIFT',
  RESOURCE_LIMIT: 'B33B2B_RESOURCE_LIMIT',
  STATE_CONFLICT: 'B33B2B_STATE_CONFLICT',
  UNRECOVERABLE: 'B33B2B_UNRECOVERABLE',
});

export const B33B2B_STATE = Object.freeze({
  ACTIVATED: 'ACTIVATED',
  LOCAL_BRANCH_DURABLE: 'LOCAL_BRANCH_DURABLE',
  RIVAL_RECORDED: 'RIVAL_RECORDED',
  RACE_FROZEN: 'RACE_FROZEN',
  SETTLEMENT_PREPARED: 'SETTLEMENT_PREPARED',
  STABLE: 'STABLE',
  UNRECOVERABLE: 'UNRECOVERABLE',
});

export const B33B2B_LIMITS = Object.freeze({
  maxBlobBytes: 8 * 1024 * 1024,
  maxCommitBytes: 1024 * 1024,
  maxHeadBytes: 1024 * 1024,
  maxStoreBytes: 64 * 1024 * 1024,
  maxTransitions: 16,
});

export class B33b2bError extends Error {
  constructor(code, message, details = undefined) {
    super(message);
    this.name = 'B33b2bError';
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

export function failB33b2b(code, message, details = undefined) {
  throw new B33b2bError(code, message, details);
}

export function compareIdentityHex(left, right) {
  if (!/^[0-9a-f]{64}$/.test(left) || !/^[0-9a-f]{64}$/.test(right) || left === right) {
    failB33b2b(B33B2B_ERROR.INVALID,
      'fork ordering requires two distinct canonical 32-byte account identities');
  }
  return left < right ? -1 : 1;
}
