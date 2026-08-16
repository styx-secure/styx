// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — bounded concurrent-fork proof constants.

export const B33B2B_ERROR = Object.freeze({
  BLOCKED: 'B33B2B_BLOCKED',
  ENGINE_REJECTED: 'B33B2B_ENGINE_REJECTED',
  INVALID: 'B33B2B_INVALID',
  MDK_BEHAVIOR_DRIFT: 'B33B2B_MDK_BEHAVIOR_DRIFT',
  PIN_DRIFT: 'B33B2B_PIN_DRIFT',
});

export function failB33b2b(code, message, details = undefined) {
  const error = new Error(message);
  error.code = code;
  if (details !== undefined) error.details = details;
  throw error;
}

export function compareIdentityHex(left, right) {
  if (!/^[0-9a-f]{64}$/.test(left) || !/^[0-9a-f]{64}$/.test(right) || left === right) {
    failB33b2b(B33B2B_ERROR.INVALID,
      'fork ordering requires two distinct canonical 32-byte account identities');
  }
  return left < right ? -1 : 1;
}
