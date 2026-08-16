// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — exact retained-application-window evidence contract.

import { B33B1_MAX_PAST_EPOCHS }
  from '../marmot-phase-b3-3b-1/b3-3b-1-canonical.mjs';

export const B33B2A_CLAIM = 'B3.3b-2a BOUNDED_GO';
export const B33B2A_FINAL_EPOCH = '7';
export const B33B2A_RETAINED_DISTANCES = Object.freeze([4, 5]);
export const B33B2A_REJECTED_DISTANCE = 6;
export const B33B2A_RETENTION_POLICY = B33B1_MAX_PAST_EPOCHS;

export const B33B2A_OPERATION_SEQUENCE = Object.freeze([
  'group-created-and-joined',
  'b33b1-authority-activated',
  'epoch1-distance6-prepared',
  'epoch2-mdk-update-applied',
  'future-epoch-control-rejected',
  'epoch2-distance5-prepared',
  'epoch3-styx-update-applied',
  'epoch3-distance4-prepared',
  'epoch4-mdk-update-applied',
  'epoch5-styx-update-applied',
  'epoch6-mdk-update-applied',
  'epoch7-styx-update-applied',
  'receivers-restarted',
  'corrupted-distance4-rejected',
  'distance4-delivered-exactly-once',
  'distance5-delivered-exactly-once',
  'distance6-rejected-without-mutation',
  'final-authority-verified',
]);

export class B33b2aError extends Error {
  constructor(code, message, details = undefined) {
    super(message);
    this.name = 'B33b2aError';
    this.code = code;
    this.details = details;
  }
}

export function failB33b2a(code, message, details = undefined) {
  throw new B33b2aError(code, message, details);
}

export function createB33b2aOperationTrace() {
  const observed = [];
  return Object.freeze({
    advance(name) {
      const expected = B33B2A_OPERATION_SEQUENCE[observed.length];
      if (name !== expected) {
        failB33b2a('B33B2A_BLOCKED', 'retained-window operation sequence drifted', {
          expected, observed: Object.freeze([...observed]), received: name,
        });
      }
      observed.push(name);
    },
    complete() {
      if (observed.length !== B33B2A_OPERATION_SEQUENCE.length) {
        failB33b2a('B33B2A_BLOCKED', 'retained-window operation sequence is incomplete', {
          expected: B33B2A_OPERATION_SEQUENCE,
          observed: Object.freeze([...observed]),
        });
      }
      return Object.freeze([...observed]);
    },
  });
}

