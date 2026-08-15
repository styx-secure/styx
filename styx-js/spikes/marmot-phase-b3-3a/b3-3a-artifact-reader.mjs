// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — descriptor-bound exact artifact reads.

import { createHash } from 'node:crypto';
import {
  closeSync,
  constants,
  fstatSync,
  openSync,
  readFileSync,
} from 'node:fs';

import { B33A_ERROR, failB33a } from './b3-3a-canonical.mjs';

const MAX_ARTIFACT_BYTES = 16 * 1024 * 1024;

function digest(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export function readExactRegularFile(path, expectedSha256Hex = null) {
  if (expectedSha256Hex !== null
    && (typeof expectedSha256Hex !== 'string'
      || !/^[0-9a-f]{64}$/.test(expectedSha256Hex))) {
    failB33a(B33A_ERROR.INVALID, 'expected artifact digest is invalid');
  }
  if (!Number.isInteger(constants.O_NOFOLLOW)) {
    failB33a(B33A_ERROR.INVALID, 'O_NOFOLLOW is unavailable for exact artifact reads');
  }

  let descriptor;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.size < 1n || before.size > BigInt(MAX_ARTIFACT_BYTES)) {
      failB33a(B33A_ERROR.INVALID, 'candidate artifact is not a bounded regular file');
    }
    const bytes = Uint8Array.from(readFileSync(descriptor));
    const after = fstatSync(descriptor, { bigint: true });
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size
      || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs
      || BigInt(bytes.byteLength) !== after.size) {
      failB33a(B33A_ERROR.INVALID, 'candidate artifact changed while it was being read');
    }
    const actualSha256Hex = digest(bytes);
    if (expectedSha256Hex !== null && actualSha256Hex !== expectedSha256Hex) {
      bytes.fill(0);
      failB33a(B33A_ERROR.INVALID, 'candidate artifact differs from its verified tuple');
    }
    return Object.freeze({ bytes, sha256Hex: actualSha256Hex });
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}
