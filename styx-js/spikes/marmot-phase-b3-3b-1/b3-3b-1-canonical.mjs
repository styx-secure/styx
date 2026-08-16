// SPDX-License-Identifier: AGPL-3.0-or-later
// STYX_SPIKE_PROTOTYPE — closed constants and codecs for B3.3b-1.

import { createHash } from 'node:crypto';

export const B33B1_BUILD_ROOT =
  '/home/mverde/.local/share/styx-b3-3b-1-builds/issue-188';
export const B33B1_PRIVATE_ROOT =
  '/home/mverde/.local/share/styx-b3-3b-1-private/issue-188';
export const B33B1_RUN_ROOT =
  '/home/mverde/.local/share/styx-b3-3b-1-runs/issue-188';
export const B33B1_MDK_BUILD_ROOT =
  '/home/mverde/.local/share/styx-b3-3b-1-mdk-builds/issue-188';
export const B33B1_PROVIDER_FORMAT = 'phase-b33b1-provider-canonical-v1';
export const B33B1_MAX_PAST_EPOCHS = 5;

export const B33B1_ERROR = Object.freeze({
  BLOCKED: 'B33B1_BLOCKED',
  INVALID: 'B33B1_INVALID',
  PIN_DRIFT: 'B33B1_PIN_DRIFT',
  ENGINE_REJECTED: 'B33B1_ENGINE_REJECTED',
  MDK_REJECTS_STYX_SELF_UPDATE: 'MDK_REJECTS_STYX_SELF_UPDATE',
});

export const B33B1_GENERATED_FILES = Object.freeze([
  'openmls_wasm.js',
  'openmls_wasm.d.ts',
  'openmls_wasm_bg.wasm',
  'openmls_wasm_bg.wasm.d.ts',
  'package.json',
]);

export class B33b1Error extends Error {
  constructor(code, message, details = undefined) {
    super(message);
    this.name = 'B33b1Error';
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

export function failB33b1(code, message, details = undefined) {
  throw new B33b1Error(code, message, details);
}

export function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export function bytesToHex(bytes) {
  return Buffer.from(bytes).toString('hex');
}

export function hexToBytes(label, value, expectedLength = undefined) {
  if (typeof value !== 'string' || value.length === 0 || value.length % 2 !== 0
    || !/^[0-9a-f]+$/.test(value)
    || (expectedLength !== undefined && value.length !== expectedLength * 2)) {
    failB33b1(B33B1_ERROR.INVALID, `${label} is not canonical lowercase hex`);
  }
  return Uint8Array.from(Buffer.from(value, 'hex'));
}

export function clearBytes(value) {
  value?.fill?.(0);
}

export function safeFree(value) {
  try { value?.free?.(); } catch { /* cleanup cannot change protocol authority */ }
}

export function exactFields(value, fields, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    failB33b1(B33B1_ERROR.INVALID, `${label} is not an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  if (actual.length !== expected.length
    || actual.some((field, index) => field !== expected[index])) {
    failB33b1(B33B1_ERROR.INVALID, `${label} fields are not exact`);
  }
  return value;
}

export function projectionEvidence(projection) {
  const fields = {
    authoritySha256Hex: bytesToHex(projection.authority_sha256()),
    candidateGroupContextSha256Hex:
      bytesToHex(projection.candidate_group_context_sha256()),
    commitSha256Hex: bytesToHex(projection.commit_sha256()),
    committerAccountHex: bytesToHex(projection.committer_account()),
    committerLeafIndex: projection.committer_leaf_index(),
    committerSignatureKeyHex: bytesToHex(projection.committer_signature_key()),
    domain: projection.domain(),
    groupIdHex: bytesToHex(projection.group_id()),
    orderingPriority: projection.ordering_priority(),
    parentGroupContextSha256Hex:
      bytesToHex(projection.parent_group_context_sha256()),
    parentStateSha256Hex: bytesToHex(projection.parent_state_sha256()),
    sourceEpoch: projection.source_epoch().toString(),
    targetEpoch: projection.target_epoch().toString(),
    verifiedLeafDigestHex: bytesToHex(projection.verified_leaf_digest()),
  };
  return Object.freeze(fields);
}
