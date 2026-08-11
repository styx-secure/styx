// STYX_SPIKE_PROTOTYPE — Phase B2.4 only; no product path may import this file.

import { sha256 } from '@noble/hashes/sha256';

import {
  B23_LIMITS,
  assertBytes,
  assertGroupIdHex,
  assertHex64,
  assertSafeInteger,
  assertString,
  bytesToHex,
  hexToBytes,
  parseEpochDecimal,
} from '../marmot-phase-b2-3/b2-3-canonical.mjs';

const UTF8 = new TextEncoder();

export const B24_POLICY_VERSION = 1;
export const B24_DB_PREFIX = 'styx-b2-4-poc-v1-';
export const B24_CONTEXT_DOMAIN = 'STYX-B2.4-AUTHORIZATION-CONTEXT-v1';
export const B24_RESULT_DOMAIN = 'STYX-B2.4-AUTHORIZATION-RESULT-v1';
export const B24_PARENT_FORMAT = 'styx-b2-4-parent-v1';
export const B24_REQUIRED_COMPONENT_IDS = Object.freeze([32771, 32777, 32780]);
export const B24_ACTIVE_LIFECYCLE_HEX = '00';

export const B24_LIMITS = Object.freeze({
  maxMembers: B23_LIMITS.maxMembers,
  maxAdmins: B23_LIMITS.maxMembers,
  maxAdminPolicyBytes: B23_LIMITS.maxMembers * 32 + 2,
});

export const B24_ERROR = Object.freeze({
  INVALID: 'B24_INVALID',
  ENGINE_REJECTED: 'B24_ENGINE_REJECTED',
  POLICY_REJECTED: 'B24_POLICY_REJECTED',
  BINDING_MISMATCH: 'B24_BINDING_MISMATCH',
  RECOVERY_MISMATCH: 'B24_RECOVERY_MISMATCH',
});

export const B24_REASON = Object.freeze({
  ALLOW_ADD: 'B24_ALLOW_ADD',
  ALLOW_REMOVE: 'B24_ALLOW_REMOVE',
  ALLOW_SELF_UPDATE: 'B24_ALLOW_SELF_UPDATE',
  INVALID_PARENT: 'B24_REJECT_INVALID_PARENT',
  INVALID_CANDIDATE: 'B24_REJECT_INVALID_CANDIDATE',
  INVALID_PARENT_PROOF: 'B24_REJECT_INVALID_PARENT_PROOF',
  INVALID_CANDIDATE_PROOF: 'B24_REJECT_INVALID_CANDIDATE_PROOF',
  DUPLICATE_ACCOUNT: 'B24_REJECT_DUPLICATE_ACCOUNT',
  ADMIN_POLICY: 'B24_REJECT_ADMIN_POLICY',
  POLICY_MUTATION: 'B24_REJECT_POLICY_MUTATION',
  LIFECYCLE: 'B24_REJECT_LIFECYCLE',
  COMPONENTS: 'B24_REJECT_COMPONENTS',
  EPOCH: 'B24_REJECT_EPOCH',
  COMMITTER: 'B24_REJECT_COMMITTER',
  NOT_ADMIN: 'B24_REJECT_NOT_ADMIN',
  UNSUPPORTED_SHAPE: 'B24_REJECT_UNSUPPORTED_SHAPE',
  MEMBER_TRANSITION: 'B24_REJECT_MEMBER_TRANSITION',
  SELF_REMOVE: 'B24_REJECT_SELF_REMOVE',
  ADMIN_REMOVE: 'B24_REJECT_ADMIN_REMOVE',
  SIGNING_KEY_ROTATION: 'B24_REJECT_SIGNING_KEY_ROTATION',
});

export class B24Error extends Error {
  constructor(code, message, details = {}, options = {}) {
    super(`${code}: ${message}`, 'cause' in options ? { cause: options.cause } : undefined);
    this.name = 'B24Error';
    this.code = code;
    this.details = Object.freeze({ ...details });
  }
}

export function failB24(code, message, details, cause) {
  throw new B24Error(code, message, details, cause === undefined ? {} : { cause });
}

export function canonicalB24Bytes(value) {
  return UTF8.encode(JSON.stringify(value));
}

export function digestB24(value) {
  return bytesToHex(Uint8Array.from(sha256(canonicalB24Bytes(value))));
}

export function assertDirectObject(value, fields, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)
    || (Object.getPrototypeOf(value) !== Object.prototype
      && Object.getPrototypeOf(value) !== null)) {
    failB24(B24_ERROR.INVALID, `${label} must be a plain object`);
  }
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== 'string') || keys.length !== fields.length) {
    failB24(B24_ERROR.INVALID, `${label} field set is invalid`);
  }
  const out = {};
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) {
      failB24(B24_ERROR.INVALID, `${label} contains a missing or accessor field`);
    }
    out[field] = descriptor.value;
  }
  for (const key of keys) {
    if (!fields.includes(key)) failB24(B24_ERROR.INVALID, `${label} contains an unexpected field`);
  }
  return out;
}

export function assertHexBytes(name, value, bytes) {
  assertString(name, value, {
    min: bytes * 2,
    max: bytes * 2,
    pattern: new RegExp(`^(?:[0-9a-f]{2}){${bytes}}$`),
  });
  return value;
}

export function assertU32(name, value) {
  return assertSafeInteger(name, value, 0, 0xffffffff);
}

export function assertSortedU16(name, value) {
  if (!Array.isArray(value) || value.length > 64) {
    failB24(B24_ERROR.INVALID, `${name} must be a bounded array`);
  }
  const out = [];
  let prior = -1;
  for (const item of value) {
    assertSafeInteger(name, item, 0, 0xffff);
    if (item <= prior) failB24(B24_ERROR.INVALID, `${name} must be strictly sorted and unique`);
    prior = item;
    out.push(item);
  }
  return Object.freeze(out);
}

export function assertAuthorizationContext(context) {
  const safe = assertDirectObject(context, [
    'domain', 'version', 'groupIdHex', 'parentEpochDec',
    'parentGroupContextDigestHex', 'commitDigestHex', 'projectionDigestHex',
    'candidateEpochDec', 'candidateGroupContextDigestHex', 'verifiedLeafDigestHex',
    'operationKind', 'committerLeafIndex', 'committerIdentityHex',
    'committerSignatureKeyHex',
  ], 'authorization context');
  if (safe.domain !== B24_CONTEXT_DOMAIN || safe.version !== B24_POLICY_VERSION) {
    failB24(B24_ERROR.INVALID, 'authorization context domain or version is invalid');
  }
  assertGroupIdHex(safe.groupIdHex);
  parseEpochDecimal(safe.parentEpochDec, 'parentEpochDec');
  parseEpochDecimal(safe.candidateEpochDec, 'candidateEpochDec');
  for (const field of [
    'parentGroupContextDigestHex', 'commitDigestHex', 'projectionDigestHex',
    'candidateGroupContextDigestHex', 'verifiedLeafDigestHex',
  ]) assertHex64(field, safe[field]);
  if (!['add', 'remove', 'self-update', 'unsupported'].includes(safe.operationKind)) {
    failB24(B24_ERROR.INVALID, 'authorization operation kind is invalid');
  }
  assertU32('committerLeafIndex', safe.committerLeafIndex);
  assertHexBytes('committerIdentityHex', safe.committerIdentityHex, 32);
  assertHexBytes('committerSignatureKeyHex', safe.committerSignatureKeyHex, 32);
  return Object.freeze({ ...safe });
}

export function authorizationContextDigest(context) {
  const safe = assertAuthorizationContext(context);
  return digestB24([
    safe.domain, safe.version, safe.groupIdHex, safe.parentEpochDec,
    safe.parentGroupContextDigestHex, safe.commitDigestHex,
    safe.projectionDigestHex, safe.candidateEpochDec,
    safe.candidateGroupContextDigestHex, safe.verifiedLeafDigestHex,
    safe.operationKind, safe.committerLeafIndex, safe.committerIdentityHex,
    safe.committerSignatureKeyHex,
  ]);
}

export function authorizationResultDigest({ contextDigestHex, verdict, reason }) {
  assertHex64('contextDigestHex', contextDigestHex);
  if (verdict !== 'ALLOW' && verdict !== 'REJECT') {
    failB24(B24_ERROR.INVALID, 'authorization verdict is invalid');
  }
  assertString('authorization reason', reason, {
    min: 1, max: 96, pattern: /^B24_(?:ALLOW|REJECT)_[A-Z0-9_]+$/,
  });
  return digestB24([B24_RESULT_DOMAIN, B24_POLICY_VERSION, contextDigestHex, verdict, reason]);
}

export function hex32(name, value) {
  assertHexBytes(name, value, 32);
  return hexToBytes(name, value);
}

export function assertProofBytes(value) {
  assertBytes('identity proof', value, { min: 104, max: 104 });
  return value;
}
