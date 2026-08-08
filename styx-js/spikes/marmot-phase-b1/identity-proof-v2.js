import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';

export const ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID = 0x8009;
export const ACCOUNT_IDENTITY_PROOF_V2_EVENT_KIND = 450;
export const ACCOUNT_IDENTITY_PROOF_V2_LENGTH = 104;
export const ACCOUNT_IDENTITY_PROOF_V2_CONTENT =
  'Authorize this MLS leaf key for my Marmot account';

const MAX_SAFE_TIMESTAMP = Number.MAX_SAFE_INTEGER;
const encoder = new TextEncoder();

function exactBytes(value, length, label) {
  if (!(value instanceof Uint8Array) || Object.getPrototypeOf(value) !== Uint8Array.prototype) {
    throw new TypeError(`${label} must be a direct Uint8Array`);
  }
  if (value.length !== length) {
    throw new RangeError(`${label} must be exactly ${length} bytes`);
  }
  return Uint8Array.from(value);
}

function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function equalBytes(left, right) {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

function assertCreatedAt(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > MAX_SAFE_TIMESTAMP) {
    throw new RangeError('createdAt must be a positive safe integer');
  }
  return value;
}

function encodeUint64(value) {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(value), false);
  return bytes;
}

function decodeUint64(bytes) {
  const value = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getBigUint64(0, false);
  if (value < 1n || value > BigInt(MAX_SAFE_TIMESTAMP)) {
    throw new RangeError('proof created_at is outside the supported range');
  }
  return Number(value);
}

function assertXOnlyPublicKey(publicKey) {
  try {
    schnorr.utils.lift_x(schnorr.utils.bytesToNumberBE(publicKey));
  } catch {
    throw new TypeError('account public key is not a valid x-only secp256k1 key');
  }
}

export function accountIdentityProofV2Event(accountPublicKey, leafSignatureKey, createdAt) {
  const account = exactBytes(accountPublicKey, 32, 'accountPublicKey');
  const leaf = exactBytes(leafSignatureKey, 32, 'leafSignatureKey');
  assertXOnlyPublicKey(account);
  const timestamp = assertCreatedAt(createdAt);
  return Object.freeze({
    pubkey: bytesToHex(account),
    created_at: timestamp,
    kind: ACCOUNT_IDENTITY_PROOF_V2_EVENT_KIND,
    tags: Object.freeze([
      Object.freeze(['d', 'marmot.account-identity-proof.v2']),
      Object.freeze(['component', '0x8009']),
      Object.freeze(['ciphersuite', '0x0001']),
      Object.freeze(['signature_scheme', '0x0807']),
      Object.freeze(['mls_signature_key', bytesToHex(leaf)]),
    ]),
    content: ACCOUNT_IDENTITY_PROOF_V2_CONTENT,
  });
}
export function accountIdentityProofV2EventId(event) {
  const canonical = [0, event.pubkey, event.created_at, event.kind, event.tags, event.content];
  return sha256(encoder.encode(JSON.stringify(canonical)));
}

export function createAccountIdentityProofV2(accountPrivateKey, leafSignatureKey, createdAt) {
  const privateKey = exactBytes(accountPrivateKey, 32, 'accountPrivateKey');
  const leaf = exactBytes(leafSignatureKey, 32, 'leafSignatureKey');
  const account = Uint8Array.from(schnorr.getPublicKey(privateKey));
  const event = accountIdentityProofV2Event(account, leaf, createdAt);
  const signature = Uint8Array.from(schnorr.sign(accountIdentityProofV2EventId(event), privateKey));
  const proof = new Uint8Array(ACCOUNT_IDENTITY_PROOF_V2_LENGTH);
  proof.set(account, 0);
  proof.set(encodeUint64(createdAt), 32);
  proof.set(signature, 40);
  return proof;
}

export function verifyAccountIdentityProofV2(proofBytes, expectedAccountKey, leafSignatureKey) {
  const proof = exactBytes(proofBytes, ACCOUNT_IDENTITY_PROOF_V2_LENGTH, 'proof');
  const expectedAccount = exactBytes(expectedAccountKey, 32, 'expectedAccountKey');
  const leaf = exactBytes(leafSignatureKey, 32, 'leafSignatureKey');
  const signer = proof.slice(0, 32);
  assertXOnlyPublicKey(signer);
  if (!equalBytes(signer, expectedAccount)) {
    throw new Error('proof signer does not match the expected account key');
  }
  const createdAt = decodeUint64(proof.slice(32, 40));
  const signature = proof.slice(40, 104);
  const event = accountIdentityProofV2Event(signer, leaf, createdAt);
  if (!schnorr.verify(signature, accountIdentityProofV2EventId(event), signer)) {
    throw new Error('account identity proof signature is invalid');
  }
  return Object.freeze({
    componentId: ACCOUNT_IDENTITY_PROOF_V2_COMPONENT_ID,
    accountPublicKey: signer,
    leafSignatureKey: leaf,
    createdAt,
  });
}
