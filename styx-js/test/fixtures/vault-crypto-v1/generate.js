// generate.js — regenerates the frozen vault-crypto-v1 test vectors.
//
//   cd styx-js && node test/fixtures/vault-crypto-v1/generate.js
//
// EVERY secret below is SYNTHETIC, deterministically derived from TEST-ONLY
// labels: no real password, Root Storage Key, user data or production value
// exists in these fixtures. Determinism (no randomness, no clock) is the
// point: the vectors are a compatibility CONTRACT — after PR-2 merges,
// changing them requires an explicit motivation and a compatibility review.
//
// This script deliberately does NOT use the production encrypt APIs for the
// ciphertext vectors: those generate nonces internally and accept no caller
// nonce (vault spec §6). It re-implements the encryption side with WebCrypto
// and FIXED nonces, while importing the canonical AAD builders and HKDF
// constants from the production modules so the serialization contract is
// shared, not duplicated.

import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildWrapperAadBytes, buildRecordAadBytes, encodeBase64 } from '../../../src/crypto/vault-aad.js';
import { VAULT_HKDF_INFO, VAULT_HKDF_SALT_LABEL } from '../../../src/crypto/vault-keys.js';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const { subtle } = globalThis.crypto;
const UTF8 = new TextEncoder();

const toHex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, '0')).join('');
const sha256 = async (label) => new Uint8Array(await subtle.digest('SHA-256', UTF8.encode(label)));

// --- synthetic material (TEST-ONLY, label-derived, no randomness) -----------
const rootKey = await sha256('STYX-VAULT-TEST-ONLY root key v1');
const kek = await sha256('STYX-VAULT-TEST-ONLY kek v1');
const kdfSalt = (await sha256('STYX-VAULT-TEST-ONLY kdf salt v1')).slice(0, 16);
const wrapNonce = (await sha256('STYX-VAULT-TEST-ONLY wrap nonce v1')).slice(0, 12);
const jsonRecordNonce = (await sha256('STYX-VAULT-TEST-ONLY record nonce json v1')).slice(0, 12);
const bytesRecordNonce = (await sha256('STYX-VAULT-TEST-ONLY record nonce bytes v1')).slice(0, 12);
const canaryPayload = await sha256('STYX-VAULT-TEST-ONLY canary payload v1');

// --- HKDF hierarchy (spec §5): salt = SHA-256("styx-vault-v1") --------------
const hkdfSalt = await sha256(VAULT_HKDF_SALT_LABEL);
const ikm = await subtle.importKey('raw', rootKey, 'HKDF', false, ['deriveBits']);
const okm = {};
for (const [name, info] of Object.entries(VAULT_HKDF_INFO)) {
  okm[name] = new Uint8Array(await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: hkdfSalt, info: UTF8.encode(info) }, ikm, 256,
  ));
}

const aesGcm = (usages) => (raw) => subtle.importKey('raw', raw, 'AES-GCM', false, usages);
const importAes = aesGcm(['encrypt', 'decrypt']);

// --- wrapper-v1: KEK wraps the synthetic Root Key ----------------------------
const wrapperFields = {
  format: 'styx-vault-wrapper',
  version: 1,
  kdf: 'argon2id',
  kdfVersion: 19,
  mKib: 65536,
  t: 3,
  p: 1,
  profile: 'mobile-balanced',
  saltB64: encodeBase64(kdfSalt),
  outLen: 32,
  keyVersion: 1,
};
const wrapperAad = buildWrapperAadBytes(wrapperFields);
const wrappedRootKey = new Uint8Array(await subtle.encrypt(
  { name: 'AES-GCM', iv: wrapNonce, additionalData: wrapperAad, tagLength: 128 },
  await importAes(kek),
  rootKey,
));

// --- record-v1-json: settings namespace --------------------------------------
const jsonRecordMeta = { v: 1, ns: 'settings', k: 'ui:theme', rv: 3, kv: 1, ct: 'json' };
const jsonPlaintextValue = { theme: 'dark', language: 'it', notifications: false };
const jsonPlaintext = JSON.stringify(jsonPlaintextValue);
const jsonAad = buildRecordAadBytes(jsonRecordMeta);
const jsonData = new Uint8Array(await subtle.encrypt(
  { name: 'AES-GCM', iv: jsonRecordNonce, additionalData: jsonAad, tagLength: 128 },
  await importAes(okm.settings),
  UTF8.encode(jsonPlaintext),
));

// --- record-v1-bytes: canary namespace ---------------------------------------
const bytesRecordMeta = { v: 1, ns: 'canary', k: 'canary:0001', rv: 1, kv: 1, ct: 'bytes' };
const bytesAad = buildRecordAadBytes(bytesRecordMeta);
const bytesData = new Uint8Array(await subtle.encrypt(
  { name: 'AES-GCM', iv: bytesRecordNonce, additionalData: bytesAad, tagLength: 128 },
  await importAes(okm.canary),
  canaryPayload,
));

// --- manifest-hmac-v1 ---------------------------------------------------------
const manifestCanonical = JSON.stringify([
  'styx-vault-manifest', 1, 1, ['settings', 'canary'], 'STYX-VAULT-TEST-ONLY sample manifest',
]);
const hmacKey = await subtle.importKey(
  'raw', okm.manifest, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
);
const manifestMac = new Uint8Array(await subtle.sign('HMAC', hmacKey, UTF8.encode(manifestCanonical)));

// --- write files ---------------------------------------------------------------
const note = 'TEST-ONLY synthetic vectors — see README.md; regenerate with generate.js';
const write = (name, obj) => writeFileSync(join(HERE, name), `${JSON.stringify(obj, null, 2)}\n`);

write('hkdf-v1.json', {
  note,
  rootKeyHex: toHex(rootKey),
  saltLabel: VAULT_HKDF_SALT_LABEL,
  saltHex: toHex(hkdfSalt),
  okmBitsPerDerivation: 256,
  derivations: Object.fromEntries(
    Object.entries(VAULT_HKDF_INFO).map(([name, info]) => [name, { info, okmHex: toHex(okm[name]) }]),
  ),
});

write('wrapper-v1.json', {
  note,
  inputs: {
    rootKeyHex: toHex(rootKey),
    kekHex: toHex(kek),
    kdfSaltHex: toHex(kdfSalt),
    wrapNonceHex: toHex(wrapNonce),
  },
  aadUtf8: JSON.stringify([
    wrapperFields.format, wrapperFields.version, wrapperFields.kdf, wrapperFields.kdfVersion,
    wrapperFields.mKib, wrapperFields.t, wrapperFields.p, wrapperFields.saltB64,
    wrapperFields.outLen, wrapperFields.keyVersion,
  ]),
  aadHex: toHex(wrapperAad),
  wrapper: {
    ...wrapperFields,
    wrapAlg: 'A256GCM',
    wrapNonceHex: toHex(wrapNonce),
    wrappedRootKeyHex: toHex(wrappedRootKey),
    createdAt: '2026-07-12',
    calibratedMs: 130,
    rewrapPending: null,
  },
});

write('record-v1-json.json', {
  note,
  namespaceKeyHex: toHex(okm.settings),
  plaintextValue: jsonPlaintextValue,
  plaintextUtf8: jsonPlaintext,
  aadUtf8: JSON.stringify(Object.values(jsonRecordMeta)),
  aadHex: toHex(jsonAad),
  record: { ...jsonRecordMeta, nonceHex: toHex(jsonRecordNonce), dataHex: toHex(jsonData) },
});

write('record-v1-bytes.json', {
  note,
  namespaceKeyHex: toHex(okm.canary),
  plaintextHex: toHex(canaryPayload),
  aadUtf8: JSON.stringify(Object.values(bytesRecordMeta)),
  aadHex: toHex(bytesAad),
  record: { ...bytesRecordMeta, nonceHex: toHex(bytesRecordNonce), dataHex: toHex(bytesData) },
});

write('manifest-hmac-v1.json', {
  note,
  manifestKeyHex: toHex(okm.manifest),
  canonicalUtf8: manifestCanonical,
  macHex: toHex(manifestMac),
});

console.log('vault-crypto-v1 fixtures written:', HERE);
