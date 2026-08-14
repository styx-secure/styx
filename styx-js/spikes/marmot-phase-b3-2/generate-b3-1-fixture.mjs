// SPDX-License-Identifier: AGPL-3.0-or-later

import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { schnorr } from '@noble/curves/secp256k1';

import { createAccountIdentityProofV2 } from '../marmot-phase-b1/identity-proof-v2.js';

const EXPECTED_WRITER_SHA256 =
  '26a41d86d7fd2c9ab4184344e4ff00f5eebb5bc7609ba22e98b12ce903d4a4dd';
const SOURCE_HEAD = '019da38921deca8b9bb9a4ca6544c827db8ef3ac';
const OPENMLS_REVISION = '09e92777dba0528d3d29e2e5e681b7e91637c7be';
const CIPHERSUITE = 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519';
const PROOF_CREATED_AT = 1_786_707_600;
const EXPECTED_SUPPORTED_COMPONENTS = Object.freeze([0x8001, 0x8003, 0x8009, 0x800c]);
const EXPECTED_LEAF_COMPONENTS = Object.freeze([0x0001, 0x8009]);

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const styxJsDirectory = join(scriptDirectory, '..', '..');
const wasmDirectory = join(styxJsDirectory, 'vendor', 'openmls-wasm');
const fixtureDirectory = join(styxJsDirectory, 'test', 'fixtures', 'mls-state-b3-1');
const contextPath = join(fixtureDirectory, 'context.json');
const envelopePath = join(fixtureDirectory, 'envelope.json');

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function base64(bytes) {
  return Buffer.from(bytes).toString('base64');
}

function assert(condition, message) {
  if (!condition) throw new Error(`B3.1 writer fixture: ${message}`);
}

function exactPrivateKey(lastByte) {
  const privateKey = new Uint8Array(32);
  privateKey[31] = lastByte;
  return privateKey;
}

function equalNumbers(actual, expected) {
  return actual.length === expected.length
    && actual.every((value, index) => value === expected[index]);
}

const wasmBytes = readFileSync(join(wasmDirectory, 'openmls_wasm_bg.wasm'));
const writerSha256 = sha256(wasmBytes);
if (writerSha256 !== EXPECTED_WRITER_SHA256) {
  throw new Error(`unexpected committed writer ${writerSha256}`);
}

const moduleUrl = new URL('../../vendor/openmls-wasm/openmls_wasm.js', import.meta.url);
moduleUrl.searchParams.set('fixture', 'b3-1-writer');
const wasm = await import(moduleUrl.href);
await wasm.default({ module_or_path: wasmBytes });

function strictKeys(value, expected, label) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  assert(
    actual.length === wanted.length && actual.every((key, index) => key === wanted[index]),
    `${label} fields are not exact`,
  );
}

if (existsSync(envelopePath) || existsSync(contextPath)) {
  assert(existsSync(envelopePath) && existsSync(contextPath), 'committed fixture is incomplete');
  const envelopeJson = readFileSync(envelopePath, 'utf8');
  const contextJson = readFileSync(contextPath, 'utf8');
  const envelope = JSON.parse(envelopeJson);
  const context = JSON.parse(contextJson);
  strictKeys(envelope, [
    'format', 'envelopeVersion', 'storageSchemaVersion', 'sourceHead', 'openMlsRevision',
    'wasmArtifactSha256', 'ciphersuite', 'payloadEncoding', 'payloadSha256', 'payload',
  ], 'committed envelope');
  strictKeys(context, [
    'format', 'version', 'sourceHead', 'openMlsRevision', 'wasmArtifactSha256',
    'ciphersuite', 'proofCreatedAt', 'accountPublicKey', 'leafSignatureKey',
    'identityProof', 'framedKeyPackage', 'framedKeyPackageSha256', 'leafComponentIds',
    'supportedComponentIds', 'isLastResort', 'selfCheck',
  ], 'committed context');
  assert(envelope.format === 'styx-phase-b3-1-provider-state', 'wrong envelope format');
  assert(context.format === 'styx-phase-b3-1-writer-fixture-context', 'wrong context format');
  for (const field of ['sourceHead', 'openMlsRevision', 'wasmArtifactSha256', 'ciphersuite']) {
    assert(envelope[field] === context[field], `committed ${field} mismatch`);
  }
  assert(context.sourceHead === SOURCE_HEAD, 'wrong committed source head');
  assert(context.openMlsRevision === OPENMLS_REVISION, 'wrong committed OpenMLS revision');
  assert(context.wasmArtifactSha256 === writerSha256, 'wrong committed writer digest');
  const snapshot = Uint8Array.from(Buffer.from(envelope.payload, 'base64'));
  const framedKeyPackage = Uint8Array.from(Buffer.from(context.framedKeyPackage, 'base64'));
  const accountPublicKey = Uint8Array.from(Buffer.from(context.accountPublicKey, 'base64'));
  const leafSignatureKey = Uint8Array.from(Buffer.from(context.leafSignatureKey, 'base64'));
  assert(sha256(snapshot) === envelope.payloadSha256, 'committed Provider digest mismatch');
  assert(
    sha256(framedKeyPackage) === context.framedKeyPackageSha256,
    'committed KeyPackage digest mismatch',
  );
  const provider = new wasm.Provider();
  const identity = (() => {
    provider.restore_state(snapshot);
    return wasm.PhaseB2Identity.load(provider, accountPublicKey, leafSignatureKey);
  })();
  const parsed = wasm.PhaseB31KeyPackage.from_framed_bytes(framedKeyPackage);
  try {
    assert(identity !== undefined, 'committed Provider does not restore its identity');
    assert(parsed.ciphersuite_id() === 1, 'committed KeyPackage ciphersuite changed');
    assert(!parsed.is_last_resort(), 'committed KeyPackage became last-resort');
    assert(
      equalNumbers([...parsed.component_ids()], context.leafComponentIds),
      'committed LeafNode component ids changed',
    );
    assert(
      equalNumbers([...parsed.supported_component_ids()], context.supportedComponentIds),
      'committed supported components changed',
    );
    assert(
      Buffer.from(parsed.credential_identity()).equals(Buffer.from(accountPublicKey))
        && Buffer.from(parsed.leaf_signature_key()).equals(Buffer.from(leafSignatureKey)),
      'committed KeyPackage identity binding changed',
    );
  } finally {
    parsed.free();
    identity?.free();
    provider.free();
  }
  console.log(JSON.stringify({
    mode: 'verify-committed',
    context: { bytes: Buffer.byteLength(contextJson), sha256: sha256(contextJson) },
    envelope: { bytes: Buffer.byteLength(envelopeJson), sha256: sha256(envelopeJson) },
    keyPackage: { bytes: framedKeyPackage.length, sha256: sha256(framedKeyPackage) },
    payload: { bytes: snapshot.length, sha256: sha256(snapshot) },
    selfCheck: context.selfCheck,
    writerSha256,
  }, null, 2));
  process.exit(0);
}

const accountPrivateKey = exactPrivateKey(3);
const accountPublicKey = Uint8Array.from(schnorr.getPublicKey(accountPrivateKey));
const provider = new wasm.Provider();
const identity = new wasm.PhaseB2Identity(provider, accountPublicKey);
const leafSignatureKey = Uint8Array.from(identity.leaf_signature_key());
const identityProof = createAccountIdentityProofV2(
  accountPrivateKey,
  leafSignatureKey,
  PROOF_CREATED_AT,
);
const keyPackage = identity.b3_1_key_package(provider, identityProof);
const framedKeyPackage = Uint8Array.from(keyPackage.to_framed_bytes());

assert(keyPackage.ciphersuite_id() === 0x0001, 'unexpected ciphersuite');
assert(keyPackage.is_last_resort() === false, 'KeyPackage is last-resort');
assert(
  equalNumbers(Array.from(keyPackage.component_ids()), EXPECTED_LEAF_COMPONENTS),
  'unexpected LeafNode component dictionary',
);
assert(
  equalNumbers(Array.from(keyPackage.supported_component_ids()), EXPECTED_SUPPORTED_COMPONENTS),
  'unexpected supported-component advertisement',
);
assert(
  Buffer.from(keyPackage.credential_identity()).equals(Buffer.from(accountPublicKey)),
  'credential identity mismatch',
);
assert(
  Buffer.from(keyPackage.leaf_signature_key()).equals(Buffer.from(leafSignatureKey)),
  'leaf signature key mismatch',
);
assert(
  Buffer.from(keyPackage.identity_proof()).equals(Buffer.from(identityProof)),
  'identity proof mismatch',
);

const snapshot = Uint8Array.from(provider.serialize_state());
const restoredProvider = new wasm.Provider();
restoredProvider.restore_state(snapshot);
const restoredIdentity = wasm.PhaseB2Identity.load(
  restoredProvider,
  accountPublicKey,
  leafSignatureKey,
);
assert(restoredIdentity !== undefined, 'restored identity is absent');
assert(
  Buffer.from(restoredIdentity.account_public_key()).equals(Buffer.from(accountPublicKey)),
  'restored account key mismatch',
);
assert(
  Buffer.from(restoredIdentity.leaf_signature_key()).equals(Buffer.from(leafSignatureKey)),
  'restored signature key mismatch',
);

const parsedKeyPackage = wasm.PhaseB31KeyPackage.from_framed_bytes(framedKeyPackage);
assert(
  Buffer.from(parsedKeyPackage.to_framed_bytes()).equals(Buffer.from(framedKeyPackage)),
  'framed KeyPackage round trip changed bytes',
);

const envelope = {
  format: 'styx-phase-b3-1-provider-state',
  envelopeVersion: 1,
  storageSchemaVersion: 1,
  sourceHead: SOURCE_HEAD,
  openMlsRevision: OPENMLS_REVISION,
  wasmArtifactSha256: writerSha256,
  ciphersuite: CIPHERSUITE,
  payloadEncoding: 'base64',
  payloadSha256: sha256(snapshot),
  payload: base64(snapshot),
};
const context = {
  format: 'styx-phase-b3-1-writer-fixture-context',
  version: 1,
  sourceHead: SOURCE_HEAD,
  openMlsRevision: OPENMLS_REVISION,
  wasmArtifactSha256: writerSha256,
  ciphersuite: CIPHERSUITE,
  proofCreatedAt: PROOF_CREATED_AT,
  accountPublicKey: base64(accountPublicKey),
  leafSignatureKey: base64(leafSignatureKey),
  identityProof: base64(identityProof),
  framedKeyPackage: base64(framedKeyPackage),
  framedKeyPackageSha256: sha256(framedKeyPackage),
  leafComponentIds: EXPECTED_LEAF_COMPONENTS,
  supportedComponentIds: EXPECTED_SUPPORTED_COMPONENTS,
  isLastResort: false,
  selfCheck: 'restore-identity-and-key-package-round-trip-pass',
};

const envelopeJson = `${JSON.stringify(envelope, null, 2)}\n`;
const contextJson = `${JSON.stringify(context, null, 2)}\n`;
writeFileSync(envelopePath, envelopeJson, { encoding: 'utf8', flag: 'wx' });
writeFileSync(contextPath, contextJson, { encoding: 'utf8', flag: 'wx' });

console.log(JSON.stringify({
  context: { bytes: Buffer.byteLength(contextJson), sha256: sha256(contextJson) },
  envelope: { bytes: Buffer.byteLength(envelopeJson), sha256: sha256(envelopeJson) },
  keyPackage: { bytes: framedKeyPackage.length, sha256: sha256(framedKeyPackage) },
  payload: { bytes: snapshot.length, sha256: sha256(snapshot) },
  selfCheck: context.selfCheck,
  writerSha256,
}, null, 2));
