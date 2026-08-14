import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { schnorr } from '@noble/curves/secp256k1';

import { createAccountIdentityProofV2 } from '../marmot-phase-b1/identity-proof-v2.js';

const EXPECTED_WRITER_SHA256 =
  'ed5e740d9c93aa46aa1afb7b6065e4b5b92be972a8a080ddd0a35091260691bb';
const SOURCE_HEAD = 'a69df78c720bc679840172f68a68327ef603636c';
const OPENMLS_REVISION = '09e92777dba0528d3d29e2e5e681b7e91637c7be';
const CIPHERSUITE = 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519';
const PROOF_CREATED_AT = 1_786_572_000;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const styxJsDirectory = join(scriptDirectory, '..', '..');
const wasmDirectory = join(styxJsDirectory, 'vendor', 'openmls-wasm');
const fixtureDirectory = join(styxJsDirectory, 'test', 'fixtures', 'mls-state-b2-7');
const contextPath = join(fixtureDirectory, 'context.json');
const envelopePath = join(fixtureDirectory, 'envelope.json');

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function base64(bytes) {
  return Buffer.from(bytes).toString('base64');
}

function exactPrivateKey(lastByte) {
  const privateKey = new Uint8Array(32);
  privateKey[31] = lastByte;
  return privateKey;
}

function createPeer(wasm, provider, privateKey) {
  const accountPublicKey = Uint8Array.from(schnorr.getPublicKey(privateKey));
  const identity = new wasm.PhaseB2Identity(provider, accountPublicKey);
  const signatureKey = Uint8Array.from(identity.leaf_signature_key());
  const proof = createAccountIdentityProofV2(privateKey, signatureKey, PROOF_CREATED_AT);
  const keyPackage = wasm.PhaseB2KeyPackage.from_framed_bytes(
    identity.key_package(provider, proof).to_framed_bytes(),
  );
  return { accountPublicKey, identity, keyPackage, proof, signatureKey };
}

function assert(condition, message) {
  if (!condition) throw new Error(`B2.7 writer fixture: ${message}`);
}

const wasmBytes = readFileSync(join(wasmDirectory, 'openmls_wasm_bg.wasm'));
const writerSha256 = sha256(wasmBytes);
if (writerSha256 !== EXPECTED_WRITER_SHA256) {
  throw new Error(`unexpected committed writer ${writerSha256}`);
}

const moduleUrl = new URL('../../vendor/openmls-wasm/openmls_wasm.js', import.meta.url);
moduleUrl.searchParams.set('fixture', 'b2-7-writer');
const wasm = await import(moduleUrl.href);
await wasm.default({ module_or_path: wasmBytes });

const aliceProvider = new wasm.Provider();
const bobProvider = new wasm.Provider();
const alice = createPeer(wasm, aliceProvider, exactPrivateKey(1));
const bob = createPeer(wasm, bobProvider, exactPrivateKey(2));
const groupId = encoder.encode('styx-b2-7-writer-fixture-v1');

const aliceGroup = wasm.PhaseB2Group.create_new(
  aliceProvider,
  alice.identity,
  groupId,
  alice.proof,
);
const addBob = aliceGroup.prepare_add(aliceProvider, alice.identity, bob.keyPackage);
const addProjection = addBob.projection();
aliceGroup.confirm_pending(
  aliceProvider,
  addBob,
  addProjection.verified_leaf_digest(),
);
const bobGroup = wasm.PhaseB2Group.join(
  bobProvider,
  addBob.welcome(),
  wasm.PhaseB2RatchetTree.from_bytes(aliceGroup.export_ratchet_tree().to_bytes()),
);

const warmupAlice = encoder.encode('synthetic B2.7 writer Alice to Bob');
const warmupAliceCiphertext = aliceGroup.create_application_message(
  aliceProvider,
  alice.identity,
  warmupAlice,
);
assert(
  decoder.decode(bobGroup.process_application_message(bobProvider, warmupAliceCiphertext))
    === decoder.decode(warmupAlice),
  'Alice-to-Bob warmup failed',
);
const warmupBob = encoder.encode('synthetic B2.7 writer Bob to Alice');
const warmupBobCiphertext = bobGroup.create_application_message(
  bobProvider,
  bob.identity,
  warmupBob,
);
assert(
  decoder.decode(aliceGroup.process_application_message(aliceProvider, warmupBobCiphertext))
    === decoder.decode(warmupBob),
  'Bob-to-Alice warmup failed',
);

const snapshot = Uint8Array.from(aliceProvider.serialize_state());
const referencePlaintext =
  'mls-state-b2-7 reference message — only a compatible restored PhaseB2 session decrypts this';
const referenceCiphertext = Uint8Array.from(bobGroup.create_application_message(
  bobProvider,
  bob.identity,
  encoder.encode(referencePlaintext),
));

const restoredProvider = new wasm.Provider();
restoredProvider.restore_state(snapshot);
const restoredIdentity = wasm.PhaseB2Identity.load(
  restoredProvider,
  alice.accountPublicKey,
  alice.signatureKey,
);
const restoredGroup = wasm.PhaseB2Group.load(restoredProvider, groupId);
assert(restoredIdentity !== undefined, 'restored identity is absent');
assert(restoredGroup !== undefined, 'restored group is absent');
assert(restoredGroup.epoch() === 1n, 'restored group epoch is not one');
assert(restoredGroup.member_count() === 2, 'restored group member count is not two');
assert(
  decoder.decode(restoredGroup.process_application_message(restoredProvider, referenceCiphertext))
    === referencePlaintext,
  'restored reference decryption failed',
);
const replyPlaintext = 'B2.7 writer fixture restored response';
const reply = restoredGroup.create_application_message(
  restoredProvider,
  restoredIdentity,
  encoder.encode(replyPlaintext),
);
assert(reply.length > 0, 'restored reply is empty');

const envelope = {
  format: 'styx-phase-b2-provider-state',
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
  format: 'styx-phase-b2-writer-fixture-context',
  version: 1,
  sourceHead: SOURCE_HEAD,
  openMlsRevision: OPENMLS_REVISION,
  wasmArtifactSha256: writerSha256,
  ciphersuite: CIPHERSUITE,
  proofCreatedAt: PROOF_CREATED_AT,
  groupId: base64(groupId),
  epoch: '1',
  groupContextSha256: base64(aliceGroup.group_context_sha256(aliceProvider)),
  verifiedLeafDigest: base64(addProjection.verified_leaf_digest()),
  alice: {
    accountPublicKey: base64(alice.accountPublicKey),
    leafSignatureKey: base64(alice.signatureKey),
    identityProof: base64(alice.proof),
    leafIndex: aliceGroup.member_leaf_index(0),
  },
  bob: {
    accountPublicKey: base64(bob.accountPublicKey),
    leafSignatureKey: base64(bob.signatureKey),
    identityProof: base64(bob.proof),
    leafIndex: aliceGroup.member_leaf_index(1),
  },
  referenceCiphertext: base64(referenceCiphertext),
  referencePlaintext,
  replyPlaintext,
  selfCheck: 'restore-reference-decrypt-and-reply-pass',
};

const envelopeJson = `${JSON.stringify(envelope, null, 2)}\n`;
const contextJson = `${JSON.stringify(context, null, 2)}\n`;
writeFileSync(envelopePath, envelopeJson, { encoding: 'utf8', flag: 'wx' });
writeFileSync(contextPath, contextJson, { encoding: 'utf8', flag: 'wx' });

console.log(JSON.stringify({
  context: { bytes: Buffer.byteLength(contextJson), sha256: sha256(contextJson) },
  envelope: { bytes: Buffer.byteLength(envelopeJson), sha256: sha256(envelopeJson) },
  payload: { bytes: snapshot.length, sha256: sha256(snapshot) },
  selfCheck: context.selfCheck,
  writerSha256,
}, null, 2));
