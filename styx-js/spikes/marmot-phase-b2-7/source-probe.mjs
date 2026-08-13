import { createHash } from 'node:crypto';
import { readFileSync, realpathSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

import { schnorr } from '@noble/curves/secp256k1';

import { createAccountIdentityProofV2 } from '../marmot-phase-b1/identity-proof-v2.js';

const COMMITTED_WRITER_SHA256 =
  '60dbbc1127fbfb0e7e479cf7e2f7e6e20183c60d0559268f039d8db58bf60a3a';
const PROOF_CREATED_AT = 1_786_572_000;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

const committedDirectory = process.argv[2];
const candidateDirectory = process.argv[3];
if (!committedDirectory || !candidateDirectory) {
  throw new Error('committed and candidate WASM directories are required');
}
if (realpathSync(committedDirectory) === realpathSync(candidateDirectory)) {
  throw new Error('candidate directory must be external to the committed artifact directory');
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function check(condition, message) {
  if (!condition) throw new Error(`Phase B2.7 source probe failed: ${message}`);
  console.log(`PASS ${message}`);
}

function bytesEqual(left, right) {
  return left.length === right.length
    && left.every((byte, index) => byte === right[index]);
}

function valueShape(value) {
  if (typeof value === 'function') return `function:${value.length}`;
  if (value === null) return 'null';
  return typeof value;
}

function descriptorMap(owner) {
  return Object.fromEntries(Object.getOwnPropertyNames(owner).sort().map((name) => {
    const property = Object.getOwnPropertyDescriptor(owner, name);
    const attributes = `${property.enumerable ? 'e' : '-'}${property.configurable ? 'c' : '-'}${property.writable ? 'w' : '-'}`;
    if ('value' in property) return [name, `${attributes}:${valueShape(property.value)}`];
    return [name, `${attributes}:accessor:${property.get?.length ?? '-'}:${property.set?.length ?? '-'}`];
  }));
}

function canonicalGeneratedSurface(wasmModule, initOutput, declarations) {
  const namedExports = Object.keys(wasmModule).sort();
  const exportShapes = Object.fromEntries(namedExports.map((name) => {
    const value = wasmModule[name];
    if (typeof value !== 'function') return [name, valueShape(value)];
    return [name, {
      function: valueShape(value),
      own: descriptorMap(value),
      prototype: value.prototype ? descriptorMap(value.prototype) : null,
    }];
  }));
  const initOutputMembers = Object.keys(initOutput).sort()
    .map((name) => [name, valueShape(initOutput[name])]);
  const declarationClasses = Object.fromEntries(
    [...declarations.matchAll(/^export class ([A-Za-z0-9_$]+) \{\n([\s\S]*?)^\}$/gm)]
      .map((match) => [
        match[1],
        match[2].split('\n').map((line) => line.trim()).filter(Boolean).sort(),
      ])
      .sort(([left], [right]) => left.localeCompare(right)),
  );
  const declarationInitOutput = (
    declarations.match(/^export interface InitOutput \{\n([\s\S]*?)^\}$/m)?.[1]
    ?? (() => { throw new Error('InitOutput missing'); })()
  ).split('\n').map((line) => line.trim()).filter(Boolean).sort();
  return JSON.stringify({
    declarationClasses,
    declarationInitOutput,
    exportShapes,
    initOutputMembers,
    namedExports,
  });
}

function expectFailure(operation, fragment, message) {
  try {
    operation();
  } catch (error) {
    check(String(error).includes(fragment), `${message} (${fragment})`);
    return;
  }
  throw new Error(`Phase B2.7 source probe failed: ${message} did not fail`);
}

function privateKey(lastByte) {
  const value = new Uint8Array(32);
  value[31] = lastByte;
  return value;
}

function createPeer(wasm, provider, accountPrivateKey) {
  const accountPublicKey = Uint8Array.from(schnorr.getPublicKey(accountPrivateKey));
  const identity = new wasm.PhaseB2Identity(provider, accountPublicKey);
  const signatureKey = Uint8Array.from(identity.leaf_signature_key());
  const proof = createAccountIdentityProofV2(
    accountPrivateKey,
    signatureKey,
    PROOF_CREATED_AT,
  );
  const keyPackage = wasm.PhaseB2KeyPackage.from_framed_bytes(
    identity.key_package(provider, proof).to_framed_bytes(),
  );
  return { accountPublicKey, identity, keyPackage, proof, signatureKey };
}

function assertReceived(received, expected) {
  check(bytesEqual(received.group_id(), expected.groupId), `${expected.label} group id`);
  check(received.epoch() === expected.epoch, `${expected.label} exact epoch`);
  check(received.sender_leaf_index() === expected.leaf, `${expected.label} sender leaf`);
  check(
    bytesEqual(received.sender_credential_identity(), expected.accountPublicKey),
    `${expected.label} credential identity`,
  );
  check(
    bytesEqual(received.sender_signature_key(), expected.signatureKey),
    `${expected.label} leaf signature key`,
  );
  check(bytesEqual(received.plaintext(), expected.plaintext), `${expected.label} plaintext`);
}

const committedWasmBytes = readFileSync(join(committedDirectory, 'openmls_wasm_bg.wasm'));
const candidateWasmBytes = readFileSync(join(candidateDirectory, 'openmls_wasm_bg.wasm'));
const committedSha256 = sha256(committedWasmBytes);
const candidateSha256 = sha256(candidateWasmBytes);
check(committedSha256 === COMMITTED_WRITER_SHA256, 'committed writer has the exact B2.2 digest');
check(candidateSha256 !== committedSha256, 'external candidate is not the committed artifact');

const committedJavaScript = readFileSync(join(committedDirectory, 'openmls_wasm.js'), 'utf8');
const candidateJavaScript = readFileSync(join(candidateDirectory, 'openmls_wasm.js'), 'utf8');
const candidateTypes = readFileSync(join(candidateDirectory, 'openmls_wasm.d.ts'), 'utf8');
check(
  !committedJavaScript.includes('receive_application_message'),
  'committed artifact does not expose the Stage 1 candidate API',
);
check(
  candidateJavaScript.includes('receive_application_message'),
  'candidate JavaScript exposes receive_application_message',
);
check(
  candidateTypes.includes('PhaseB2ReceivedApplicationMessage'),
  'candidate declarations expose the closed receive result',
);

const moduleUrl = pathToFileURL(join(candidateDirectory, 'openmls_wasm.js'));
moduleUrl.searchParams.set('stage', 'b2-7-source-probe');
const wasm = await import(moduleUrl.href);
const initOutput = await wasm.default({ module_or_path: candidateWasmBytes });
const generatedSurface = canonicalGeneratedSurface(wasm, initOutput, candidateTypes);
check(typeof wasm.PhaseB2ReceivedApplicationMessage === 'function', 'candidate result class loads');
check(
  typeof wasm.PhaseB2Group.prototype.receive_application_message === 'function',
  'candidate receive method loads',
);
check(
  typeof wasm.PhaseB2Group.prototype.process_application_message === 'function',
  'legacy sender-discarding method remains present',
);

const groupId = encoder.encode('phase-b2-7-source-probe');
const aliceProvider = new wasm.Provider();
const bobProvider = new wasm.Provider();
const charlieProvider = new wasm.Provider();
const alice = createPeer(wasm, aliceProvider, privateKey(11));
const bob = createPeer(wasm, bobProvider, privateKey(12));
const charlie = createPeer(wasm, charlieProvider, privateKey(13));
const aliceGroup = wasm.PhaseB2Group.create_new(
  aliceProvider,
  alice.identity,
  groupId,
  alice.proof,
);
const addBob = aliceGroup.prepare_add(aliceProvider, alice.identity, bob.keyPackage);
const addBobProjection = addBob.projection();
aliceGroup.confirm_pending(aliceProvider, addBob, addBobProjection.verified_leaf_digest());
const bobGroup = wasm.PhaseB2Group.join(
  bobProvider,
  addBob.welcome(),
  wasm.PhaseB2RatchetTree.from_bytes(aliceGroup.export_ratchet_tree().to_bytes()),
);
const addCharlie = aliceGroup.prepare_add(
  aliceProvider,
  alice.identity,
  charlie.keyPackage,
);
const addCharlieProjection = addCharlie.projection();
const charlieLeaf = addCharlieProjection.proposal_added_leaf_index(0);
const bobStagedAdd = bobGroup.stage_inbound_commit(bobProvider, addCharlie.commit());
bobGroup.merge_staged_commit(
  bobProvider,
  bobStagedAdd,
  addCharlieProjection.verified_leaf_digest(),
);
aliceGroup.confirm_pending(
  aliceProvider,
  addCharlie,
  addCharlieProjection.verified_leaf_digest(),
);
const charlieGroup = wasm.PhaseB2Group.join(
  charlieProvider,
  addCharlie.welcome(),
  wasm.PhaseB2RatchetTree.from_bytes(aliceGroup.export_ratchet_tree().to_bytes()),
);
check(aliceGroup.epoch() === 2n && bobGroup.epoch() === 2n, 'three-member group is at epoch two');

const payloads = [
  {
    label: 'Alice attribution one',
    group: aliceGroup,
    provider: aliceProvider,
    peer: alice,
    leaf: 0,
    plaintext: encoder.encode(JSON.stringify({
      claimedAccount: Buffer.from(charlie.accountPublicKey).toString('hex'),
      value: 'payload identity is not authoritative',
    })),
  },
  {
    label: 'Charlie attribution',
    group: charlieGroup,
    provider: charlieProvider,
    peer: charlie,
    leaf: charlieLeaf,
    plaintext: encoder.encode('Charlie authenticated by MLS, not the payload'),
  },
  {
    label: 'Alice attribution two',
    group: aliceGroup,
    provider: aliceProvider,
    peer: alice,
    leaf: 0,
    plaintext: encoder.encode('Alice interleaved again'),
  },
];
for (const input of payloads) {
  const ciphertext = input.group.create_application_message(
    input.provider,
    input.peer.identity,
    input.plaintext,
  );
  const received = bobGroup.receive_application_message(bobProvider, ciphertext);
  assertReceived(received, {
    ...input,
    groupId,
    epoch: 2n,
    accountPublicKey: input.peer.accountPublicKey,
    signatureKey: input.peer.signatureKey,
  });
}
check(
  !bytesEqual(
    alice.accountPublicKey,
    charlie.accountPublicKey,
  ),
  'payload claim differs from the authenticated Alice result',
);

const ownMessage = aliceGroup.create_application_message(
  aliceProvider,
  alice.identity,
  encoder.encode('own echo'),
);
expectFailure(
  () => aliceGroup.receive_application_message(aliceProvider, ownMessage),
  'own message rejected',
  'own PrivateMessage is rejected',
);

const oldCharlieMessage = charlieGroup.create_application_message(
  charlieProvider,
  charlie.identity,
  encoder.encode('old epoch'),
);
const staleBobSnapshot = Uint8Array.from(bobProvider.serialize_state());
const staleBobProvider = new wasm.Provider();
staleBobProvider.restore_state(staleBobSnapshot);
const staleBobGroup = wasm.PhaseB2Group.load(staleBobProvider, groupId);
check(staleBobGroup !== undefined, 'stale epoch-two group reloads for cross-epoch test');

const selfUpdate = aliceGroup.prepare_self_update(aliceProvider, alice.identity);
const selfProjection = selfUpdate.projection();
const bobBeforePublic = Uint8Array.from(bobProvider.serialize_state());
expectFailure(
  () => bobGroup.receive_application_message(bobProvider, selfUpdate.commit()),
  'PrivateMessage application required',
  'PublicMessage Commit is rejected before receive processing',
);
check(bytesEqual(bobBeforePublic, bobProvider.serialize_state()), 'PublicMessage rejection writes no provider state');

const otherAliceProvider = new wasm.Provider();
const otherBobProvider = new wasm.Provider();
const otherAlice = createPeer(wasm, otherAliceProvider, privateKey(21));
const otherBob = createPeer(wasm, otherBobProvider, privateKey(22));
const otherGroupId = encoder.encode('phase-b2-7-wrong-group');
const otherAliceGroup = wasm.PhaseB2Group.create_new(
  otherAliceProvider,
  otherAlice.identity,
  otherGroupId,
  otherAlice.proof,
);
const otherAddBob = otherAliceGroup.prepare_add(
  otherAliceProvider,
  otherAlice.identity,
  otherBob.keyPackage,
);
const otherProjection = otherAddBob.projection();
otherAliceGroup.confirm_pending(
  otherAliceProvider,
  otherAddBob,
  otherProjection.verified_leaf_digest(),
);
const wrongGroupMessage = otherAliceGroup.create_application_message(
  otherAliceProvider,
  otherAlice.identity,
  encoder.encode('wrong group'),
);
const bobBeforeWrongGroup = Uint8Array.from(bobProvider.serialize_state());
expectFailure(
  () => bobGroup.receive_application_message(bobProvider, wrongGroupMessage),
  'group id mismatch',
  'different-group PrivateMessage is rejected before receive processing',
);
check(
  bytesEqual(bobBeforeWrongGroup, bobProvider.serialize_state()),
  'different-group rejection writes no provider state',
);

const bobStagedUpdate = bobGroup.stage_inbound_commit(bobProvider, selfUpdate.commit());
bobGroup.merge_staged_commit(
  bobProvider,
  bobStagedUpdate,
  selfProjection.verified_leaf_digest(),
);
const charlieStagedUpdate = charlieGroup.stage_inbound_commit(
  charlieProvider,
  selfUpdate.commit(),
);
charlieGroup.merge_staged_commit(
  charlieProvider,
  charlieStagedUpdate,
  selfProjection.verified_leaf_digest(),
);
aliceGroup.confirm_pending(aliceProvider, selfUpdate, selfProjection.verified_leaf_digest());

const newEpochMessage = aliceGroup.create_application_message(
  aliceProvider,
  alice.identity,
  encoder.encode('new epoch'),
);
const staleBefore = Uint8Array.from(staleBobProvider.serialize_state());
expectFailure(
  () => staleBobGroup.receive_application_message(staleBobProvider, newEpochMessage),
  'current epoch required',
  'future-epoch message is refused by stale receiver',
);
check(bytesEqual(staleBefore, staleBobProvider.serialize_state()), 'future-epoch refusal writes no provider state');
const currentBefore = Uint8Array.from(bobProvider.serialize_state());
expectFailure(
  () => bobGroup.receive_application_message(bobProvider, oldCharlieMessage),
  'current epoch required',
  'past-epoch message is refused by current receiver',
);
check(bytesEqual(currentBefore, bobProvider.serialize_state()), 'past-epoch refusal writes no provider state');

const validMessage = aliceGroup.create_application_message(
  aliceProvider,
  alice.identity,
  encoder.encode('tampered generation'),
);
const tampered = Uint8Array.from(validMessage);
tampered[tampered.length - 1] ^= 1;
expectFailure(
  () => bobGroup.receive_application_message(bobProvider, tampered),
  'OpenMLS processing failed',
  'tampered ciphertext fails closed with a stable error',
);
expectFailure(
  () => bobGroup.receive_application_message(bobProvider, validMessage),
  'OpenMLS processing failed',
  'the rejected generation cannot later be replayed as valid',
);
const afterTamperMessage = aliceGroup.create_application_message(
  aliceProvider,
  alice.identity,
  encoder.encode('next generation remains live'),
);
const afterTamper = bobGroup.receive_application_message(bobProvider, afterTamperMessage);
check(
  decoder.decode(afterTamper.plaintext()) === 'next generation remains live',
  'a later sender-ratchet generation remains live after tamper rejection',
);
expectFailure(
  () => bobGroup.receive_application_message(bobProvider, afterTamperMessage),
  'OpenMLS processing failed',
  'accepted ciphertext replay fails closed',
);

const malformedBefore = Uint8Array.from(bobProvider.serialize_state());
expectFailure(
  () => bobGroup.receive_application_message(bobProvider, Uint8Array.of(1, 2, 3)),
  'malformed MLSMessage',
  'malformed framing is rejected',
);
check(bytesEqual(malformedBefore, bobProvider.serialize_state()), 'malformed framing writes no provider state');

console.log(JSON.stringify({
  candidate: {
    wasmBytes: candidateWasmBytes.length,
    wasmSha256: candidateSha256,
    javascriptBytes: Buffer.byteLength(candidateJavaScript),
    javascriptSha256: sha256(candidateJavaScript),
    declarationsSha256: sha256(candidateTypes),
    generatedSurfaceBytes: Buffer.byteLength(generatedSurface),
    generatedSurfaceSha256: sha256(generatedSurface),
  },
  committedWasmSha256: committedSha256,
  result: 'phase-b2-7-source-probe-pass',
}, null, 2));
